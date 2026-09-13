---
name: checkout-and-unlock
description: Check out this repo (trinoris-secure) and decrypt its real, securegit-protected source. Use whenever an agent needs to read, edit, build, or test actual source in this repo — after a fresh clone, after `securegit lock`, or whenever a file reads back as raw ciphertext instead of code.
---

# Checkout and unlock trinoris-secure

This repo dogfoods its own tool: outside `docs/`, `README.md`, `LICENSE`,
`.github/workflows/`, `.github/actions/`, package manifests, and
`secret-pass-phrase.txt`/`recovery-code.txt`/`*.recovery.txt` themselves,
every file is real securegit ciphertext at rest (see README.md's "This
repository dogfoods itself"). A plain `git clone` or `git checkout` gets
you that ciphertext, not code — this is expected, never a corrupted
checkout.

Follow every step below in order. Do not skip the verification step or
declare success from a command's exit code alone — `securegit unlock`
and `git checkout` can both exit 0 while a file is still ciphertext, and
the two real bugs this recipe exists to prevent (see "The two mistakes
that silently break this") do exactly that.

## 1. Confirm securegit is available

```sh
securegit --version 2>&1 || command -v securegit
```

If missing: `npm install -g @trinoris/securegit` (the last published
release — this repo's own in-progress source can't decrypt itself with
a securegit built from that same still-encrypted source).

## 2. Register the filter (idempotent, safe to always run)

```sh
cd /path/to/trinoris-secure
securegit install
```

## 3. Rebuild a keyring from the committed recovery file, then unlock

```sh
SECUREGIT_RECOVERY_CODE="$(tail -1 recovery-code.txt)" SECUREGIT_PASSPHRASE="$(tail -1 secret-pass-phrase.txt)" \
  securegit key import-recovery --in trinoris-secure.recovery.txt
SECUREGIT_PASSPHRASE="$(tail -1 secret-pass-phrase.txt)" securegit unlock
```

The `import-recovery` line is not optional, even though it looks like
it should only matter for disaster recovery. Skipping it and running
`securegit unlock` alone fails with `no keyring found for this
repository` on every machine except whichever one originally ran
`securegit init` — `unlock` decrypts a *local* keyring
(`~/.securegit/repos/<repoId>/keyring.json`) that is never committed to
Git by design. `import-recovery` is what actually creates that keyring
from the committed recovery file; it's safe to run even on a machine
that already has one (it just adds an equivalent copy), so always run
it rather than guessing whether this machine needs it.

Expect: `securegit: unlocked (generation <fingerprint>)`. Anything else
means a step above failed — see "The two mistakes that silently break
this" below before retrying.

## 4. Force Git to actually re-materialize plaintext

```sh
git rm --cached -r -q . && git checkout HEAD -- .
```

Not optional. Git's own stat-cache assumes a file already checked out
as ciphertext "matches the index" and skips re-running `smudge` even
right after a successful `unlock` — without this, every file stays
ciphertext on disk despite the unlock above reporting success.

## 5. Verify — don't just trust the exit code

Exit codes 0 from every step above are consistent with success AND with
"still ciphertext, no error surfaced." Confirm the actual content:

```sh
head -c 20 packages/securegit/src/cli.ts
```

**Real success** looks like `// The command surface` (or any other real
JS/TS comment/code). **Still locked** looks like a binary/garbled
`SECUREGIT` envelope header — if you see that, decryption did not
actually happen; go back to step 3.

For a stronger, whole-repo check:

```sh
securegit verify --json
```

Every check's `"ok"` must be `true`. Any `false` entry means something
about this repo's own securegit setup regressed — do not proceed with
edits/builds until it's resolved.

## The two mistakes that silently break this

1. **`cat` instead of `tail -1`.** `secret-pass-phrase.txt` and
   `recovery-code.txt` are both mostly explanatory prose — the actual
   secret is only each file's **last line**. `$(cat secret-pass-
   phrase.txt)` reads the *entire file* as the passphrase and fails
   every time. Always `tail -1`, never `cat`, on either file.
2. **Skipping `import-recovery` and running `securegit unlock` alone.**
   This works *only* on the one machine that originally ran `securegit
   init` — `unlock` decrypts a local keyring
   (`~/.securegit/repos/<repoId>/keyring.json`) that is never committed
   to Git by design. Every other machine, including any fresh Claude
   Code session's own sandbox, has no keyring to unlock and fails with
   `no keyring found for this repository` regardless of how correct the
   passphrase is. `import-recovery` (step 3 above) is what actually
   creates one.

Both were caught the hard way while wiring up this repo's own CI — the
second one on a real GitHub Actions run, not in local testing (local
testing kept reusing the same machine's already-existing keyring
without anyone noticing it never got exercised).

## Verifying the recovery mechanism itself (not the everyday path)

`./scripts/recovery-scenario-demo.sh` implements and verifies this
exact sequence end to end from a genuinely isolated `SECUREGIT_HOME` —
run it if you want to confirm the recovery file + code still work,
rather than hand-rolling the same check.
