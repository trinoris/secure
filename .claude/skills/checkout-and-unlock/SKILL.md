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
the one real bug this recipe exists to prevent (see "The one mistake
that silently breaks this") does exactly that.

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

## 3. Unlock with the published passphrase

```sh
SECUREGIT_PASSPHRASE="$(tail -1 secret-pass-phrase.txt)" securegit unlock
```

Expect: `securegit: unlocked (generation <fingerprint>)`. Anything else
(`could not unlock — wrong passphrase...`) means step 3 itself failed —
see "The one mistake that silently breaks this" below before retrying.

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

## The one mistake that silently breaks this

`secret-pass-phrase.txt` is mostly explanatory prose — the passphrase is
only its **last line**. `SECUREGIT_PASSPHRASE="$(cat secret-pass-
phrase.txt)"` reads the *entire file* as the passphrase and fails
`unlock` with "could not unlock — wrong passphrase" every time. Always
use `tail -1 secret-pass-phrase.txt`, never `cat`. This is a real bug
this skill exists to prevent, not a hypothetical — it was caught the
hard way while wiring up this repo's own CI.

## Recovery scenario (a different situation, not the everyday path)

If `secret-pass-phrase.txt` itself is ever lost or wrong, this repo also
dogfoods the recovery path: `recovery-code.txt` (its own last-line
convention, same caveat as above) plus `trinoris-secure.recovery.txt`
rebuild a working keyring from scratch via
`securegit key import-recovery`. Don't hand-run that — use
`./scripts/recovery-scenario-demo.sh` and read its output; it already
implements and verifies the full sequence end to end.
