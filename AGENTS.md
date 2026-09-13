# Agent guide — trinoris-secure

> **This file is hand-authored for this repo's own dogfooding setup — it
> is not, and must never become, `securegit agent install`'s generated
> output.** That CLI feature (spec [17](specs/securegit/17-agent-integration.md))
> writes *generic* securegit guidance for someone else's real repo, and
> its own generic advice is the opposite of what this file says below
> (it correctly says "never expose your passphrase"; this repo
> deliberately does, for open-source dogfooding reasons explained in
> README.md). The two are incompatible content for the same path.
> `securegit agent install codex` already refuses to touch this file
> (no `managed by: securegit agent install` marker here) — never pass
> `--force` to overwrite it; that would silently delete the
> checkout/unlock instructions this repo cannot be worked on without.

Cross-tool instructions (the [AGENTS.md](https://agents.md) convention) —
read this if you are Cursor, Windsurf, Cline, Aider, OpenAI Codex,
Gemini CLI, JetBrains Junie, or any other coding agent working in this
repo. Claude Code should follow
[`.claude/skills/checkout-and-unlock`](.claude/skills/checkout-and-unlock/SKILL.md)
instead (richer, tool-native format, same recipe); GitHub Copilot reads
[`.github/copilot-instructions.md`](.github/copilot-instructions.md)
automatically. All three exist because an agent has to be able to
discover and read *one* of them before it can decrypt anything else in
this repo — see below.

## This repo is real securegit ciphertext at rest

This is `@trinoris/securegit`'s own repository, dogfooding itself: outside
`docs/`, `README.md`, `LICENSE`, `.github/workflows/`, `.github/actions/`,
`.claude/`, `.github/copilot-instructions.md`, `AGENTS.md` (this file),
package manifests (`package.json`, `package-lock.json` — kept plaintext
for Dependabot and a plain `npm ci`), and
`secret-pass-phrase.txt`/`recovery-code.txt`/`*.recovery.txt` themselves,
every file — nearly all of `packages/**`'s real TypeScript source
included — is genuinely encrypted in Git. A file whose content is
garbled binary starting with the literal bytes `SECUREGIT` is not
broken, not a bad clone, and not something to regenerate from a guess —
it's ciphertext, exactly as designed. Decrypt the checkout first.

## Unlock before reading or editing any source file

```sh
securegit --version 2>&1 || npm install -g @trinoris/securegit
securegit install
SECUREGIT_RECOVERY_CODE="$(tail -1 recovery-code.txt)" SECUREGIT_PASSPHRASE="$(tail -1 secret-pass-phrase.txt)" \
  securegit key import-recovery --in trinoris-secure.recovery.txt
SECUREGIT_PASSPHRASE="$(tail -1 secret-pass-phrase.txt)" securegit unlock
git rm --cached -r -q . && git checkout HEAD -- .
```

**Two mistakes silently break this, both confirmed the hard way in
this repo's own CI:**

1. `secret-pass-phrase.txt` and `recovery-code.txt` are mostly
   explanatory prose — the actual secret is only each file's last line.
   `$(cat secret-pass-phrase.txt)` (the whole file) fails `unlock` with
   "wrong passphrase" every single time, with no signal that anything
   is wrong until a later command hits ciphertext. Always `tail -1`,
   never `cat`, on either file.
2. `securegit unlock` alone, without `import-recovery` first, only
   works on the one machine that originally ran `securegit init` — it
   decrypts a *local* keyring (`~/.securegit/repos/<repoId>/keyring.json`)
   that is never committed to Git by design. Any other machine —
   including a CI runner, confirmed on a real GitHub Actions run — fails
   with `no keyring found for this repository` regardless of how
   correct the passphrase is. `import-recovery` rebuilds that keyring
   from the committed recovery file; it's safe to run unconditionally,
   even on a machine that already has one.

The final `git rm --cached -r -q . && git checkout HEAD -- .` line is
required, not optional cleanup: Git's own stat-cache assumes a file
already checked out as ciphertext "matches the index" and skips
re-running `smudge` even immediately after a successful `unlock`.

## Verify — every command above can exit 0 while still locked

```sh
head -c 20 packages/securegit/src/cli.ts   # expect a real // comment, not binary
securegit verify --json                    # every "ok" must be true
```

Do not report the repo as "checked out" or proceed to read/edit source
based on exit codes alone — confirm actual plaintext came back first.

## Why the passphrase is published instead of kept secret

This is the open-source security tool itself. Hiding its own source
from the researchers, users, and AI agents it asks to trust would
defeat the entire point of being open source. Publishing the decrypt
key proves the real mechanism (real AES-256-GCM ciphertext at rest,
real decrypt on checkout) without costing anyone — human or agent — the
ability to read, audit, or contribute to the source. Full reasoning:
`README.md`'s "This repository dogfoods itself".

## Verifying the recovery mechanism itself

`recovery-code.txt` (same last-line convention as the passphrase file)
plus `trinoris-secure.recovery.txt` are already load-bearing above, not
a rare fallback — `import-recovery` is what actually bootstraps a
keyring on any machine. Run `./scripts/recovery-scenario-demo.sh`
rather than improvising a check yourself — it already implements and
verifies the full recovery path end to end.

## Committing changes

`git add`/`git commit`/`git push` behave exactly as in any other repo —
the clean filter re-encrypts protected files automatically on `git
add`. Never hand-edit ciphertext, and never bypass the filter to "fix"
what looks like corruption. It isn't.
