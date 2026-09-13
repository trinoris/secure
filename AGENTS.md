# Agent guide — trinoris-secure

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
SECUREGIT_PASSPHRASE="$(tail -1 secret-pass-phrase.txt)" securegit unlock
git rm --cached -r -q . && git checkout HEAD -- .
```

**The one mistake that silently breaks this, confirmed the hard way in
this repo's own CI**: `secret-pass-phrase.txt` is mostly explanatory
prose — the passphrase is only its last line.
`SECUREGIT_PASSPHRASE="$(cat secret-pass-phrase.txt)"` (the whole file)
fails `unlock` with "wrong passphrase" every single time, with no
signal that anything is wrong until a later command hits ciphertext.
Always `tail -1 secret-pass-phrase.txt`, never `cat` it.

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

## Recovery scenario — a different situation, not the everyday path

If `secret-pass-phrase.txt` is ever lost or wrong, `recovery-code.txt`
(same last-line convention) plus `trinoris-secure.recovery.txt` rebuild
a working keyring from scratch via `securegit key import-recovery`.
Run `./scripts/recovery-scenario-demo.sh` rather than improvising that
sequence — it already implements and verifies the full recovery path
end to end.

## Committing changes

`git add`/`git commit`/`git push` behave exactly as in any other repo —
the clean filter re-encrypts protected files automatically on `git
add`. Never hand-edit ciphertext, and never bypass the filter to "fix"
what looks like corruption. It isn't.
