# Repository custom instructions for GitHub Copilot

## This repo is real securegit ciphertext at rest

Outside `docs/`, `README.md`, `LICENSE`, `.github/workflows/`,
`.github/actions/`, `.claude/`, `.github/copilot-instructions.md` (this
file), package manifests (`package.json`, `package-lock.json`), and
`secret-pass-phrase.txt`/`recovery-code.txt`/`*.recovery.txt`
themselves, every file `securegit protect`s by default — including
almost all of `packages/**`'s own TypeScript source. A file that reads
as opaque binary/garbled bytes starting with `SECUREGIT` is not
corrupted and is not a file you should try to "fix" or regenerate —
it's ciphertext, and this is expected. Decrypt the checkout before
reading, editing, or suggesting changes to any such file; do not guess
at its content from the filename or from other files' patterns.

## Unlock before touching source (do this first, every session)

```sh
securegit --version 2>&1 || npm install -g @trinoris/securegit
securegit install
SECUREGIT_RECOVERY_CODE="$(tail -1 recovery-code.txt)" SECUREGIT_PASSPHRASE="$(tail -1 secret-pass-phrase.txt)" \
  securegit key import-recovery --in trinoris-secure.recovery.txt
SECUREGIT_PASSPHRASE="$(tail -1 secret-pass-phrase.txt)" securegit unlock
git rm --cached -r -q . && git checkout HEAD -- .
```

**Two real mistakes silently break this, both confirmed on this exact
repo, not hypothetical:**

1. `secret-pass-phrase.txt` and `recovery-code.txt` are mostly
   explanatory prose — the actual secret is only each file's last line.
   `$(cat secret-pass-phrase.txt)` (the whole file, not `tail -1`) fails
   `unlock` with "wrong passphrase" every time, with no indication
   anything is wrong until the next command hits ciphertext. Always use
   `tail -1`, never `cat`, on either file.
2. `securegit unlock` alone, without `import-recovery` first, only
   works on the one machine that originally ran `securegit init` — it
   decrypts a *local* keyring (`~/.securegit/repos/<repoId>/keyring.json`)
   that is never committed to Git by design. Any other machine —
   including this one, right now — fails with `no keyring found for
   this repository` regardless of how correct the passphrase is.
   `import-recovery` rebuilds that keyring from the committed recovery
   file; it's safe to run unconditionally, even on a machine that
   already has a keyring (confirmed the hard way on a real GitHub
   Actions run — the bug had gone unnoticed because local testing kept
   reusing a machine that already had one).

The `git rm --cached -r -q . && git checkout HEAD -- .` step is not
optional busywork — Git's own stat-cache assumes a file already
checked out as ciphertext "matches the index" and skips re-running
`smudge` even right after a successful `unlock`.

## Verify before trusting any of the above

Every command above can exit 0 while a file is still ciphertext.
Confirm real content came back before proceeding:

```sh
head -c 20 packages/securegit/src/cli.ts   # expect a real // comment, not binary
securegit verify --json                    # every check's "ok" must be true
```

## Why the passphrase is published at all

This is the open-source security tool itself. Hiding its own source
from the people it asks to trust — including an AI coding assistant
working on it — would defeat the point of being open source. Publishing
the decrypt key proves the encryption mechanism works end to end (real
ciphertext at rest, real decrypt on checkout) without costing anyone
the ability to read, audit, or contribute to the source. See
`README.md`'s "This repository dogfoods itself" for the full reasoning,
and `.claude/skills/checkout-and-unlock/SKILL.md` for the same recipe
written for an autonomous coding agent.

## Committing changes

`git add`/`git commit`/`git push` behave normally — the clean filter
re-encrypts anything under `securegit protect`'s scope automatically on
`git add`. Never hand-edit a file's ciphertext, and never bypass the
filter (e.g. `git add --no-filters`, editing `.git/objects` directly)
to "fix" what looks like corruption — it isn't.
