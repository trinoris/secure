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
SECUREGIT_PASSPHRASE="$(tail -1 secret-pass-phrase.txt)" securegit unlock
git rm --cached -r -q . && git checkout HEAD -- .
```

**The one real mistake that silently breaks this**: `secret-pass-
phrase.txt` is mostly explanatory prose — the passphrase is only its
last line. `SECUREGIT_PASSPHRASE="$(cat secret-pass-phrase.txt)"` (the
whole file, not `tail -1`) fails `unlock` with "wrong passphrase" every
time, with no indication anything is wrong until the next command hits
ciphertext. Always use `tail -1 secret-pass-phrase.txt`. This is a
confirmed, previously-real bug in this repo's own CI, not a
hypothetical.

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
