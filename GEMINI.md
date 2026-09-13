# trinoris-secure — read before touching any source file

This repo (`@trinoris/securegit`'s own repository) dogfoods itself: outside
`docs/`, `README.md`, `LICENSE`, `.github/workflows/`, `.github/actions/`,
`.claude/`, `.github/copilot-instructions.md`, `AGENTS.md`, `.cursor/`,
`.windsurfrules`, `.clinerules`, `GEMINI.md` (this file), package
manifests, and `secret-pass-phrase.txt`/`recovery-code.txt`/
`*.recovery.txt` themselves, every file is real securegit ciphertext at
rest. A file whose content is garbled binary starting with `SECUREGIT`
is not corrupted — decrypt the checkout before treating it as broken.

## Unlock first

```sh
securegit --version 2>&1 || npm install -g @trinoris/securegit
securegit install
SECUREGIT_PASSPHRASE="$(tail -1 secret-pass-phrase.txt)" securegit unlock
git rm --cached -r -q . && git checkout HEAD -- .
```

Use `tail -1 secret-pass-phrase.txt`, never `cat` it — the file is
mostly explanatory prose; `cat`ing the whole thing as the passphrase
fails `unlock` with "wrong passphrase" every time, silently. The final
`git rm --cached`/`checkout` line is required — Git's stat-cache skips
re-running `smudge` on an already-ciphertext file even right after
`unlock` without it.

## Verify, don't assume

Every command above can exit 0 while still locked:

```sh
head -c 20 packages/securegit/src/cli.ts   # expect a real // comment
securegit verify --json                    # every "ok" must be true
```

The passphrase is published on purpose — this is the open-source
security tool itself, so hiding its own source would defeat the point
of being open source. Full reasoning: README.md's "This repository
dogfoods itself".
