# Using the CLI

This page walks through the commands you'll actually type, grouped by what
you're trying to do — not an exhaustive flag reference. For the complete,
precise contract (every flag, every exit code, what each one does under the
hood) see
[specs/securegit/10-cli-contract.md](../../specs/securegit/10-cli-contract.md).
Nothing here should ever disagree with that page; if it does, that page is
right.

## Setting up a repository

Three commands, in this order, once per repository:

```sh
securegit init
securegit install
securegit protect config/production.json '*.pem'
```

- **`init`** creates `.securegit/config.json` and your first key
  (generation 1), asking for a passphrase to lock it behind. Refuses if
  you're not inside a Git repository, or if this one's already set up.
- **`install`** is the one easy to forget, because nothing visibly breaks
  if you skip it — Git simply won't run the encryption filter at all, and
  files you "protect" afterward check out and commit as ordinary
  plaintext. It writes local, never-committed `.git/config` entries
  telling Git to actually call `securegit` on the patterns you protect.
  Idempotent — safe to run again if you're ever unsure whether it's done.
- **`protect <pattern>…`** adds patterns to `.gitattributes` (committed,
  so everyone who clones gets the same rules). Takes any number of
  patterns: `securegit protect '*.env' secrets/**`.

From here on, nothing about your day-to-day Git workflow changes:

```sh
git add . && git commit -m "hello" && git push
```

`git status`, `git diff`, `git log -p` all behave normally on protected
files, from a machine that holds the key.

**Changed your mind about a pattern?** `securegit unprotect <pattern>…`
removes it from `.gitattributes` — but only going forward. Whatever's
already committed under that pattern stays encrypted until you edit and
re-commit it (or run `reencrypt`, below); `unprotect` warns about this
every time so it's never a silent surprise.

## On a second machine (or a fresh clone)

If you already hold a key for this repository — you set it up yourself
elsewhere, or a teammate shared access with you (see "Sharing access"
below):

```sh
git clone …
securegit unlock
```

`unlock` asks for whatever unlocks your key (passphrase, YubiKey touch,
however it's set up) once, then caches the result for a while (8 hours by
default) so you're not asked again on every single `git` command. See
[04-keys-usage.md](04-keys-usage.md#not-having-to-unlock-every-single-time-the-session)
for exactly what that cache is and how seriously to treat it.

```sh
securegit unlock --ttl 3600   # cache for 1 hour instead of the 8-hour default
securegit lock                # end the session early, right now
```

If you've never unlocked this repository before but a teammate has
added you as a recipient (see below), `unlock` tries that path
automatically — no separate command needed. If neither a local key nor a
recipient entry exists for you, `unlock` tells you exactly which of the
two setup paths to take.

## Checking on things

```sh
securegit status
```

Tells you, in one glance: whether you're currently unlocked, which
generation is current, whether `bindPath` is on, and whether your
recovery situation has a warning worth reading (e.g. only one person can
currently unlock this repository, with no recovery export on file — see
[02-faq.md](02-faq.md)). Add `--json` for a script-readable form of the
same report.

```sh
securegit verify
securegit verify --history
securegit verify --access
```

- **`verify`** (no flags) checks the current checkout is sane — config,
  attributes, nothing that looks like an accidentally-committed plaintext
  file where ciphertext belongs. Fast enough for a pre-commit hook.
- **`verify --history`** walks the *entire* commit history looking for
  the same thing — slower, meant for CI or a pre-push hook, not every
  commit:
  ```sh
  securegit verify --history || exit 1
  ```
- **`verify --access`** answers "who can currently read this
  repository" — every recipient, every recovery export on record, in
  plain terms.

## Sharing access with a teammate

Adding someone never means handing them your passphrase. Each person
sets up their own identity once, on their own machine:

```sh
securegit identity init
securegit identity show
```

`identity show` prints a public key (safe to paste anywhere — Slack,
email, a pull request). Whoever already has access to the repository
runs:

```sh
securegit key add-recipient <the pubkey they sent you>
```

That's it — the new person's `securegit unlock` now works on its own,
using the recipient entry `key add-recipient` just committed plus their
own private identity, which never left their machine. See
[04-keys-usage.md](04-keys-usage.md#sharing-access-every-teammate-has-their-own-key-not-a-copy-of-yours)
for the mechanism, and
[02-faq.md](02-faq.md#someone-left-the-team-can-i-lock-them-out) for what
happens (and what doesn't) when someone leaves.

```sh
securegit key list-recipients
securegit key remove-recipient <fingerprint>
```

Removing a recipient stops them from being included in *future*
generations — it does not (cannot) reach back and revoke what they
already read. Pair it with `key rotate` below when that forward-only
distinction matters to you.

## Rotating and revoking

```sh
securegit key rotate --confirm-recipients <n>
```

Creates a new generation and rewraps it for everyone currently on the
recipient list. `--confirm-recipients <n>` is a deliberate speed bump:
`key rotate` prints the recipient list and refuses to proceed unless the
count you pass matches it exactly — so rotating right after removing (or
forgetting you added) someone can't happen by habit. Refuses on a dirty
working tree or a locked repository too.

```sh
securegit reencrypt
```

Existing files stay under whichever generation encrypted them until you
touch them again — `reencrypt` moves everything to the *current*
generation in one pass, without you needing to open and re-save each
file by hand. Add `--dry-run` to see what would move first.

## Hardware keys and additional providers

```sh
securegit key add-provider yubikey-piv --slot 9d
securegit key add-provider yubikey-fido2
securegit key list
securegit key remove-provider <id>
```

Adds an additional way to unlock the same keys — a YubiKey, or a second,
independently-passphrased local secret — without replacing what's
already there. `key list` shows every generation and which provider ids
can unlock each; `key remove-provider` refuses if removing one would
leave any generation with no way to unlock it at all. See
[04-keys-usage.md](04-keys-usage.md#where-it-lives-and-what-locks-it) for
what a "provider" actually is.

## Your safety net: recovery codes

Set this up once, before you need it — there's no "forgot password"
button by design:

```sh
securegit key export-recovery --out recovery.enc
```

Prints a one-time code to your screen (never written anywhere by
`securegit` itself — write it down or store it somewhere safe, separately
from `recovery.enc`). Later, on a machine with neither a keyring nor an
identity:

```sh
securegit key import-recovery --in recovery.enc
```

You'll be asked for the code and a new local passphrase to protect the
rebuilt keyring with. See
[04-keys-usage.md](04-keys-usage.md#your-safety-net-a-recovery-code) for
why this is a bearer credential, not an inert backup file.

## Working with a file outside Git entirely

```sh
securegit encrypt somefile.txt --out somefile.txt.enc
securegit decrypt somefile.txt.enc --out somefile.txt
securegit inspect somefile.txt.enc
```

The same envelope format and code path the Git filter uses, with no
repository involved — useful for testing, or for encrypting something
that was never meant to live in Git at all. `-` works as `stdin`/`stdout`
for either command. `inspect` reads the header only (generation,
algorithm, flags) without needing a key.

## Useful global flags

| Flag | What it does |
|---|---|
| `--repo <path>` | Run against a different repository than the current directory. |
| `--json` | Machine-readable output, for `status`, `verify`, `inspect`, `key list`, `key list-recipients`. |
| `--quiet` | Suppress one-line success confirmations. Never hides an error or an actual report. |
| `-v`, `--verbose` | Per-file tracing on `clean`/`smudge`/`merge` — path, generation, what happened. Never prints plaintext or key material. |

## When something goes wrong

`securegit` exits with a specific code depending on what kind of failure
it was — useful in a script, and worth knowing if you see a nonzero exit
and want to know how worried to be:

| Exit code | Meaning |
|---|---|
| 0 | success |
| 1 | locked — a key was needed and isn't available right now; run `unlock` |
| 2 | misconfigured — this repository, or your Git config, isn't set up correctly; `init`/`install` may not have run |
| 3 | a cryptographic or format failure — wrong key for this specific file, or corrupted ciphertext |
| 4 | a usage error — a missing argument, an unknown flag, or a command run somewhere it can't work |
| 5 | `verify` found a leak — a "protected" path's committed content isn't actually encrypted |

The full table, with exactly which situation produces which code per
command, is in
[10-cli-contract.md](../../specs/securegit/10-cli-contract.md#exit-codes).

## The commands Git runs for you

You'll never type these yourself — `install` wires them up, and Git
invokes them on every `add`, `checkout`, `diff`, and `merge` touching a
protected path. Listed here only so a `git config -l | grep securegit`
output or a stack trace makes sense if you ever see one:

`clean`, `smudge`, `textconv`, `merge`, `filter-process`.

**Details:** [specs/securegit/10-cli-contract.md](../../specs/securegit/10-cli-contract.md)
