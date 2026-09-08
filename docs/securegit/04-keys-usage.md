# Keys: What Protects What

A lot of different things get called "the key" when people talk about
securegit — your passphrase, a YubiKey, the file that gets encrypted,
the thing your teammate has. This page walks through each one, in plain
terms: what it actually is, where it lives, and what protects it. Every
section links to the precise technical spec at the bottom, for anyone
who wants the exact details.

## The one secret that actually matters

Underneath everything, each repository has, at any given moment, exactly
**one secret currently in use**: a 32-byte number this project calls the
**repository master key**. Everything else in this page is really just
"how is *this* protected" or "what gets calculated *from* it
automatically."

"At any given moment" matters: rotating your key (`securegit key
rotate`) doesn't erase the old master key and replace it — it creates a
new one, called a **generation**, on top. Every file encrypted under
generation 1 still needs generation 1's master key to open; a file you
touch after rotating gets encrypted under generation 2's. Your keyring
quietly holds every generation you've ever had, so nothing you've
already written ever becomes unreadable to you — but strictly, "the
master key" always means one specific generation's, not one single
number that lives forever.

A few things are true of every generation's master key, always:

- It's generated on your computer and never leaves it — except when a
  hardware key or a cloud vault holds it instead, in which case it never
  leaves *that* (more on this below).
- It's never uploaded, never committed to Git, never written anywhere
  inside your repository.
- It's the one thing that, if you lost every copy of it with no
  recovery plan, would mean your encrypted files are gone for good — see
  [02-faq.md](02-faq.md#what-happens-if-i-lose-my-laptop-or-forget-my-passphrase).

**Details:** [05-key-hierarchy.md](../../specs/securegit/05-key-hierarchy.md)

## Where it lives, and what locks it

The master key is stored on your computer, but never in plain,
readable form — it's locked ("wrapped," in the technical spec) behind
something only you can produce. Which "something" is swappable — that's
what this project calls a **provider**. Two are available from the
`securegit` command line itself, right now:

- **A passphrase** (the default). Your passphrase itself is never
  stored anywhere — instead, it's run through a slow, deliberately
  expensive scrambling process (the same kind banks and password
  managers use) to produce an encryption key, and the master key is
  sealed behind that lock. Guessing your way in without the real
  passphrase is designed to be prohibitively slow, even for someone who
  steals the locked file itself.
- **A YubiKey or similar hardware security key**
  (`securegit key add-provider yubikey-piv --slot <slot>` or
  `yubikey-fido2` — a slightly different mechanism each way, smartcard
  mode versus the key's authentication mode, though the practical effect
  is the same). Unlocking needs one calculation that only the *physical
  device itself* can perform — its own internal secret never leaves it,
  ever, under any circumstances. What that calculation produces does
  briefly pass back to your computer to finish unlocking the repository,
  the same as typing a passphrase does — so the real protection isn't
  "your computer never touches the secret," it's this: without the
  physical device present and touched, your computer alone — even fully
  compromised — cannot perform that one calculation, at all, no matter
  how much malware or time an attacker has. Confirmed against a real
  YubiKey: adding it this way produces a genuinely usable slot, and
  unlocking through it afterward actually works, even with the wrong
  passphrase typed.

One more is real, working, tested code — just not yet reachable from the
`securegit` command itself (see
[02-faq.md](02-faq.md#what-kind-of-keystore-does-it-support-can-i-use-a-tpm-smartcard-or-my-oss-keychain)
for exactly what "not yet reachable" means):

- **A cloud key vault** (AWS, Google Cloud, or Azure's key-management
  service). The vault locks and unlocks your master key on request, over
  the network — concretely, your actual master key is sent to the cloud
  provider's service in plain form each time, and comes back in plain
  form each time it unlocks, the same way a locksmith briefly has to
  handle your actual key to cut you a copy. This one comes with a real,
  deliberate limit: it can never be your *only* way in. A cloud
  provider's vault is still something that provider could theoretically
  be compelled to unlock — useful as a company-wide "break glass"
  backup, never as the single point of trust the whole tool exists to
  avoid.

The difference between the last two matters enough to have a name:
**can whoever holds this lock be forced to open it without you?** A
passphrase only you know: no. A YubiKey that performs the unlock
calculation on the device itself, requiring your physical touch: no.
A cloud vault a company operates: in principle, yes — which is exactly
why it's never allowed to be the *only* lock on a repository.

**Details:** [06-key-provider-port.md](../../specs/securegit/06-key-provider-port.md)

## The key for one specific file — which you never see

securegit does **not** keep a separate stored secret for every file you
protect. Instead, every time it needs one, it *recalculates* a per-file
key on the spot, from two things: your master key, and a small,
non-secret fingerprint of that exact file's content — a bit like a
tamper-evident stamp, calculated once when the file is encrypted and
saved alongside the encrypted bytes themselves (never separately, never
anywhere else). That stamp is what makes recalculating the same key
later possible at all: reading a file back doesn't need to reconstruct
the fingerprint from scratch, only read the one already sitting right
there with it, then combine it with your master key the same way as
before.

Change one byte of the file, and its stamp — and so its per-file key —
comes out completely different. Encrypt the exact same content twice,
and both the stamp and the per-file key come out *identical*, every
time. That last property is deliberate, not incidental: it's what makes
`git diff`/`git status` behave sanely on encrypted files (committing the
same content twice produces the same encrypted bytes, not a noisy,
meaningless diff every time), and it means there's genuinely nothing
extra to back up or lose — the per-file key was never stored anywhere
to begin with, only ever recalculated when needed. It also means
figuring out one file's key (which nobody can do without your master
key anyway) reveals nothing at all about any other file's key.

Separately, the encryption itself (AES-256-GCM) carries its own
authentication check, stored alongside the stamp — so if even a single
bit of an encrypted file changes after the fact — a storage glitch, a
bad merge, anything — unlocking fails loudly and immediately, instead
of quietly handing you corrupted data. See
[02-faq.md](02-faq.md#what-if-an-encrypted-file-gets-corrupted--would-i-even-find-out)
for what this does and doesn't catch.

**Details:** [05-key-hierarchy.md](../../specs/securegit/05-key-hierarchy.md)

## Sharing access: every teammate has their own key, not a copy of yours

Adding a teammate never means handing them your key, your passphrase,
or a copy of anything secret. Instead, each person generates their own
personal identity — a matched pair, one half public (safe to paste into
Slack, an email, anywhere) and one half private (never leaves their own
computer, protected the same way their own master key is: passphrase,
hardware key, whatever they've set up).

Adding someone means wrapping a fresh copy of the repository's master
key specifically for their public half — a bit like sealing an envelope
that only their private half can open. From that point on, their
computer can unlock the repository entirely on its own; nothing further
ever has to flow through you.

**This cuts the other way too, and it's worth being direct about:**
removing someone only ever protects generations created *after* they're
removed — `securegit key rotate` only wraps its new generation for
whoever is currently on the recipient list, so a removed person is
automatically left out of everything from that point forward. It cannot
reach back and revoke a master key generation they already received
while they had legitimate access — nothing can, once a key has actually
been handed to someone. See
[02-faq.md](02-faq.md#someone-left-the-team-can-i-lock-them-out) for
what "locking someone out" actually means here.

**Details:** [08-multi-recipient.md](../../specs/securegit/08-multi-recipient.md)

## Not having to unlock every single time: the session

Once you run `securegit unlock`, you're not asked for your passphrase
(or touch prompt, for a hardware key) on every single `git` command
after that — the unlocked master key itself, not some lesser stand-in
for it, is cached in another file outside your repository, for a
limited time (a few hours, by default). Holding that cache file while
it's valid is, functionally, the same as holding the master key
itself — treat access to it with exactly that seriousness. It's why the
cache lives outside the repo, expires on its own, and is never
something `securegit` writes anywhere Git could ever commit.

**Details:** [07-unlock-session.md](../../specs/securegit/07-unlock-session.md)

## Your safety net: a recovery code

Because there's deliberately no "forgot password" reset (a reset button
would be exactly the kind of backdoor this tool exists to avoid),
`securegit` offers a one-time recovery export instead: a code you
generate ahead of time, print or store somewhere safe, and can use
later to get back into a repository even if every other copy of your
key is gone. It's a completely different mechanism from a passphrase or
hardware key — worth setting up once, before you ever need it, not
after.

Treat it as what it actually is: a **bearer credential**, not merely a
backup copy sitting inert until you need it. Anyone who obtains the
code — not just you — can use it to recover your repository's key,
exactly the same way you would. Store it the way you'd store a spare
physical key to your house, not a note to yourself.

**Details:** [09-rotation-recovery.md](../../specs/securegit/09-rotation-recovery.md)

## Putting it all together

```
   your passphrase / YubiKey touch / cloud vault call
                     │
                     │  unlocks (this is the swappable "provider")
                     ▼
        ┌─────────────────────────────┐
        │   repository master key      │   one 32-byte secret,
        │   (one per "generation")     │   never stored in the repo
        └──────────────┬───────────────┘
                        │
                        │  recalculated automatically, per file,
                        │  never stored anywhere
                        ▼
        ┌─────────────────────────────┐
        │   this file's own key        │
        └──────────────┬───────────────┘
                        │
                        ▼
        ┌─────────────────────────────┐
        │   your file, now safe to     │   this is the only thing
        │   commit, push, back up      │   Git or GitHub ever sees
        └───────────────────────────────┘
```

## Quick reference

| Thing | Where it actually lives | What protects it | If you lose it |
|---|---|---|---|
| Repository master key | Your keyring file, outside the repo (or on a hardware device, or in a cloud vault) | Your passphrase / hardware touch / cloud vault access | Gone, unless a teammate still has access or you saved a recovery code |
| Per-file key | Nowhere — recalculated on the spot every time | The master key it's derived from | N/A — never stored, never lost separately |
| Your identity keypair | Your own computer, private half never leaves it | Same provider as your master key | A teammate can add your new identity if you get a new device |
| A teammate's access | A wrapped copy of the master key, committed to the repo in plain (but not secret) form | Their own private identity half, which never left their computer | Removing them + rotating stops them reading anything new; see [02-faq.md](02-faq.md#someone-left-the-team-can-i-lock-them-out) |
| Session cache | A file outside the repo, expires on its own | Same protection as the master key, while it exists | Nothing lost — just unlock again |
| Recovery code | Wherever you printed or stored it — securegit keeps no copy | Physical/storage security of wherever you kept it | Gone — this was the backup; there's no backup for the backup |
