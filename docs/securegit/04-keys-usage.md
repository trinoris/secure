# Keys: What Protects What

A lot of different things get called "the key" when people talk about
securegit — your passphrase, a YubiKey, the file that gets encrypted,
the thing your teammate has. This page walks through each one, in plain
terms: what it actually is, where it lives, and what protects it. Every
section links to the precise technical spec at the bottom, for anyone
who wants the exact details.

## The one secret that actually matters

Underneath everything, there is exactly **one secret per repository**:
a 32-byte number, generated once, that everything else in this page is
really just "how is *this* protected" or "what gets calculated *from*
it automatically." This project calls it the **repository master key**.

A few things are true of it, always:

- It's generated on your computer and never leaves it — except when a
  hardware key or a cloud vault holds it instead, in which case it never
  leaves *that* (more on this below).
- It's never uploaded, never committed to Git, never written anywhere
  inside your repository.
- It's the one thing that, if you lost every copy of it with no
  recovery plan, would mean your encrypted files are gone for good — see
  [02-faq.md](02-faq.md#what-happens-if-i-lose-my-laptop-or-forget-my-passphrase).

Rotating your key (`securegit key rotate`) doesn't erase the old one —
it adds a new "generation" on top. Every file encrypted under
generation 1 still needs generation 1's key to open; a file you touch
after rotating gets encrypted under generation 2. Your keyring quietly
holds every generation you've ever had, so nothing you've already
written ever becomes unreadable to you.

**Details:** [05-key-hierarchy.md](../../specs/securegit/05-key-hierarchy.md)

## Where it lives, and what locks it

The master key is stored on your computer, but never in plain,
readable form — it's locked ("wrapped," in the technical spec) behind
something only you can produce. Which "something" is swappable — that's
what this project calls a **provider**. Right now, one is available
from the `securegit` command line itself:

- **A passphrase** (today's default, and the only one `securegit key
  add-provider` currently understands). Your passphrase itself is never
  stored anywhere — instead, it's run through a slow, deliberately
  expensive scrambling process (the same kind banks and password
  managers use) to produce a lock, and the master key is sealed behind
  that lock. Guessing your way in without the real passphrase is
  designed to be prohibitively slow, even for someone who steals the
  locked file itself.

Two more are real, working, tested code — just not yet reachable from
the `securegit` command itself (see
[02-faq.md](02-faq.md#what-kind-of-keystore-does-it-support-can-i-use-a-tpm-smartcard-or-my-oss-keychain)
for exactly what "not yet reachable" means):

- **A YubiKey or similar hardware security key.** The master key gets
  locked using a calculation the *physical device itself* performs —
  you plug it in and touch it, and the secret math never happens
  anywhere your computer could read it. Even if your whole computer were
  compromised, the key material on the device stays out of reach without
  the device physically present and touched.
- **A cloud key vault** (AWS, Google Cloud, or Azure's key-management
  service). The vault locks and unlocks your master key on request, over
  the network. This one comes with a real, deliberate limit: it can
  never be your *only* way in. A cloud provider's vault is still
  something that provider could theoretically be compelled to unlock —
  useful as a company-wide "break glass" backup, never as the single
  point of trust the whole tool exists to avoid.

The difference between the last two matters enough to have a name:
**can whoever holds this lock be forced to open it without you?** A
passphrase only you know: no. A YubiKey that performs the unlock
calculation on the device itself, requiring your physical touch: no.
A cloud vault a company operates: in principle, yes — which is exactly
why it's never allowed to be the *only* lock on a repository.

**Details:** [06-key-provider-port.md](../../specs/securegit/06-key-provider-port.md)

## The key for one specific file — which you never see

securegit does **not** keep a separate stored secret for every file you
protect. Instead, every time it needs one, it recalculates a per-file
key on the spot, from two things: your master key, and that exact
file's content. Change one byte of the file, and its per-file key comes
out completely different — but hand it the same content twice, and it
always recalculates the *identical* key, every time.

That last property is deliberate, not incidental: it's what makes
`git diff`/`git status` behave sanely on encrypted files (committing the
same content twice produces the same encrypted bytes, not a noisy,
meaningless diff every time), and it means there's genuinely nothing
extra to back up or lose — the per-file key was never stored anywhere
to begin with, only ever recalculated when needed. It also means
figuring out one file's key (which nobody can do without your master
key anyway) reveals nothing at all about any other file's key.

Every protected file also carries a small tamper-evident stamp,
calculated the same automatic way. If even a single bit of an encrypted
file changes after the fact — a storage glitch, a bad merge, anything —
unlocking it fails loudly and immediately, instead of quietly handing
you corrupted data. See
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

**Details:** [08-multi-recipient.md](../../specs/securegit/08-multi-recipient.md)

## Not having to unlock every single time: the session

Once you run `securegit unlock`, you're not asked for your passphrase
(or touch prompt, for a hardware key) on every single `git` command
after that — the unlocked master key is cached, for a limited time (a
few hours, by default), in another file outside your repository. This
cache is exactly as sensitive as your master key itself while it
exists, which is why it lives outside the repo, expires on its own, and
is never something `securegit` writes anywhere Git could ever commit.

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
