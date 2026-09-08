# FAQ

Plain-language answers to the questions people actually ask. Every answer
links to the full technical spec at the bottom, for anyone who wants the
precise details.

## What does securegit actually do?

It encrypts specific files on your own computer before Git ever sees
them. You keep working normally — the encryption happens automatically
every time you `git add` or `git commit`, and un-does itself automatically
every time you check the file out again. GitHub, your backups, anyone who
copies the repository — they only ever see scrambled, unreadable data for
the files you've protected. Only someone who holds the right key can turn
it back into the real file.

**Details:** [README.md](../../README.md)

## Does this change how I use Git day to day?

No. `git add`, `git commit`, `git push`, `git diff`, `git log` — all of
it works exactly the way it always has. You don't type any special
commands to encrypt or decrypt a file; Git does it for you in the
background because you told it to, once, up front.

**Details:** [specs/securegit/02-git-integration.md](../../specs/securegit/02-git-integration.md)

## How do I turn this on?

Two commands, once, in a repository:

```sh
securegit init
securegit protect config/production.json
```

The first sets things up. The second tells it which file (or file
pattern, like `secrets/*.json`) to protect. From then on, just use Git
normally — `git add .`, `git commit`, `git push`.

On a second computer that should also be able to read those files:

```sh
git clone …
securegit unlock
```

**Details:** [README.md](../../README.md#quickstart)

## What kind of keystore does it support? Can I use a TPM, smartcard, or my OS's keychain?

**Two, today, both usable right now via the `securegit` command
itself:**

- **A passphrase** (the default). Your key is stored locally, locked
  behind a passphrase only you know, using the same kind of slow,
  deliberately expensive scrambling banks and password managers use to
  make a stolen copy useless without your actual passphrase (technically:
  `scrypt` to turn your passphrase into a lock, then AES-256-GCM to
  actually lock the key with it).
- **A YubiKey or similar hardware security key** — `securegit key
  add-provider yubikey-piv --slot <slot>` (the key's smartcard mode) or
  `securegit key add-provider yubikey-fido2` (its authentication mode).
  Either way, the actual secret material never leaves the physical
  device — you plug it in and touch it, the device does the unlocking
  math itself, and nothing your computer can read ever includes the raw
  key. Confirmed against a real YubiKey: adding it this way really
  produces a usable slot, and a later `securegit unlock` really succeeds
  through the device alone, even with the wrong passphrase typed.

**One more is built and tested, but not yet reachable from the
`securegit` command line:**

- **A cloud key vault (AWS KMS, Google Cloud KMS, Azure Key Vault)** —
  with an important limit, on purpose: this can never be your *only* way
  in. A cloud provider's key vault is still something that provider
  could theoretically be compelled to unlock, so it's only ever allowed
  as one option among several — useful as a company-wide "break glass"
  backup, never as the single point of trust the whole point of this
  tool is to avoid. The code is built and tested, but not yet against a
  real cloud account (only against realistic simulations, since that
  needs real cloud credentials nobody's plugged in yet), and not yet
  wired into `key add-provider` — its configuration doesn't reduce to a
  simple `--slot <value>` the way the YubiKey did, so wiring it in means
  settling a real design question, not just plumbing.

**Still just a plan, no code yet:** a TPM chip, or your operating
system's own keychain (Windows Credential Manager, macOS Keychain). What's
left overall: [01-architecture.md](01-architecture.md#whats-still-ahead).

Worth keeping separate: this is about what protects *your own*
computer's copy of the key. Sharing that key with a teammate is a
different mechanism entirely (see the next question) — every teammate
still protects their own copy locally, the same way you protect yours.

**Details:** [specs/securegit/06-key-provider-port.md](../../specs/securegit/06-key-provider-port.md)

## How do I give a teammate access?

They generate their own key on their own computer (`securegit identity
init`), send you the public part of it (not a secret — safe to paste
into Slack or email), and you run one command to add them:

```sh
securegit key add-recipient <their public key>
```

That's it — their computer can now unlock the repository on its own.

**Details:** [specs/securegit/08-multi-recipient.md](../../specs/securegit/08-multi-recipient.md)

## Someone left the team. Can I lock them out?

Yes, but it's worth understanding exactly what "locking out" means here.
You can't make them un-see what they already saw — nobody can, once
someone has read something, that's permanent. What you *can* do is make
sure they can't read anything **new** you write from now on:

```sh
securegit key remove-recipient <their fingerprint>   # take them off the list
securegit key rotate                                  # generate a fresh key
securegit reencrypt                                   # move current files onto it
```

After that, their old key still opens everything that existed before
this point — that was always going to be true, encryption or not, the
moment they had legitimate access. But it opens nothing written
afterward. Think of it less like changing a lock and more like moving to
a new lock and only handing out the new key to people still on the team.

**Details:** [specs/securegit/09-rotation-recovery.md](../../specs/securegit/09-rotation-recovery.md)

## Is there an "owner" or admin who controls everyone else's access?

No — and this surprises people. There's no owner role and no permission
levels. Anyone who currently has a working key can do anything: add
someone, remove someone, even remove the person who originally set the
whole thing up. Nothing inside securegit itself stops that.

What actually protects you is everything *around* it, the same way it
already does for your code: you need permission to push to the
repository in the first place, and a change that adds or removes someone
shows up as an ordinary commit that a teammate can review before it's
merged. The tool deliberately doesn't try to be its own gatekeeper — a
gatekeeper is a thing that can go down, get hacked, or be forced to hand
over access, and this project's whole design avoids having one.

**Details:** [specs/securegit/08-multi-recipient.md](../../specs/securegit/08-multi-recipient.md)

## Can someone fake who made a change?

Right now — yes, and this is an honest, currently-open gap, not
something quietly swept under the rug. Git normally trusts whatever name
you type into your own settings; nothing forces that to be true. The
same goes for the record of who added a new teammate — it's whatever the
person running the command typed, not something independently verified.

Because anyone with access can do anything (see the question above),
this matters more than it might for an ordinary tool: someone with
legitimate access, behaving badly, could make it look like the change
came from someone else, or no one in particular. The fix — cryptographic
commit signing, so a change is provably tied to a real key instead of a
typed name — is already planned but not yet turned on by default. Until
then, treat "who made this change" as trustworthy only as your team's
own review habits make it.

**Details:** [specs/securegit/16-adversarial-integrity.md](../../specs/securegit/16-adversarial-integrity.md)

## What happens if I lose my laptop, or forget my passphrase?

If someone else on the team still has access, they can add a new key
for your new computer the same way they'd add anyone else — you're not
permanently locked out just because one device is gone.

If you're the *only* one with access and you lose your passphrase with
no backup, that content is genuinely gone — there's no "forgot password"
reset, on purpose, because a reset button would be exactly the kind of
backdoor this tool exists to avoid. This is why the tool warns you if
you're the only holder of a key with no recovery copy on file, and offers
a one-time recovery export you can print or store somewhere safe ahead
of time, before you need it.

**Details:** [specs/securegit/09-rotation-recovery.md](../../specs/securegit/09-rotation-recovery.md)

## Can GitHub, a cloud backup, or anyone else who stores my repo read my files?

No, not the files you've told it to protect. Everywhere your repository
goes after it leaves your computer — GitHub, a mirror, a backup, a CI
server's cache — it only ever holds the scrambled version. Nobody
storing a copy of your repository can turn it back into the real file
unless they separately hold one of the actual keys, which never gets
uploaded anywhere.

**Details:** [specs/securegit/01-threat-model.md](../../specs/securegit/01-threat-model.md)

## Are the `.gitattributes` file and the `.securegit` folder themselves encrypted?

No to both, but for two different reasons.

**`.gitattributes`** is always plain, readable text — it's the file that
*tells* Git which other files to encrypt, so it can't itself be
encrypted (Git has to be able to read it first). This is normal and
expected.

**`.securegit/`** is actually two different things that happen to share
a name:

- A `.securegit` folder *inside your repository* — this is committed to
  Git and stays plain, readable text on purpose. It only ever holds
  public information: settings, and teammates' public keys (a public key
  isn't a secret — it's the "email address" half of a lock-and-key pair,
  meant to be shared).
- A `.securegit` folder in **your own computer's home folder**, outside
  the repository, that never gets committed to Git at all. This is where
  your actual private key material lives, and its contents *are*
  encrypted — locked behind your passphrase.

So the one thing that's actually secret never even travels with the
repository in the first place.

**Details:** [specs/securegit/05-key-hierarchy.md](../../specs/securegit/05-key-hierarchy.md)

## What if an encrypted file gets corrupted — would I even find out?

Yes, and it's worth knowing *how*, because the obvious guess is wrong.
`git fsck` (Git's own built-in health check) does **not** catch this — it
only checks that Git's internal bookkeeping is sound, not whether the
data inside a file makes any sense. A scrambled, unrecoverable file would
look perfectly fine to `git fsck`.

What actually catches it is the encryption itself. The method used
(AES-256-GCM) doesn't just scramble data — it also seals it with a kind
of tamper-evident stamp. If even a single bit of a protected file changes
after it was encrypted — from a storage glitch, a bad merge, anything —
unlocking it will fail loudly and immediately, instead of silently
handing you garbage and pretending everything's fine. This is tested
directly: the test suite deliberately corrupts encrypted data, byte by
byte, and confirms every single case is caught.

The one honest gap: there isn't yet a single command you can run to
proactively scan your *entire* project history and confirm every
protected file still unlocks correctly — today that check only happens
one file at a time, when you actually open it. A repo-wide "check
everything" command is a reasonable thing to add later; it doesn't exist
yet.

**Details:** [specs/securegit/13-verify.md](../../specs/securegit/13-verify.md)

## I have an old repository that's already full of unencrypted files. Can I switch it over?

Yes — you don't need a fresh start. Three commands:

```sh
securegit init
securegit protect secrets/*.json
securegit reencrypt
```

The first two set things up and tell it which files to protect. The
third is the important one for an existing repo: it takes every file
you just told it to protect — even ones that have been sitting there as
plain, unencrypted text for months — and encrypts them right now, as one
normal commit you can review before it goes anywhere. From that point
on, your everyday `git add`/`commit`/`push` just works, the same as a
brand-new repository.

**The one thing this can't do: erase the past.** Every commit made
*before* that point still has the old file in plain text, permanently,
sitting in your repository's history. Turning on encryption today
protects everything from today onward — it doesn't reach backward in
time. You can find out exactly how much old plaintext you're carrying
with `securegit verify --history`. If you genuinely need that old
history scrubbed too, that requires a separate, more disruptive step
(rewriting your repository's history and force-pushing it — securegit
doesn't do this for you), and even then: if that secret was ever real
and ever seen by someone who shouldn't have it, the only thing that
actually fixes that is changing the secret itself, not hiding where it
used to be written down.

**Details:** [specs/securegit/09-rotation-recovery.md](../../specs/securegit/09-rotation-recovery.md)

## My team already works a certain way — is securegit still worth it?

Almost certainly, but exactly how much depends on how your team already
handles changes to your main branch. There are three common shapes, and
this project actually tests all three for real (not just in theory —
see [03-chaos-sandbox.md](03-chaos-sandbox.md) for the live results):

- **W1 — Direct push.** Anyone can push straight to the main branch, no
  review step. Common on small teams, or any repo nobody's gotten around
  to locking down yet.
- **W2 — Shared branch.** Everyone pushes to one shared branch (often
  called `develop` or `staging`), and someone reviews it before it's
  promoted to the main branch.
- **W3 — Pull requests.** The GitHub/GitLab default: nothing reaches the
  main branch without being reviewed first, every time.

If none of these ring a bell, you're already using one of them — this
isn't something you need to set up, it's just naming how your team
already works.

## What's "Basic" vs "Advance" mode, and which one should I turn on?

**Basic** is securegit's normal, default behavior: your files get
encrypted, full stop, with no extra requirement on who's allowed to push.

**Advance** adds one more rule on top: every push has to be
cryptographically signed by someone already trusted with this
repository's secrets — like an ID check at the door, in addition to the
encryption itself. It catches a very specific kind of attacker: someone
who has ordinary push access but was never actually given a key. Signing
proves *who* is pushing, not just that the file happens to be encrypted
correctly.

### What real tests actually found

| Your team's setup | Basic mode | Advance mode turned on |
|---|---|---|
| **W1** — direct push, no review | Weakest combination. Real tests found genuine leaks got through. | Leaks almost completely disappeared — signing alone did the job, even with zero review process at all. |
| **W2** — shared branch, reviewed before promotion | Surprisingly weak too — the shared branch is already visible to everyone the moment something lands on it, long before any review runs. | Same big improvement as W1 — signing stops the leak before it ever reaches the shared branch. |
| **W3** — pull requests | Already strong on its own — review and branch isolation catch problems before they reach anyone. | Adds a second, independent layer on top — useful if someone with real, legitimate access starts behaving maliciously. |

**In short:** if your team works as W1 or W2, turning on Advance mode is
a big, measured improvement, not a minor tweak — it's the difference
between "somewhat protected" and "well protected" in real tests. If your
team already works as W3 (pull requests), you're already in good shape;
Advance is a worthwhile extra layer, not an urgent fix.

One honest caveat, for the curious: even the strongest setup (W3 +
Advance) isn't airtight against someone who is a fully legitimate,
already-trusted teammate (or an AI coding assistant with real access)
choosing to misuse that access — signing can't tell "trusted person
doing something wrong" apart from "trusted person doing something
right." That specific, narrower scenario is documented and tested too:
see [specs/chaotests/04-agent-threat-model.md](../../specs/chaotests/04-agent-threat-model.md).

**Details:** [03-chaos-sandbox.md](03-chaos-sandbox.md), [specs/chaotests/03-orchestrator.md](../../specs/chaotests/03-orchestrator.md)

## What does securegit *not* protect me from?

Being upfront about the limits matters as much as the guarantees:

- **A hacked or unlocked computer.** If someone has control of your
  computer while your files are unlocked, they can already see
  everything you can see. No encryption tool anywhere can prevent that —
  the protection is about data in transit and at rest elsewhere, not
  about a compromised endpoint.
- **Someone rewriting or deleting history.** Encryption stops someone
  from *reading* a file's contents; it doesn't stop a person with
  ordinary push access from overwriting, rolling back, or deleting
  things. That's what code review and branch protection are for, and
  you still need them.
- **Someone deleting the whole repository.** If your only copy is
  deleted, it's deleted. This is a backup problem, not something
  encryption addresses.
- **Metadata.** File names, file sizes, commit messages, who committed
  something and when, and the shape of your branches are all still
  visible to anyone who can see the repository — only the *contents* of
  protected files are hidden.

**Details:** [specs/securegit/01-threat-model.md](../../specs/securegit/01-threat-model.md)

## Why use this instead of git-crypt, SOPS, or age?

The basic trick — encrypting a file automatically as it goes into Git
and decrypting it automatically as it comes out — isn't new; several
tools do that part. What this one is built around is what happens
*after*: no single person or service ever has to be the one gatekeeper
everyone depends on, and changing who has access, adding a new computer,
or replacing a compromised key never requires touching anything you've
already committed. It also has no other software it depends on to run —
one less thing that could be tampered with in a supply-chain attack.

**Details:** [README.md](../../README.md#why-this-and-not-git-crypt--sops--age)
