# Architecture

How this repository is organized, and why it's split the way it is.

## The core insight

Nothing about the envelope format, the key hierarchy, the provider port,
or multi-recipient sharing is specific to Git. Git is the transport and
storage layer this project happened to build against first — `seal()`/
`unseal()` operate on plain `Buffer`s, not Git blobs; the `KeyProvider`
port ([06-key-provider-port.md](../../specs/securegit/06-key-provider-port.md))
wraps and unwraps a 32-byte key with no notion of `.gitattributes`,
commits, or branches anywhere in its interface. The only things in this
codebase that genuinely know they're talking to Git are the
clean/smudge/textconv/merge filter wiring, `.gitattributes` handling,
the CLI's git-specific commands, and `verify`'s history-walking checks.

That split isn't just a module boundary inside one package — it's a real
package boundary, because a `KeyProvider` implementation (a hardware key,
a cloud KMS backend) has *nothing* git-specific about it either: a
component that wraps and unwraps a 32-byte secret is exactly as useful
to a tool that isn't Git as it is to this one.

## The packages

An npm-workspaces monorepo, four real packages:

| Package | What it is | Depends on |
|---|---|---|
| `@trinoris/securelib` | The shared core: envelope format, key derivation, the `KeyProvider` port, multi-recipient sharing, rotation and recovery-code primitives, identity keypairs. Zero runtime dependencies — the package that actually holds keys. | nothing but `node:crypto`/`node:fs` |
| `@trinoris/securegit` | The Git integration: the clean/smudge/textconv/merge filter, `.gitattributes` handling, the CLI, `verify`'s history-walking, the chaos sandbox. From a user's perspective this *is* "securegit" — `securegit init`, `protect`, `unlock`, all of it. | `@trinoris/securelib` |
| `@trinoris/securelib-piv` | A real `KeyProvider` transport for YubiKey/PIV smartcards — built and verified against physical hardware. Zero npm dependencies of its own; shells out to already-installed system tools (`ykman`, OpenSC's `pkcs11-tool`) rather than a native PC/SC addon. | `@trinoris/securelib` (peer) |
| `@trinoris/securelib-fido2` | The FIDO2/CTAP2 equivalent, via the `hmac-secret` extension — same hardware-verified standard, shells out to libfido2's CLI tools. | `@trinoris/securelib` (peer) |

Every `KeyProvider` implementation plugs into `@trinoris/securelib`'s
port — installable by `securegit` today, and by any future non-Git
consumer of the same library with no change to the provider package
itself. `securelib`'s own `registry.ts` loads each companion package
lazily (a dynamic `import()` by naming convention), so a user who never
touches a YubiKey never pays for PC/SC bindings in their own dependency
tree — see
[06-key-provider-port.md](../../specs/securegit/06-key-provider-port.md)'s
"Loading a provider package without paying for it" for the exact
mechanism.

`kms-envelope` (AWS/GCP/Azure cloud KMS) is deliberately not a fifth
package: its design stays dependency-free enough (hand-rolled request
signing, no cloud SDK) to live inside `securelib` core itself, loaded
eagerly the same way the built-in passphrase provider is.

## Why the split happened before a second real consumer existed

Doing this while `securegit` was the only consumer meant the extraction
was a refactor with an existing, comprehensive test suite as a safety
net — the git-agnostic tests just moved with the code they cover, and
green stayed green throughout. Building a second consumer first and
extracting afterward would instead have meant two independent
implementations of the same envelope format and key hierarchy,
reconciled into one shared library after the fact — real, avoidable risk
for no benefit.

## What's still ahead

- **Publishing `@trinoris/securelib` as its own independently-versioned
  package**, rather than a workspace link — the point `securegit`'s own
  `package.json` gains a real, external dependency. Depends on choices
  (registry, versioning cadence) worth deciding when actually reached.
- **Wiring the built, hardware-verified providers (YubiKey PIV/FIDO2,
  cloud KMS) into `securegit`'s own CLI.** They exist and work at the
  library level today; `securegit key add-provider` only knows about
  `passphrase-file` so far — see
  [02-faq.md](02-faq.md#what-kind-of-keystore-does-it-support-can-i-use-a-tpm-smartcard-or-my-oss-keychain).
- **A second real consumer of `securelib`** for something other than
  Git, proving the extraction was worth doing rather than merely
  aesthetic.

## Relationship to other docs

- [specs/securegit/06-key-provider-port.md](../../specs/securegit/06-key-provider-port.md)
  — the `KeyProvider` port this whole document is built around, and the
  concrete `kms-envelope`/`yubikey-piv`/`yubikey-fido2` designs
- [specs/securegit/04-envelope-format.md](../../specs/securegit/04-envelope-format.md),
  [05-key-hierarchy.md](../../specs/securegit/05-key-hierarchy.md) — the
  wire format and derivation tree `securelib` implements
- [04-keys-usage.md](04-keys-usage.md) — the same key hierarchy, explained
  in plain English for people using the tool, not building it
- [../../README.md](../../README.md) — "zero runtime dependencies," the
  property `securelib` holds absolutely and `securegit` holds with one
  documented, same-repo exception
