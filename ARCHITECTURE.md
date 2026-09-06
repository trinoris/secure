# Architecture: toward `@trinoris/securelib`

**Status: PROPOSED. Nothing in this document has been executed yet** — no
package has been split, no code has moved, no new npm package exists. This
is the target shape and the reasoning for it, written down before the
migration starts, the same way this project writes a spec before building
a feature.

## The core insight

Nothing about the envelope format, the key hierarchy, the provider port,
or multi-recipient sharing is specific to Git. Git is the transport and
storage layer this project happened to build against first — `seal()`/
`unseal()` (`src/envelope.ts`) operate on plain `Buffer`s, not Git blobs;
the `KeyProvider` port (`specs/securegit/06-key-provider-port.md`) wraps
and unwraps a 32-byte key with no notion of `.gitattributes`, commits, or
branches anywhere in its interface. The only things in this codebase that
genuinely know they're talking to Git are the clean/smudge/textconv/merge
filter wiring, `.gitattributes` handling, the CLI's git-specific commands,
and `verify`'s history-walking checks.

That split was never designed as a package boundary — it fell out of
ordinary module decomposition. It's worth becoming a real package
boundary now, for a concrete reason: `@trinoris/securegit-piv` (agreed on
in [06-key-provider-port.md](specs/securegit/06-key-provider-port.md)'s
"Concrete designs" section) has *nothing git-specific about it either* —
a hardware key that wraps and unwraps a 32-byte secret is exactly as
useful to a tool that isn't Git as it is to this one. Naming it
`securegit-piv` would have been premature coupling to a name, not just a
package.

## Current state

One package, `@trinoris/securegit`, no workspace tooling. But the
module split described above already exists inside `src/`:

| Already git-agnostic (operates on bytes, keys, and provider abstractions) | Genuinely Git-specific |
|---|---|
| `crypto.ts` — derivation, AEAD | `filter.ts` — `clean`/`smudge`/`textconv`, the Git filter contract |
| `envelope.ts` — `seal()`/`unseal()`, wire format | `install.ts` — `.gitattributes`, `.git/config` |
| `provider.ts` — the `KeyProvider` port, `PassphraseFileProvider` | `merge.ts` — the Git merge driver |
| `keyring.ts` | `cli.ts` — mostly; a few commands (`clean`/`smudge`/`merge`/`filter-process`) are Git-only, the rest (`key rotate`, `identity`, `encrypt`/`decrypt`) are not |
| `recipients.ts` — multi-recipient wrap/unwrap | `verify.ts`'s `--history` mode — walks `git log` |
| `recovery.ts` — export/import recovery codes | the entire `chaos/` sandbox — inherently about Git workflows |
| `identity.ts` | |

**One real seam still needs cutting, not zero.** `config.ts`'s `init()`
refuses unless `isGitRepo()` finds a `.git` — the one place a nominally
git-agnostic module actually checks for Git. A `securelib` consumer that
isn't a git repository (a plain folder of documents, for
`@trinoris/securedoc` below) needs its own, different "is this a valid
place to initialise" check, not this one. Small, identified, not yet
done.

## Target: three kinds of package

### `@trinoris/securelib` — the shared core

Everything in the left-hand column above, published as its own package
with its own semver. Exposes `seal()`/`unseal()`, the `KeyProvider` port
and `PassphraseFileProvider`, the recipient sharing model, rotation and
recovery-code primitives, and identity keypairs. Depends on nothing but
`node:crypto` and `node:fs` — the "zero runtime dependencies" property
this project already treats as a stated security property
([README.md](README.md)) moves here as the property's actual home, since
this is the package that actually holds keys.

### `@trinoris/securegit` — a consumer, not the core

Keeps everything in the right-hand column: the Git filter, `install`,
the merge driver, the CLI, `verify`'s history-walking, the chaos sandbox.
Takes a real dependency on `@trinoris/securelib` for anything
cryptographic. From a user's perspective, nothing changes — `securegit
init`, `protect`, `unlock`, all of it, look and behave identically. This
is a packaging change, not a behavior change.

### Provider companion packages — `@trinoris/securelib-piv`, `@trinoris/securelib-fido2`

Renamed from the `securegit-piv` name used when these were first
proposed, per this document's own core insight: a `KeyProvider`
implementation has no idea what its caller does with the key it
wraps and unwraps, so it belongs under the shared library's namespace,
not any one consumer's. Each is a `KeyProvider` implementation
(`specs/securegit/06-key-provider-port.md`'s "Concrete designs" section
has the crypto design for both) that plugs into `@trinoris/securelib`'s
port — installable by `securegit` today, and by `securedoc` tomorrow,
with no change to either provider package. A future `@trinoris/securelib-kms`
is a candidate for the same treatment, though `kms-envelope`'s own design
note already argues it can stay dependency-free enough to live inside
`securelib` core itself (hand-rolled request signing, no cloud SDK) —
worth deciding at implementation time, not speculatively here.

### `@trinoris/securedoc` — future, unscoped

A sibling project for documents instead of Git: same envelope format,
same provider port, same recipient-sharing model — a different
integration surface entirely (not a clean/smudge filter; something more
like a folder-watching sync tool, or direct encrypt/decrypt commands
against arbitrary files). **Named here only to explain why the
extraction is worth doing now, not to design it.** Nothing about its own
shape, CLI, or file layout is decided by this document.

## Why extract now, before `securedoc` exists

Doing this while `securegit` is the only consumer means the extraction
is a refactor with an existing, comprehensive test suite as a safety net
(`crypto.test.ts`, `envelope.test.ts`, `provider.conformance.test.ts`,
`recipients.test.ts`, `recovery.test.ts` already test exactly the
git-agnostic surface, unchanged by which package it ends up in) — the
tests just move with the code they cover, and green stays green.
Building `securedoc` first and extracting afterward would instead mean
two independent implementations of the same envelope format and key
hierarchy, built at different times by people making different
incidental choices, needing to be reconciled into one shared library
after the fact — real, avoidable risk for no benefit.

## Migration plan (phased, none of it started)

1. **Introduce workspace tooling, no behavior change.** `packages/securelib/`
   and `packages/securegit/` (npm or pnpm workspaces — not yet decided
   which), moving the git-agnostic modules into `securelib` verbatim, with
   `securegit` depending on it via a workspace link. Every existing test
   moves with the module it tests. `npm test`, `npm run build`, and every
   CLI command's behavior stay byte-for-byte identical — this phase is a
   file-mover and an import-path-updater, not a rewrite.
2. **Cut the one real seam.** `config.ts`'s `isGitRepo()` check becomes
   something the `securegit`-side caller supplies (e.g. `init()` takes a
   `validateEnvironment` callback, or `securelib`'s own `init()` drops the
   check entirely and `securegit`'s wrapper adds it back) — the only
   actual code change in this migration, everything else is relocation.
3. **Publish `@trinoris/securelib` as its own package.** Once the split
   builds and tests green with no behavioral diff, it graduates from
   "code living in a workspace" to "a real, independently versioned
   dependency" — this is the point `securegit`'s own `package.json` gains
   a real, external `@trinoris/securelib` dependency rather than a
   workspace link.
4. **Build the provider companion packages against the now-public port.**
   This is where the `kms-envelope`/`yubikey-piv`/`yubikey-fido2` design
   work from `06-key-provider-port.md` actually gets implemented — against
   a stable, published `securelib`, not against `securegit`'s internals.
5. **`@trinoris/securedoc`** (future, unscoped) becomes a second real
   consumer of `securelib`, proving the extraction was worth doing rather
   than merely aesthetic.

No phase above has started. Phase 1 is the natural next step whenever
this is picked up — it's the only phase with no design decisions left
to make.

## Relationship to other specs

- [specs/securegit/06-key-provider-port.md](specs/securegit/06-key-provider-port.md)
  — the `KeyProvider` port this whole document is built around, and the
  concrete `kms-envelope`/`yubikey-piv`/`yubikey-fido2` designs that will
  land in `securelib` and its companion packages
- [specs/securegit/04-envelope-format.md](specs/securegit/04-envelope-format.md),
  [05-key-hierarchy.md](specs/securegit/05-key-hierarchy.md) — the format
  and derivation tree that move to `securelib` unchanged
- [README.md](README.md) — "zero runtime dependencies," the property
  that moves to `securelib` as its actual home
