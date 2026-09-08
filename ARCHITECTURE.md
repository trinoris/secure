# Architecture: toward `@trinoris/securelib`

**Status: Phases 1 and 2 DONE — real npm workspaces, real package split,
`config.ts`'s `isGitRepo()` seam cut, real green
build/typecheck/test/integration-test, verified on a real Docker build of
the chaos sandbox image too.** Phases 3–5 below are still proposed, not
executed. This document originally described the target shape before
starting; the "Current state" and migration-plan sections below are now
updated to say what actually happened, including corrections the original
plan got wrong (see "Corrections found during Phase 1").

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

## Current state — real, as of Phase 1

Two packages in one npm-workspaces monorepo (`packages/securelib`,
`packages/securegit`; root `package.json` is a private workspace root).
The module split below is what actually landed, not a projection — it
corrects two things the original version of this document got wrong,
found only by doing the split for real and following the actual import
graph rather than a quick grep (see "Corrections found during Phase 1"):

| `packages/securelib/src/` (git-agnostic) | `packages/securegit/src/` (genuinely Git-specific) |
|---|---|
| `crypto.ts` — derivation, AEAD | `filter.ts` — `clean`/`smudge`/`textconv`, the Git filter contract |
| `envelope.ts` — `seal()`/`unseal()`, wire format | `install.ts` — `.gitattributes`, `.git/config` |
| `provider.ts` — the `KeyProvider` port, `PassphraseFileProvider`, **and now `KeySource`/`KeyGeneration`** (moved from `filter.ts` — see below) | `merge.ts` — the Git merge driver |
| `keyring.ts` | `cli.ts` — mostly; a few commands (`clean`/`smudge`/`merge`/`filter-process`) are Git-only, the rest (`key rotate`, `identity`, `encrypt`/`decrypt`) are not |
| `recipients.ts` — multi-recipient wrap/unwrap | `verify.ts`, **the whole module, not just `--history`** (see below) |
| `recovery.ts` — export/import recovery codes | `pktline.ts`, `process.ts` — `filter-process`'s wire protocol |
| `identity.ts` | `index.ts` — the package's own curated re-export barrel |
| `session.ts` — **moved here; the original table missed this one entirely** | the entire `chaos/` sandbox — inherently about Git workflows |

### Corrections found during Phase 1

Both found by tracing the actual import graph
(`grep -oP "from '\./\K[a-zA-Z_-]+(?=\.js')"` across every file), not by
re-reading the original quick-grep table and trusting it:

- **`session.ts` belongs in `securelib`, not listed anywhere in the
  original table.** It's a generic "cache an unwrapped key by repoId,
  with a TTL, on disk" mechanism — its own doc comment motivates it with
  "Git runs filters non-interactively," but nothing in its actual
  mechanism is Git-specific. A future `securedoc` wants the exact same
  "unlock once, stay unlocked for N hours" behavior.
- **`verify.ts` doesn't split cleanly into a git-agnostic base and a
  git-specific `--history` mode — the whole module is git-specific.**
  The original table claimed only `--history` (which walks `git log`)
  was the git-specific part. In fact the *base* `verify()` also imports
  `EXCLUSION_LINE`/`RESIDUE_SUFFIXES` directly from `install.ts` — the
  `.gitattributes` exclusion pattern and residue-file suffixes — so even
  the "always-on" checks are inherently about Git's own attribute
  mechanism. `verify.ts` stayed in `securegit`, whole.
- **A real backward dependency existed and had to be cut, not just
  moved around:** `keyring.ts`, `recipients.ts`, and `session.ts` (all
  now in `securelib`) imported the `KeySource`/`KeyGeneration` types from
  `filter.ts` (Git-specific, staying in `securegit`) — a git-agnostic
  module depending on a git-specific one for a type that was never
  actually about Git. Fixed by moving both interfaces into `provider.ts`
  (`securelib`) — "what a caller gets after a provider successfully
  unwraps a generation" is a `securelib`-port concept, not a filter one —
  and having `filter.ts` import them from there instead of defining them.
- **Four tests were genuinely cross-package integration tests, not
  unit tests of either module alone**, and moved accordingly: `keyring.test.ts`'s
  and `session.test.ts`'s own `"bridges to filter.ts's KeySource
  contract"` blocks (real `clean`/`smudge` calls against a real unlocked
  keyring/session) moved out of `securelib` into a new
  `packages/securegit/src/filter.bridge.test.ts` — they were exercising
  `securegit`'s own filter contract, using `securelib`'s keyring/session
  as the input, so they belong on the consumer side.
- **`package.test.ts`'s T11 (supply-chain) checks had to be redesigned,
  not just relocated** — the single-package version asserted "zero
  dependencies of any kind" and "every import is relative or `node:`."
  Now split: `securelib`'s copy keeps that absolute standard (it's the
  package that actually holds key material — no exception, ever);
  `securegit`'s copy allows exactly one dependency,
  `@trinoris/securelib`, and documents why that's not the supply-chain
  risk T11 exists to catch (same repo, same CI, same review process).
  The "no raw `Buffer#equals()` outside crypto/envelope/identity/
  recovery.ts" and "no raw fingerprint `===`" checks split the same way,
  each now scoped to the files actually present on its own side.
- **The chaos sandbox's Docker image had hardcoded absolute imports**
  (`/app/dist/identity.js`, `/app/dist/crypto.js`, `/app/dist/envelope.js`,
  `/app/dist/session.js`, `/app/dist/config.js`, across
  `chaos/lib/paths.mjs`, `chaos/remote/pre-receive-check.mjs`, and
  `chaos/verifier/verify.mjs`) baked in from the single-package era.
  Fixed: `chaos/Dockerfile` now builds both workspace packages (in
  explicit order — see below) and copies `securelib`'s own `dist/` to
  `/app/node_modules/@trinoris/securelib/dist`, mirroring where the
  workspace symlink puts it during the build stage; the three `.mjs`
  files' absolute imports were repointed there. **Confirmed with a real
  `docker build` plus a real container run** — every one of the five
  re-pointed imports resolves and exports the expected function inside
  the built image, and `chaos/verifier/verify.mjs` starts up normally
  when imported directly.
- **`npm run build --workspaces` does not guarantee build order** — it
  ran `securegit`'s build before `securelib`'s at least once, which
  fails outright (`securegit`'s own build needs `securelib`'s compiled
  `.d.ts`/`.js` already present to resolve `@trinoris/securelib/*`
  imports). Root `package.json`'s `build`/`typecheck`/`test`/
  `test:integration` scripts, and `chaos/Dockerfile`'s build stage, now
  all build `securelib` explicitly first, every time — never left to
  `--workspaces`'s own ordering.

**The one real seam — cut in Phase 2.** `config.ts`'s `initConfig()` no
longer knows what Git is at all; the `isGitRepo()` check (and its
worktree-file handling) moved into `securegit`'s own `cli.ts`, called by
`cmdInit()` before `initConfig()` is reached. `securelib` now genuinely
has no opinion on what kind of directory it's initialising into — a
future `@trinoris/securedoc` consumer supplies its own "is this a valid
place to initialise" check (or none) at its own call site, exactly as
`securegit` now does.

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
with no change to either provider package. Both are ordinary sibling
workspace packages under this repo's own `packages/*`, per
`06-key-provider-port.md`'s "Loading a provider package without paying
for it" — no separate repository or workspace of their own needed.
`kms-envelope` is deliberately not a third companion package: its own
design note settles that it stays dependency-free enough (hand-rolled
request signing, no cloud SDK) to live inside `securelib` core itself,
loaded eagerly like `passphrase-file`, not through the dynamic-`import()`
path the two hardware providers need.

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

## Migration plan

1. **DONE. Introduce workspace tooling, no behavior change.**
   `packages/securelib/` and `packages/securegit/`, npm workspaces (the
   built-in tool, not pnpm — no new dependency needed, and npm ≥7 already
   ships with every environment this project already requires). Every
   existing test moved with the module it tests, plus the corrections
   above. Verified, not asserted: `npm run build`, `npm run typecheck`,
   `npm test` (754 tests: 388 in `securegit`, 366 in `securelib`, up from
   748 in the single package — the +6 are `filter.bridge.test.ts`'s tests,
   moved intact, none lost or duplicated), and
   `npm run test:integration` (40 tests, drives a real `git` binary) all
   pass, from the workspace root, exactly as CI invokes them. The chaos
   sandbox's Docker image builds and its five re-pointed absolute imports
   were confirmed resolving inside a real running container. Every CLI
   command's behavior is unchanged — this was a file-mover and an
   import-path-updater, confirmed to be exactly that and nothing more.
2. **DONE. Cut the one real seam.** `initConfig()` in `securelib`'s
   `config.ts` no longer checks for `.git` at all — that check (plus its
   worktree-file handling) moved verbatim into a new `isGitRepo()` in
   `securegit`'s `cli.ts`, called by `cmdInit()` before `initConfig()` is
   even reached. Zero change to `securegit`'s own behavior or error
   messages — the existing "exits 4 outside a git repository" test in
   `cli.test.ts` passed unmodified; a new "accepts a worktree-style .git
   file" test was added there to keep that coverage at the layer that now
   owns the check. `securelib`'s `config.test.ts` lost its two git-specific
   cases and gained one proving the opposite: `initConfig()` now succeeds
   with no `.git` present at all — the actual evidence the seam is cut,
   not just moved. Verified: `npm run build`, `npm run typecheck`,
   `npm test` (754 tests: 389 in `securegit` (+1), 365 in `securelib`
   (net −1) — same total, exactly accounted for), `npm run
   test:integration` (40 tests) all pass.
3. **Publish `@trinoris/securelib` as its own package.** Once the split
   builds and tests green with no behavioral diff, it graduates from
   "code living in a workspace" to "a real, independently versioned
   dependency" — this is the point `securegit`'s own `package.json` gains
   a real, external `@trinoris/securelib` dependency rather than a
   workspace link.
4. **IN PROGRESS. Build the provider companion packages against the
   now-public port.** Packaging is settled and built
   (`06-key-provider-port.md`'s "Loading a provider package without
   paying for it"): `registry.ts`'s `loadProvider()` resolves
   `kms-envelope` from `BUILTIN`, and `yubikey-piv`/`yubikey-fido2` by
   dynamic `import()` naming convention, giving an actionable
   `npm install @trinoris/securelib-*` error when the (not yet built)
   companion package is absent. All three `KeyProvider` implementations
   themselves are built and pass the full conformance suite against a
   real cryptographic fake (`kms-envelope.ts`, `piv.ts`, `fido2.ts`) — a
   real bug caught along the way: `KmsEnvelopeProvider.unwrap()`
   originally trusted the wrapped payload's own `keyId` instead of
   checking it against the caller's configured key. **All three cloud
   `KmsBackend`s are built**: `aws-kms-backend.ts` (hand-rolled SigV4),
   `gcp-kms-backend.ts` (service-account JWT-bearer OAuth), and
   `azure-kms-backend.ts` (Azure AD client-credentials; caller-supplied
   AES-256-GCM IV packed with the tag into one opaque blob, a real bug
   caught and fixed along the way — the first draft ignored the passed
   `keyId` entirely and used vault/key/version fixed at construction
   instead). GCP's JWT and Azure's AEAD framing are verified with real
   cryptography offline (an actual RSA sign/verify pair; a fake vault
   running real AES-256-GCM); AWS's SigV4 is checked only structurally,
   since byte-exactness needs a live endpoint. **None of the three has
   run against a real cloud account** — no credentials exist in this
   environment. Each has a real-credential integration test written and
   ready (`describe.skipIf`) — run one against a real key before trusting
   it in production. **What's left, not attempted because real hardware
   is the only way to verify it and can never run in CI regardless:** the
   two real companion packages, `@trinoris/securelib-piv`/`-fido2` (PC/SC
   and CTAP2/HID).
5. **`@trinoris/securedoc`** (future, unscoped) becomes a second real
   consumer of `securelib`, proving the extraction was worth doing rather
   than merely aesthetic.

Phases 1 and 2 are done, verified as described above. Phases 3–5 have not
started. Phase 3 (publishing `@trinoris/securelib` as its own
independently-versioned package) is next, but depends on choices
(registry, versioning cadence) worth revisiting when actually reached
rather than deciding now.

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
