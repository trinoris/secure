# `@trinoris/secure` workspace

[![Build CI](https://github.com/trinoris/secure/actions/workflows/build-ci.yml/badge.svg)](https://github.com/trinoris/secure/actions/workflows/build-ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://trinoris.github.io/secure/coverage-badge.json)](https://github.com/trinoris/secure/actions/workflows/build-ci.yml)
[![Audit](https://img.shields.io/endpoint?url=https://trinoris.github.io/secure/audit-badge.json)](https://github.com/trinoris/secure/actions/workflows/build-ci.yml)
[![CodeQL](https://github.com/trinoris/secure/actions/workflows/codeql.yml/badge.svg)](https://github.com/trinoris/secure/actions/workflows/codeql.yml)
[![Secret Scan](https://github.com/trinoris/secure/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/trinoris/secure/actions/workflows/gitleaks.yml)
[![Release](https://github.com/trinoris/secure/actions/workflows/release.yml/badge.svg)](https://github.com/trinoris/secure/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Chaos Match Viewer](https://img.shields.io/badge/chaos%20sandbox-live%20replay-3ecf8e)](https://trinoris.github.io/secure/)

This repository is a workspace of four packages, not one package with a
misleading name: `@trinoris/securelib` (the shared, dependency-free core
that actually holds keys), `@trinoris/securegit` (the Git integration most
users will actually run), and `@trinoris/securelib-piv`/`-fido2` (hardware
key-provider transports, verified against real YubiKeys). See
[Packages](#packages) below for what each one does and its individual
coverage/audit status.

`@trinoris/securegit` is the flagship consumer, and what the rest of this
README mostly talks about: client-side Git encryption via a transparent
`clean`/`smudge` filter that encrypts selected files on your own
workstation, so the repository — every commit, every push, every mirror,
every backup — is AES-256-GCM ciphertext everywhere it goes afterward.

> **The boundary is the process, not the network.** Plaintext exists in the
> working tree, on a machine that holds a key. `.git/objects`, the remote,
> the mirror, the backup and the bundle hold ciphertext, and no cloud
> provider ever holds anything that can decrypt it.

```
   worktree                          object database              remote
   ────────                          ───────────────              ──────
   plaintext  ──── clean ─────────▶  ciphertext  ──── push ────▶  ciphertext
   plaintext  ◀─── smudge ────────   ciphertext  ◀─── fetch ───   ciphertext
                   textconv ──────▶  plaintext, for display only
```

Day to day, nothing about the workflow changes:

```sh
git add . && git commit -m "hello" && git push
```

`git add`, `git status`, `git diff`, `git log -p` all behave normally — the
filter is invisible until you go looking for it.

## Packages

| Package | Purpose | Coverage | Audit |
| --- | --- | --- | --- |
| [`@trinoris/securelib`](packages/securelib) | The shared core: envelope format, key derivation, the `KeyProvider` port, multi-recipient sharing, rotation and recovery-code primitives, identity keypairs. Zero runtime dependencies — the package that actually holds keys. | [![securelib coverage](https://img.shields.io/endpoint?url=https://trinoris.github.io/secure/coverage-badge-securelib.json)](packages/securelib) | [![securelib audit](https://img.shields.io/endpoint?url=https://trinoris.github.io/secure/audit-badge-securelib.json)](packages/securelib) |
| [`@trinoris/securegit`](packages/securegit) | The Git integration: the clean/smudge/textconv/merge filter, `.gitattributes` handling, the CLI, `verify`'s history-walking, the chaos sandbox. From a user's perspective this *is* "securegit". | [![securegit coverage](https://img.shields.io/endpoint?url=https://trinoris.github.io/secure/coverage-badge-securegit.json)](packages/securegit) | [![securegit audit](https://img.shields.io/endpoint?url=https://trinoris.github.io/secure/audit-badge-securegit.json)](packages/securegit) |
| [`@trinoris/securelib-piv`](packages/securelib-piv) | A real `KeyProvider` transport for YubiKey/PIV smartcards — built and verified against physical hardware. Shells out to already-installed system tools (`ykman`, OpenSC's `pkcs11-tool`) rather than a native PC/SC addon. | [![securelib-piv coverage](https://img.shields.io/endpoint?url=https://trinoris.github.io/secure/coverage-badge-securelib-piv.json)](packages/securelib-piv) | [![securelib-piv audit](https://img.shields.io/endpoint?url=https://trinoris.github.io/secure/audit-badge-securelib-piv.json)](packages/securelib-piv) |
| [`@trinoris/securelib-fido2`](packages/securelib-fido2) | The FIDO2/CTAP2 equivalent, via the `hmac-secret` extension — same hardware-verified standard, shells out to libfido2's CLI tools. | [![securelib-fido2 coverage](https://img.shields.io/endpoint?url=https://trinoris.github.io/secure/coverage-badge-securelib-fido2.json)](packages/securelib-fido2) | [![securelib-fido2 audit](https://img.shields.io/endpoint?url=https://trinoris.github.io/secure/audit-badge-securelib-fido2.json)](packages/securelib-fido2) |

`securelib-piv` and `securelib-fido2` are peer dependents of `securelib`,
loaded by it at runtime via a dynamic-import registry
([06-key-provider-port.md](specs/securegit/06-key-provider-port.md)) —
neither is a build-time dependency of `securegit` itself. See
[docs/securegit/01-architecture.md](docs/securegit/01-architecture.md) for
the full reasoning behind the split. Coverage and audit badges above are
per-package (each package has its own `vitest.config.ts` branch-coverage
threshold and is audited independently — see [Development](#development));
a single static analysis pass (CodeQL, badge above) covers every package's
TypeScript in one run, since CodeQL has no notion of workspace boundaries.
All badges refresh nightly (and on manual dispatch), same cadence as the
chaos sandbox site they're published alongside.

## Why this matters

Leaked credentials in version control are a well-documented, recurring
cause of real breaches — not a hypothetical. A committed `.env` file, a
database connection string, an API key in a config file: the moment it's
pushed, it's in every clone, every fork, every CI runner's cache, and
every backup snapshot that's already run. Rewriting history afterward
rarely reaches all of them, and by then the secret itself has to be
treated as burned regardless.

What client-side encryption actually buys, concretely:

- **A compromised third party's blast radius drops to zero for file
  contents.** Your cloud storage provider, your CI runner, a mirror you
  don't administer, a backup vendor — every one of them ends up holding
  ciphertext only. A breach at any of them is not a breach of your
  source, which matters as much for compliance narratives ("can this
  cloud provider produce our plaintext under compulsion?") as for
  security ones — see
  [specs/securegit/01-threat-model.md](specs/securegit/01-threat-model.md)'s
  "requirement that rules out KMS as a root".
- **Revoking access is a real, forward-acting operation, not a hope.**
  `key rotate` moves the repository onto a generation a departed
  contractor's or employee's key cannot unwrap for anything written
  afterward — see
  [specs/securegit/09-rotation-recovery.md](specs/securegit/09-rotation-recovery.md).
  It does not (and cannot) erase what they already read; nothing can.
  But it stops the leak from continuing, which is the part every other
  "revoke access" story in a plain Git repo can't actually deliver.
- **No new habits for the team to remember.** `git add`, `git commit`,
  `git push`, `git diff`, `git log -p` all behave exactly as before. A
  security control that depends on people remembering an extra step
  under deadline pressure is a control that eventually gets skipped —
  this one doesn't ask for that.
- **Zero runtime dependencies.** A tool that holds encryption keys is an
  unusually attractive supply-chain target. This one has nothing to
  compromise besides itself.

**The adoption cost is `securegit init` and a few minutes; the incident
this prevents is measured in days of response, forced credential
rotation across every system the secret touched, and — depending on
what leaked — mandatory disclosure.** And unlike almost every other
control on this list, it works *before* the first plaintext byte ever
leaves the workstation, not after something has already gone wrong.

None of this is only asserted — [docs/securegit/03-chaos-sandbox.md](docs/securegit/03-chaos-sandbox.md) is a live,
adversarial simulation that measures it against real Git, real attacks,
and three real-world code-review workflows compared side by side, with
results published from an actual run every night.

## Quickstart

```sh
securegit init
securegit install
securegit protect config/production.json
git add . && git commit -m "hello" && git push
```

On a second machine that already holds a key for this repository:

```sh
git clone …
securegit unlock
```

## Install

Not yet published to a package registry (no tagged release exists yet —
see `.github/workflows/release.yml`). For now, build from source:

```sh
git clone git@github.com:trinoris/secure.git
cd secure
npm ci
npm run build
npm link --workspace=packages/securegit  # puts `securegit` on your PATH,
                                          # or run node
                                          # packages/securegit/dist/bin/securegit.js
                                          # directly
```

Once a `v*` tag is pushed, releases publish to GitHub Packages under the
`@trinoris` scope — install with an `.npmrc` pointing that scope at
`https://npm.pkg.github.com`.

## Why this, and not `git-crypt` / SOPS / `age`

The mechanism — a Git clean/smudge filter — isn't novel. What this bets on
is what sits behind it: no single custodial party can ever be the sole
decryption path, and key lifecycle (losing a machine, adding one, rotating
a compromised generation) works without ever touching already-committed
ciphertext. Zero runtime dependencies, on purpose — a package that holds
encryption keys is an unusually attractive place for a supply-chain
attack. The full comparison and reasoning: [specs/securegit/README.md](
specs/securegit/README.md#why-this-and-not-git-crypt--sops--age).

## Documentation

- **[specs/securegit/](specs/securegit/README.md)** — the full design: threat
  model, envelope format, key hierarchy, every CLI command's contract, and
  the current build status of each piece.
- **[specs/chaotests/](specs/chaotests/00-test-plan.md)** — resilience and
  chaos testing: process kills mid-write, concurrent races, a multi-actor
  Docker sandbox with adversarial agents, and the match-replay viewer that
  renders a run as a game (published nightly — see below).
- **[docs/securegit/01-architecture.md](docs/securegit/01-architecture.md)**
  — how this repository's packages are organized and why: the
  git-agnostic `@trinoris/securelib` core, `@trinoris/securegit` as a
  consumer of it, and the hardware-verified `@trinoris/securelib-piv`/
  `-fido2` provider packages.
- **[docs/securegit/02-faq.md](docs/securegit/02-faq.md)** — common
  questions answered in plain terms, e.g. what the master key is and why
  there's no "owner" role in the key model.
- **[docs/securegit/03-chaos-sandbox.md](docs/securegit/03-chaos-sandbox.md)**
  — what the chaos sandbox actually proves, in plain terms: the
  three-workflow x signing-tier comparison, what real runs found, and how
  to watch it live or run it yourself.
- **[docs/securegit/04-keys-usage.md](docs/securegit/04-keys-usage.md)**
  — every kind of "key" this project talks about, in plain terms: what
  each one is, where it lives, and what protects it.
- **[docs/securegit/05-cli-guide.md](docs/securegit/05-cli-guide.md)** —
  the commands you'll actually type, grouped by task, with working
  examples — setup, sharing access, rotation, recovery, and what each
  exit code means.

## Chaos sandbox

A Docker Compose stack simulates real collaborators, a hostile pusher, a
file-corrupting "virus", and infrastructure faults (kills, disk pressure,
network drops) running concurrently against a shared remote — across
three different git workflows (direct push, a gated shared branch, or a
fully PR-gated `master`), each independently with and without commit
signing enforced (six modes total) — then audits three hard invariants:
no plaintext ever leaked, the repository's object graph stayed intact,
and zero confirmed-pushed data was lost. **[docs/securegit/03-chaos-sandbox.md](docs/securegit/03-chaos-sandbox.md)** has the
full story, including what real runs actually found.

```sh
npm run chaos:sandbox
```

See [chaos/README.md](chaos/README.md) for prerequisites and exact
commands. A nightly run of all six modes is published as a GitHub Pages
site (`.github/workflows/build-ci.yml`'s `chaos` job) — the latest
comparison is viewable at `https://trinoris.github.io/secure/`.

## Development

```sh
npm ci
npm run build              # tsc -p tsconfig.build.json, in dependency order
npm test                   # unit tests (vitest)
npm run test:coverage      # unit tests + each package's branch-coverage gate
npm run test:integration   # against a real git binary
npm run typecheck
```

[build-ci.yml](.github/workflows/build-ci.yml) mirrors this repo's real
package dependency graph as a job DAG, rather than one job building and
testing all four packages in sequence: `audit` (`npm audit
--audit-level=high` against the whole workspace — independent, needs
nothing built) and `build-securelib` run first; once `securelib` is green,
`build-securelib-piv`, `build-securelib-fido2`, and `build-securegit` build
and test in parallel, each gated on its own package's vitest branch-coverage
threshold (`coverage.thresholds.branches` in that package's
`vitest.config.ts`) failing the job the moment real coverage drops below
it. CodeQL static analysis and secret scanning run alongside it
([codeql.yml](.github/workflows/codeql.yml),
[gitleaks.yml](.github/workflows/gitleaks.yml)), and the chaos sandbox
plus the coverage/audit badges above (`metrics-badges` job) publish
nightly (and on manual dispatch) to the same GitHub Pages site.

## Security

See [specs/securegit/01-threat-model.md](specs/securegit/01-threat-model.md)
for exactly what this protects against, and — just as important — what it
explicitly does not.

## License

[MIT](LICENSE)
