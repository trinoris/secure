# `@trinoris/securelib`

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Transport-agnostic envelope encryption core: the envelope format, key
hierarchy, pluggable `KeyProvider` port, multi-recipient sharing, and
offline recovery that power [`@trinoris/securegit`](https://github.com/trinoris/secure/tree/master/packages/securegit).
Extracted so the same primitives can back other clients that need the
same guarantees but aren't Git — see
[docs/securegit/01-architecture.md](https://github.com/trinoris/secure/blob/master/docs/securegit/01-architecture.md).

Depends on nothing but `node:crypto` and `node:fs` — zero runtime
dependencies is a stated security property, not an accident (see the
parent repository's README).

## What's in here

- `seal()` / `unseal()` — AES-256-GCM envelope encryption ([04-envelope-format.md](https://github.com/trinoris/secure/blob/master/specs/securegit/04-envelope-format.md))
- `KeyProvider` port + `PassphraseFileProvider` — pluggable key material sources ([06-key-provider-port.md](https://github.com/trinoris/secure/blob/master/specs/securegit/06-key-provider-port.md))
- Key hierarchy and HKDF derivation ([05-key-hierarchy.md](https://github.com/trinoris/secure/blob/master/specs/securegit/05-key-hierarchy.md))
- Multi-recipient sharing, rotation, and offline recovery-code primitives
- Identity keypairs, session caching, and the repository's own public
  config (`.securegit/config.json`)

This package has no opinion on what its caller is — no Git awareness, no
CLI. `@trinoris/securegit`'s `cli.ts` supplies its own "is this a valid
place to initialise" check (a `.git` directory) at its own call site,
rather than this module assuming one.

## Usage

Each module is its own subpath export:

```ts
import { seal, unseal } from '@trinoris/securelib/envelope';
import { PassphraseFileProvider } from '@trinoris/securelib/provider';
import { initConfig, readConfig } from '@trinoris/securelib/config';
```

See [`@trinoris/securegit`](https://github.com/trinoris/secure/tree/master/packages/securegit)
for a real consumer, and `specs/securegit/` in the parent repository for
the full design rationale behind every primitive here.

## License

MIT — see [LICENSE](LICENSE).
