# `@trinoris/securelib-fido2`

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Real CTAP2/HID `Fido2Authenticator` transport for
[`@trinoris/securelib`](https://github.com/trinoris/secure/tree/master/packages/securelib)'s
`yubikey-fido2` `KeyProvider` — any FIDO2 authenticator's `hmac-secret`
extension, reused for envelope encryption. See
[specs/securegit/06-key-provider-port.md](https://github.com/trinoris/secure/blob/master/specs/securegit/06-key-provider-port.md)
for the full design.

## Zero npm dependencies

Shells out to already-installed system tools (libfido2's `fido2-token`,
`fido2-cred`, `fido2-assert`) rather than linking a native CTAP2/HID
addon — no compiled binary, nothing npm can supply-chain-attack. The
`hmac-secret` extension's whole point is that the derived secret is only
reproducible by the same physical key presented with the same salt —
this package's only job is asking for it correctly.

**System prerequisites** (not npm dependencies — install via your OS
package manager):

- `fido2-token`, `fido2-cred`, `fido2-assert` (Debian/Ubuntu: `fido2-tools`)
- Read/write access to the authenticator's `/dev/hidrawN` device — on a
  typical desktop Linux install this is usually already granted via a
  udev rule (`libfido2-1`'s package, or `70-u2f.rules`); on some setups
  (e.g. a bridged WSL2 environment) it needs granting manually
  (`chmod 666 /dev/hidrawN`, or a proper udev rule for persistence).

On Debian/Ubuntu: `apt install fido2-tools`.

## Usage

```ts
import { RealFido2Authenticator } from '@trinoris/securelib-fido2';
import { YubikeyFido2Provider } from '@trinoris/securelib/fido2';

const authenticator = new RealFido2Authenticator(); // optionally { device: '/dev/hidraw1' }
const provider = new YubikeyFido2Provider(authenticator);
```

Or via `@trinoris/securelib`'s registry, resolved lazily:

```ts
import { loadProvider } from '@trinoris/securelib/registry';

const provider = await loadProvider('yubikey-fido2', { device: '/dev/hidraw1' }); // device optional, auto-discovered
```

Device discovery, when not given explicitly, uses the first result of
`fido2-token -L` — fine for the common case of one authenticator
plugged in.

## Testing without hardware

`RealFido2Authenticator`'s subprocess boundary is injected
(`RealFido2AuthenticatorOptions.runner`), same reasoning as
`@trinoris/securelib-piv`'s `RealPivCard.runner`. `src/index.fake.test.ts`
covers device discovery, argv construction, output parsing, and error
wrapping against a fake `fido2-token`/`fido2-cred`/`fido2-assert`, with
no physical key or touch needed. There's no cryptographic property to
verify in a fake here, unlike PIV's ECDH fake — the `hmac-secret` output
is opaque bytes from the authenticator, so a fake success case only
proves the parsing is right, not the derivation.

## Verified against real hardware

Manually verified against a physical YubiKey 5C NFC (firmware 5.8.0)
during development, one CLI command at a time (each needs a real touch,
so it can't be scripted end-to-end unattended the way `securelib-piv`'s
ECDH check could be): `MakeCredential` with `hmac-secret` requested, no
PIN needed; `GetAssertion` with the same credential and salt, called
twice with two *different* challenges, produced the byte-identical
`hmac-secret` both times — proving the secret depends only on
`(credential, salt)`, never the per-call challenge; a third call with a
*different* salt produced a different secret. `src/index.test.ts`'s
hardware-gated suite (`describe.skipIf`, opt-in via
`SECUREGIT_FIDO2_HARDWARE_TEST=1`) then exercises the same real hardware
through the actual `YubikeyFido2Provider`/`RealFido2Authenticator` code
path — never run automatically, and only runnable interactively (via
`!` in a real terminal), since every invocation needs a genuine physical
touch a non-interactive tool call can't react to in time.

## License

MIT — see [LICENSE](LICENSE).
