# `@trinoris/securelib-piv`

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Real PC/SC `PivCard` transport for
[`@trinoris/securelib`](https://github.com/trinoris/secure/tree/master/packages/securelib)'s
`yubikey-piv` `KeyProvider` — a YubiKey (or any PIV smartcard)'s own
key-management slot, reused for envelope encryption. See
[specs/securegit/06-key-provider-port.md](https://github.com/trinoris/secure/blob/master/specs/securegit/06-key-provider-port.md)
for the full design.

## Zero npm dependencies

This package shells out to already-installed system tools (`ykman`,
OpenSC's `pkcs11-tool`) rather than linking a native PC/SC addon — no
`node-pcsclite`, no compiled binary, nothing npm can supply-chain-attack.
The private key never leaves the card: `getPublicKey()` reads the slot's
public key (no PIN needed), and `ecdh()` asks OpenSC's PKCS#11
`ECDH1-DERIVE` mechanism to perform the ECDH operation on the card itself
— only the resulting shared secret ever comes back to this process.

**System prerequisites** (not npm dependencies — install via your OS
package manager):

- `ykman` (yubikey-manager)
- `pkcs11-tool` (opensc / opensc-pkcs11)
- `pcscd` running, with the reader visible to it

On Debian/Ubuntu: `apt install pcscd libpcsclite1 opensc yubikey-manager`.

## Usage

```ts
import { RealPivCard } from '@trinoris/securelib-piv';
import { YubikeyPivProvider } from '@trinoris/securelib/piv';

const card = new RealPivCard(); // optionally { pkcs11Module: '/path/to/opensc-pkcs11.so' }
const provider = new YubikeyPivProvider(card, '9d', () => pin);
```

## Verified against real hardware

Built and tested against a physical YubiKey 5C NFC (firmware 5.8.0), not
just fakes: the shared secret `ecdh()` produced via the card matched,
byte for byte, an independent `node:crypto` computation of the same ECDH
operation. `src/index.test.ts`'s hardware-gated suite (`describe.skipIf`,
opt-in via `SECUREGIT_PIV_TEST_PIN`) exercises a full
`YubikeyPivProvider` wrap()/unwrap() round trip through a real card —
never run automatically, since each invocation submits a real PIN to
real hardware with a limited retry counter.

## License

MIT — see [LICENSE](LICENSE).
