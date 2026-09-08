# 06. Key Provider Port

## Overview

The repository master key has to be protected by *something* the workstation
has and the cloud does not. That something differs per user and per machine —
passphrase today, a TPM on the desktop, a smartcard for the person who travels.
This is the interface that keeps that choice out of the crypto core.

**Status: the port, four `KeyProvider` implementations, the registry that
loads them, and the CLI surface to add or remove one — all built and
tested in software.** `src/provider.ts` (the `KeyProvider` interface),
`PassphraseFileProvider`, `KmsEnvelopeProvider` (`kms-envelope.ts`),
`YubikeyPivProvider` (`piv.ts`) and `YubikeyFido2Provider` (`fido2.ts`)
all pass the full conformance suite (`provider.conformance.test.ts`,
`describe.each` over all four). `registry.ts`'s `loadProvider()` resolves
`passphrase-file`/`kms-envelope` eagerly and `yubikey-piv`/`yubikey-fido2`
by dynamic `import()` — see "Loading a provider package without paying
for it" below. **`AwsKmsBackend` (`aws-kms-backend.ts`) is also built** — real
hand-rolled AWS SigV4 signing, `node:crypto` + `node:https`, no SDK —
but **not verified against a real AWS KMS endpoint**: this environment
has no AWS credentials, so it's tested structurally (deterministic,
sensitive to every input, matches AWS's documented `Authorization`
format) rather than byte-exact against an AWS-computed signature; a
real-credential integration test is written and ready
(`describe.skipIf`), waiting on real credentials to actually run.
**What's genuinely not built, drawn as an honest line, not a gap glossed
over:** `PivCard`/`Fido2Authenticator`'s real PC/SC and CTAP2/HID
implementations, and `GcpKmsBackend`/`AzureKmsBackend`. Every
`KeyProvider`'s own logic (key derivation, AEAD wrap/unwrap, AAD
binding, the `ctx.interactive` gate) is real and tested against a real
cryptographic fake (a genuine ECDH computation for PIV, a genuine HMAC
for FIDO2) — only the hardware call at the very bottom is faked for PIV/
FIDO2, exactly the boundary [00](00-test-plan.md)'s "Deliberately not
phased" note and each provider's own "Test plan" section below already
drew: a real-hardware integration test is separate, manual, and can
never run in CI regardless of credentials. [00](00-test-plan.md)'s note
no longer covers `key add-provider`/`remove-provider`/`list` themselves
(built), only the PIV/FIDO2 hardware transports and the two cloud
backends not yet built.

`key add-provider`/`remove-provider`/`list` ([10](10-cli-contract.md)) are
implemented as `addProvider()`/`removeProvider()` in `src/keyring.ts`.
With only `passphrase-file` as a real type, "add a provider" today
honestly means "add a second, independent passphrase" — `PassphraseFileProvider`'s
constructor gained an optional third `id` argument for exactly this (it
was `readonly id = 'passphrase-file'`, a class-level constant; two
instances sharing that id would silently shadow one during unlock, since
`unlockKeyring()` looks providers up by id). `addProvider()` refuses a
colliding id and refuses unless the caller's `KeySource` holds every
generation — a partial add would leave the new provider unlocking some
generations but not others. `removeProvider()` needs no unlock at all,
since it never re-wraps, only deletes — refused per-generation if doing so
would leave that generation with no provider able to unlock it, and
refused outright if the id was never present. `key list` (and its
`--json` form) needs no key either: generation numbers, fingerprints,
creation dates and provider ids are keyring metadata, not anything
requiring decryption.

Wiring `key add-provider` into a real command surfaced a genuine usage
collision, not just an implementation detail: it needs two different
things from the operator in one invocation — proof they're currently
authorized (today, an already-unlocked session), and the *new* passphrase
to wrap under — and both would naturally read from `SECUREGIT_PASSPHRASE`
if nothing distinguished them, since `loadKeys()` already treats that
variable as a filter-time unlock credential ([07](07-unlock-session.md)).
`cmdKeyAddProvider` in `src/cli.ts` resolves this the same way `key
import-recovery` already resolves its own two-secrets problem: authenticate
via whatever's already unlocked, `SECUREGIT_PASSPHRASE` deliberately left
unconsulted for this one call since it's spoken for, and take the new
passphrase from stdin instead.

`cmdUnlock` itself needed a small but real change to make any of this
usable: it used to construct exactly one `PassphraseFileProvider`, always
at the unlabeled default id, so a labeled backup provider's slot could
never be reached no matter what passphrase was entered. A new shared
`passphraseProvidersFor()` helper in `src/cli.ts` enumerates every
passphrase-file-shaped provider id actually present in the keyring and
tries the entered passphrase against all of them — the caller never says
in advance which id their passphrase belongs to, and only the one it
actually fits ever succeeds. `keySourceFromPassphraseEnv()`
([07](07-unlock-session.md)) and `rewrapOutdatedGenerations()` (below) now
share this same helper, so a second provider is honored consistently
everywhere a passphrase authenticates against the local keyring, not just
at `unlock`.

`src/provider.conformance.test.ts` is the contract suite this document
promises: `describe.each` over a `{ name, makeProvider }` registration list
(today, one row — `passphrase-file`), so every case below runs once per
registered provider rather than once for `PassphraseFileProvider`
specifically. Adding a second real provider means adding a row, not a new
test file. The "never receives a path or file content" row is proved
behaviourally, not just by the TypeScript types: a small recording wrapper
intercepts every argument actually passed to `init`/`wrap`/`unwrap` across a
full cycle and asserts none of it — recursively, skipping `Buffer`s, which
are the key material itself — carries a key matching `path`, `content` or
`plaintext`. `src/provider.test.ts` keeps everything specific to
`PassphraseFileProvider` (its scrypt parameters, its exact error strings);
the split mirrors `src/vectors.test.ts` vs. `src/envelope.test.ts` from
[03](03-determinism.md)/[04](04-envelope-format.md) — one file proves the
implementation, the other proves the contract every implementation shares.

## Core Principle

> A provider wraps and unwraps a 32-byte key. It never sees a plaintext file, a
> DEK, or a path. If a provider's implementation is wrong, the blast radius is
> the master key's confidentiality — not the correctness of every blob in the
> repository.

## Port

```typescript
export interface KeyProvider {
  /** Stable identifier recorded in the keyring: "passphrase-file", "tpm2", … */
  readonly id: string;

  /** Human-facing description for `securegit status`. Never includes secrets. */
  describe(): ProviderInfo;

  /** Is this provider usable on this machine right now? Must not prompt. */
  available(): Promise<boolean>;

  /** Called once when a repository or identity is created. */
  init(ctx: ProviderContext): Promise<ProviderState>;

  wrap(key: Buffer, ctx: ProviderContext): Promise<WrappedKey>;

  /** Throws UnlockRequired if the operator did not authorise. */
  unwrap(wrapped: WrappedKey, ctx: ProviderContext): Promise<Buffer>;
}

export interface ProviderContext {
  /** Bound into the AAD so a wrapped key cannot be moved between repos. */
  readonly repoId: string;
  readonly generation: number;
  /** Provider-specific state persisted in the keyring (salts, handles, slots). */
  readonly state: ProviderState;
  /** How the caller may reach the operator. `false` inside a Git filter. */
  readonly interactive: boolean;
}

export interface WrappedKey {
  provider: string;
  /** Opaque to everything above this port. */
  payload: Record<string, string>;
}

export interface ProviderInfo {
  id: string;
  label: string;
  /** Can the party operating this provider be compelled to produce the key? */
  custodial: boolean;
  requiresHardware: boolean;
}
```

`payload` being opaque is deliberate. A TPM stores a sealed blob and a PCR
policy; a smartcard stores a slot reference and an ephemeral public key; the
passphrase provider stores scrypt parameters, a salt and an AES-GCM ciphertext.
Nothing above the port may inspect those fields, so adding a provider changes no
existing code.

## Implementations

| Provider | `custodial` | Status | Notes |
|---|---|---|---|
| `passphrase-file` | no | **v1** | scrypt → KEK → AES-256-GCM. Works everywhere, including WSL and CI. |
| `os-keychain` | no | designed | DPAPI / macOS Keychain / libsecret. Better UX; no keychain under WSL, so it always needs a fallback. |
| `tpm2` | no | designed | Seals the RMK to PCRs. Machine-bound: a re-imaged laptop loses it, so it is never the only path. |
| `yubikey-piv` | no | **`YubikeyPivProvider` built, real PC/SC transport not** | `packages/securelib/src/piv.ts` — full conformance suite passes against a `FakePivCard` performing real P-256 ECDH (`piv.test.ts`, `provider.conformance.test.ts`). The `PivCard` port itself is the honest boundary: a real `@trinoris/securelib-piv` companion package implementing it against actual PC/SC hardware doesn't exist yet — see "Concrete designs" below. |
| `yubikey-fido2` | no | **`YubikeyFido2Provider` built, real CTAP2/HID transport not** | `packages/securelib/src/fido2.ts` — same shape, against a `FakeFido2Authenticator` (`fido2.test.ts`). See "Concrete designs" below. |
| `recovery-code` | no | built, but not a `KeyProvider` | Not interactive; used by `import-recovery` ([09](09-rotation-recovery.md)). As built, this is *not* a `KeyProvider` implementation behind this port — `src/recovery.ts` derives its wrap key directly from the code via HKDF and does its own AES-256-GCM wrap/unwrap, bypassing `provider.ts` entirely. The RMKs it recovers are then handed to an ordinary `PassphraseFileProvider` (via `keyringFromRecoveredGenerations`) to become the new local keyring's actual provider. The reason: this port's `init`/`wrap`/`unwrap` shape is built around one *persistent* secret per generation (a passphrase, a TPM binding); a recovery code instead needs to decrypt *every* generation at once under one code, which doesn't fit that per-generation shape without distortion. |
| `kms-envelope` | **yes** | **`KmsEnvelopeProvider` + `AwsKmsBackend` built; not verified against real AWS** | `packages/securelib/src/kms-envelope.ts` — full conformance suite passes against a `FakeKmsBackend`. `aws-kms-backend.ts`'s `AwsKmsBackend` implements real hand-rolled AWS SigV4 signing (`node:crypto` + `node:https`, no SDK) — structurally tested (deterministic, sensitive to every input), but **not verified against a real AWS KMS endpoint**: no AWS credentials exist in the environment this was built in. A real-credentials-gated integration test (`aws-kms-backend.test.ts`, `describe.skipIf`) is written and ready — run it against a real KMS key before relying on this in production. `GcpKmsBackend`/`AzureKmsBackend` aren't built. |

## `custodial` is the field that matters

[01](01-threat-model.md) sets the test: *if this party is compelled, can they
produce the key?* A provider that answers yes is `custodial: true`, and:

- it may never be the **only** unwrap path for a repository;
- `securegit status` prints it in the clear, as an escrow path, with the party
  named;
- `securegit verify` reports a repository whose every path is custodial as a
  finding, because that repository has re-created the property the tool exists
  to remove.

This is not an argument against KMS. An organisation that wants a break-glass
path administered by its cloud account is making a reasonable trade. It just has
to be a visible trade rather than an accident of configuration.

## The `passphrase-file` provider

```
   passphrase ──scrypt(N=2^16, r=8, p=1, salt=16B)──▶ 32-byte KEK
                                                       │
   RMK ──── AES-256-GCM(KEK, nonce=12B random) ────────▶ wrapped
                                                aad = "securegit/keywrap/v1"
                                                    ‖ repoId ‖ generation
```

- **Randomness is correct here.** The wrapped key lives in `~/.securegit`, never
  in a Git blob, so [03](03-determinism.md) does not apply. A fresh nonce per
  wrap is what we want.
- **`N = 2^16`** costs about 64 MiB and a few hundred milliseconds — tuned for a
  once-per-session unlock, not a per-file operation. Parameters are stored in
  the keyring so they can be raised later without breaking existing keyrings; a
  keyring wrapped at `2^16` is re-wrapped at the new cost on the next successful
  unlock. Implemented as `rewrapOutdatedGenerations()` in `src/keyring.ts`,
  called only from `cmdUnlock` in `src/cli.ts` — deliberately not folded into
  `unlockKeyring()` itself, which stays a pure read with no side effects,
  since that same function backs every filter-time unwrap too (including
  `SECUREGIT_PASSPHRASE`, [07](07-unlock-session.md)), and a filter must
  never write to disk. Best-effort: a re-wrap failure never fails the
  `unlock` that triggered it. Only `passphrase-file`'s own `state.N` is
  compared against the provider's current default; a slot from any other
  provider is left alone, since there's nothing generic about "raise the
  cost" to check across providers yet.
- **The AAD binds `repoId` and `generation`**, so a wrapped key copied into
  another repository's keyring — or wrapped again under a fresh salt for the
  same repository and generation — fails to unwrap under the wrong copy rather
  than silently decrypting into garbage. `unwrap` reports every failure mode
  (wrong passphrase, wrong `repoId`, wrong `generation`, malformed payload) as
  the same `ProviderError`, deliberately: distinguishing them in the message
  would tell an attacker which guess was closer.
- **Passphrase strength is the whole security of this provider** against an
  adversary holding the file (A4 in [01](01-threat-model.md)). `key init` refuses
  a passphrase under 12 characters and reports an estimate; it does not enforce
  composition rules, which produce worse passphrases.

## Concrete designs for the next three providers

**Design only — none of the three below are built.** Same status as
`tpm2`/`os-keychain` always had, just made concrete enough to build from
rather than left as a name in a table. All three fit the existing port
(`init`/`wrap`/`unwrap`/`describe`/`available`) with no change to it —
that's the port's whole reason for existing, and building one of these
should touch nothing outside its own file plus a row in `provider.conformance.test.ts`'s
registration list.

### `kms-envelope` — AWS KMS / GCP Cloud KMS / Azure Key Vault

**Never the sole root.** This is the one case the port's `custodial` field
exists for: [01](01-threat-model.md) already rules KMS out as a root, and
this provider is the "deliberate escrow path an organisation opts into"
that same section explicitly allows. Nothing new to enforce here — the
existing rules already cover it exactly:

- `describe().custodial` is `true`, so `addProvider()`'s existing "does
  every generation still have a non-custodial path" reasoning and the L10
  `verify` check (["What can go wrong quietly"](13-verify.md)) apply to it
  automatically, with no provider-specific code.
- `securegit status` names it in the clear as an escrow path — again, the
  existing custodial-provider behavior, not new behavior.

**One backend interface, three implementations.** `wrap`/`unwrap` never
call a cloud SDK directly — they call a small `KmsBackend` port of their
own, mirroring how `KeyProvider` itself sits behind `provider.ts`:

```typescript
interface KmsBackend {
  /** Resource id (ARN / key resource name / vault key id) is opaque here too. */
  // Deliberately typed as `rmkBytes`, not `plaintext` — this backend ever
  // sees exactly one thing: the 32-byte RMK itself, once per `wrap`/
  // `unwrap`. It never sees, and this interface can't be handed, any
  // actual protected file's content — that always stays local (see
  // "Never the sole root" above and 05-key-hierarchy.md's derivation
  // tree). This is the whole reason it's called an *envelope* provider.
  encrypt(rmkBytes: Buffer, keyId: string, context: Record<string, string>): Promise<Buffer>;
  decrypt(wrappedRmkBytes: Buffer, keyId: string, context: Record<string, string>): Promise<Buffer>;
}
```

`KmsEnvelopeProvider.wrap()` calls `backend.encrypt(rmk, keyId, { repoId,
generation: String(generation) })` and stores the returned ciphertext plus
`keyId` and a `backend` tag (`"aws"` / `"gcp"` / `"azure"`) in
`WrappedKey.payload`; `unwrap()` calls `backend.decrypt()` with the same
context. Every cloud KMS API accepts an authenticated-but-unencrypted
context string bound into the ciphertext (AWS calls it an "encryption
context", GCP and Azure both call it AAD) — used exactly like
`passphrase-file`'s own AAD above: a blob copied into another repository's
keyring, or presented under the wrong generation, fails to decrypt rather
than silently succeeding somewhere it shouldn't.

**Zero new runtime dependencies is achievable, not just aspirational —
worth actually doing, not a nice-to-have.** A cloud KMS `Encrypt`/`Decrypt`
call is one signed HTTPS request; none of the three clouds require their
SDK to make it:

- **AWS KMS**: SigV4 request signing is HMAC-SHA256 over a canonical
  request — directly buildable from `node:crypto` and `node:https`, no
  `aws-sdk`/`@aws-sdk/client-kms` needed. This is real, well-trodden
  ground (every from-scratch SigV4 implementation in any language follows
  the same published algorithm), not a novel crypto design.
- **GCP Cloud KMS** and **Azure Key Vault** authenticate via a signed JWT
  (a service-account key or Azure AD client-credentials flow) — RS256/
  HS256 JWT signing is also directly buildable from `node:crypto`. More
  request-shape code per backend than AWS (each cloud's REST API differs),
  but the same "no SDK dependency" property holds for all three.

Keeping this dependency-free matters here specifically because
`kms-envelope` — unlike the two hardware providers below — has no
inherent reason to need a native dependency at all (it's just an
authenticated HTTPS call), so there's no honest excuse to pull in a full
cloud SDK and its own dependency tree into a package whose whole pitch is
holding encryption keys with as little else to compromise as possible.
This can ship inside the core package, unlike the two below.

**Interactivity:** a network call, not a hardware prompt — `wrap`/`unwrap`
need network access but nothing from `ctx.interactive`, and happen once
per `unlock` (cached in the session, [07](07-unlock-session.md)), never
once per file.

**Status: built.** `KmsEnvelopeProvider` (`kms-envelope.ts`) and the
`KmsBackend` port are real; `registry.ts` loads it eagerly (`BUILTIN`,
not a companion package — see "Loading a provider package" below). Test
plan realised as designed: `FakeKmsBackend` (in-memory `Map<token,
plaintext>`, context checked exactly like a real backend would enforce
it) runs `KmsEnvelopeProvider` through the *entire*
`provider.conformance.test.ts` suite (`describe.each`'s fourth row) with
zero real network calls, plus `kms-envelope.test.ts`'s own tests —
including one real bug this caught before it shipped: `unwrap()`
originally trusted the wrapped payload's own `keyId` field instead of
checking it against the caller's configured key, so a ciphertext the
backend still held could be unwrapped by a *different* `KmsEnvelopeProvider`
instance than the one that wrapped it, as long as `repoId`/`generation`
still matched — fixed by checking `keyId` against `ctx.state`, the same
"fails rather than silently succeeding somewhere it shouldn't" property
every other binding here already had. **`AwsKmsBackend` is built**
(`aws-kms-backend.ts`) — hand-rolled SigV4 signing per AWS's own
published algorithm, `node:crypto` + `node:https`, no SDK dependency,
exactly as designed above. **Honest limit: not verified against a real
AWS KMS endpoint** — no AWS credentials exist in the environment this
was built in, so correctness rests on following the documented algorithm
precisely plus structural tests (deterministic; sensitive to the body,
secret key, and timestamp; well-formed `Authorization` header), not a
byte-exact match against an AWS-computed signature. The real-credential
integration test the design called for (`aws-kms-backend.test.ts`,
`describe.skipIf`, skipped unless `AWS_ACCESS_KEY_ID`/
`AWS_SECRET_ACCESS_KEY`/`AWS_KMS_TEST_KEY_ID` are present, never
committed) is written and ready to run — run it against a real KMS key
before relying on this in production. `GcpKmsBackend`/`AzureKmsBackend`
aren't built.

### `yubikey-piv` — YubiKey / any PIV smartcard

**Reuses the card's own PIV key-management slot**, the same approach
[age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey) and
similar tools already use: a PIV card's "key management" slot (9d, by
PIV convention) holds a NIST P-256 (or P-384) keypair whose private half
never leaves the card. Shape mirrors an X25519 recipient
([08](08-multi-recipient.md)) almost exactly, just over the curve real
off-the-shelf PIV hardware speaks instead of X25519:

```
init:   read the card's existing slot-9d public key (or generate one on
        the card, if PIV's own key-generation is preferred over import)
wrap:   ephemeral P-256 keypair ──ECDH(ephemeral.priv, card.pub)──▶ shared secret
                                  ──HKDF──▶ 32-byte KEK
        RMK ──AES-256-GCM(KEK)──▶ wrapped
        payload = { ephemeralPublicKey, wrapped, aad = repoId ‖ generation }
unwrap: send { ephemeralPublicKey } to the card's PIV applet, ask it to
        perform ECDH(card.priv-on-card, ephemeralPublicKey) — the private
        operation happens ON the card, the result (shared secret) is all
        that comes back — then HKDF ──▶ KEK ──▶ AES-256-GCM decrypt
```

`describe()`: `custodial: false` (the private key never leaves the
hardware — nobody can be compelled to produce it, only to use it once,
with the card physically present), `requiresHardware: true`.

**Interactivity is not optional, and the port already has the field for
it.** A PIV card's private-key operation requires the PIN every time (and,
depending on the slot's touch policy, a physical touch) — there is no
non-interactive path, ever. `unwrap` must check `ctx.interactive` first
and throw a specific, actionable error when it's `false` — "PIV requires
`securegit unlock` first; a Git filter cannot prompt for a PIN" — exactly
matching how `interactive: false` inside a filter is already a first-class
case this port's design anticipates ([07](07-unlock-session.md)).

**The one honest new cost: this needs a real dependency, and that's not
avoidable.** Talking to a smartcard means PC/SC (`libpcsclite` on Linux,
built into Windows and macOS) — Node has no built-in path to it. Two real
options, both genuinely "a new dependency", not zero-cost:
- a native addon (`node-pcsclite` or similar, compiled per-platform), or
- shelling out to an already-installed external tool (`ykman piv`,
  OpenSC's `pkcs11-tool`) and parsing its output.

**Recommendation: ship this as a separate, optional companion package —
`@trinoris/securelib-piv`, not `securegit-piv`.** Named under the shared
library, not this consumer, because nothing about a `KeyProvider` that
wraps and unwraps a 32-byte key is Git-specific — it's exactly as usable
by a future non-Git consumer of the same port as it is by `securegit`.
See [../../ARCHITECTURE.md](../../ARCHITECTURE.md) for the full reasoning
and the `@trinoris/securelib` extraction this naming anticipates. Either
way — inside `securegit` today or `securelib` once it exists — the point
holds: the core package's "zero runtime dependencies" claim
([README.md](../../README.md)) is a stated security property, not an
incidental fact, and a hardware provider that genuinely needs native/
external access shouldn't cost every user who never touches hardware
providers a new dependency in their own supply chain. See "Loading a
provider package without paying for it" below for how a provider id
resolves to its companion package without either core package ever
depending on it.

**Status: built.** `YubikeyPivProvider` (`piv.ts`) and the `PivCard` port
are real. Test plan realised as designed: `getPublicKey(slot):
Promise<Buffer>`, `ecdh(slot, peerPublicKey, pin): Promise<Buffer>` is
the injection seam; `FakePivCard` (`piv.test.ts`,
`provider.conformance.test.ts`) performs a genuine P-256 ECDH computation
via `node:crypto`'s `createECDH` — only "is a physical card present" is
faked, not the cryptography itself. Passes the full conformance suite
(`describe.each`'s third row) plus `piv.test.ts`'s own tests: the
`ctx.interactive` gate throws before ever touching the card, and
`wrap()` never calls `ecdh()` at all (proven by a call-counting wrapper
around the fake), matching "wrap() only ever touches the card's public
key" above. **Not built:** a real `@trinoris/securelib-piv` companion
package implementing `PivCard` against actual PC/SC hardware. A
real-hardware integration test is separate, manual, and can never run in
CI without a physical key attached — an honest limit, not a gap to
silently paper over, the same way this project already treats "code
execution on an unlocked workstation" as a named boundary rather than a
solved problem ([01](01-threat-model.md)).

### `yubikey-fido2` — any FIDO2 authenticator, via `hmac-secret`

**A different mechanism from PIV, for hardware that only speaks FIDO2**
(no PIV applet) or where CTAP2 is preferred over smartcard middleware.
Uses the `hmac-secret` CTAP2 extension — designed for exactly this
"derive a stable secret from a physical key" use, distinct from FIDO2's
usual authentication role:

```
init:   MakeCredential(hmac-secret extension requested)
          ──▶ credentialId (store in ProviderState; a fresh random
              32-byte salt, also stored — public, not secret, since the
              hmac-secret result depends on the physical authenticator
              too)
wrap:   GetAssertion(credentialId, salt, hmac-secret extension)
          ──▶ stable 32-byte secret, only reproducible by the same
              physical key presented with the same salt
        secret ──▶ KEK; RMK ──AES-256-GCM(KEK)──▶ wrapped
unwrap: GetAssertion(credentialId, salt, hmac-secret) ──▶ same secret ──▶ KEK ──▶ decrypt
```

`describe()`: `custodial: false`, `requiresHardware: true`. Same
`ctx.interactive` gate as PIV — `GetAssertion` requires user presence (a
touch) essentially always, no non-interactive path.

**Same real-dependency situation as PIV, for a different reason:** Node
has no built-in USB HID or CTAP2/WebAuthn client support, so this needs a
CTAP2 client library capable of talking to the raw device — not a browser
WebAuthn call (there's no browser here). Same recommendation, same name
pattern, as PIV: an optional companion package,
**`@trinoris/securelib-fido2`**, not `securegit-fido2` — see
[../../ARCHITECTURE.md](../../ARCHITECTURE.md).

**Status: built.** `YubikeyFido2Provider` (`fido2.ts`) and the
`Fido2Authenticator` port are real. Test plan realised as designed:
`makeCredential(extensions): Promise<{credentialId}>`,
`getAssertion(credentialId, salt): Promise<Buffer>` is the injection
seam; `FakeFido2Authenticator` (`fido2.test.ts`,
`provider.conformance.test.ts`) derives its assertion via a genuine HMAC
over a per-instance secret, standing in for the real hmac-secret
extension's own HMAC(credRandom, salt) — different instances (different
physical keys) never produce the same secret for the same credential/
salt, proven directly. Passes the full conformance suite
(`describe.each`'s fourth row) plus `fido2.test.ts`'s own tests: the
`ctx.interactive` gate throws before ever touching the authenticator.
**Not built:** a real `@trinoris/securelib-fido2` companion package
implementing `Fido2Authenticator` against actual CTAP2/HID hardware;
real-hardware coverage is separate, manual, same honest CI limit as PIV.

## Multiple providers per repository

The keyring stores a list of wrapped copies of each generation, one per
provider. Unlock tries providers in order of `available()`, preferring
non-interactive ones.

```json
{
  "generation": 3,
  "fingerprint": "a1b2c3d4e5f60718",
  "createdAt": "2026-09-01T10:04:11.000Z",
  "wrapped": [
    { "provider": "passphrase-file", "state": { "…": "…" }, "payload": { "…": "…" } },
    { "provider": "piv",             "state": { "…": "…" }, "payload": { "…": "…" } }
  ]
}
```

Each slot carries **`state`** alongside `payload`: a provider's `wrap`/`unwrap`
need whatever `init` produced for that generation (the scrypt salt and cost,
for `passphrase-file`) even though `payload` alone is what is secret. Splitting
them keeps `payload` — the only field an audit of "what is encrypted" needs to
reason about — free of parameters that are public by nature.

`unlockKeyring` (`src/keyring.ts`) tries every slot of every generation against
whatever providers the caller has, in the order the generations were created,
and keeps whichever succeed:

```typescript
for (const gen of file.generations) {
  for (const slot of gen.wrapped) {
    const provider = byId.get(slot.provider);
    if (!provider) continue;
    try {
      const rmk = await provider.unwrap(slot, { …, state: slot.state });
      // fingerprint check, then held.set(keyId, rmk); break
    } catch { continue; } // try the next slot, or the next generation
  }
}
```

A provider that fails on one slot — wrong passphrase, wrong machine — does not
stop the loop. This is what makes "unlock via provider A if it works, else
provider B" and "unlock only the generations a late-joining recipient can
reach" ([08](08-multi-recipient.md)) the same code path rather than two.

Adding a provider requires an unlock through an existing one — `keyring.ts` has
no special case for it: an added provider is just another `wrap()` call,
appended to `wrapped` — for *every* generation the unlocking `KeySource`
holds, not only the current one, mirroring `key add-recipient`'s own
`wrapAllGenerations()`; a provider that could only decrypt the newest
generation would be a strange kind of backup. Removing the last provider
that can unlock a given generation is refused, per generation — implemented
as "removing it would leave that generation with no provider at all", which
in v1, with zero custodial providers built, is the same check "the last
non-custodial provider" describes; the distinction becomes real only once
one exists. Recipients ([08](08-multi-recipient.md)) are a *different*
mechanism — they wrap for other people, and live in the repository rather
than the keyring — but they follow the same rule: a repository must always
have at least one non-custodial way back in.

## Loading a provider package without paying for it

The packaging question `yubikey-piv` and `yubikey-fido2` both raise above
(an optional companion package, not a dependency of the core) but leave
open. Settled here, now that
[ARCHITECTURE.md](../../ARCHITECTURE.md)'s Phase 1 has actually happened:
`@trinoris/securelib` lives at `packages/securelib` inside this same
repository's own npm workspace (`packages/*`), not a separate one. That
simplifies the packaging question this section originally deferred —
the companion packages need no workspace of their own; they're siblings
of `packages/securelib` and `packages/securegit` under the same glob:

```
packages/
  securelib/           @trinoris/securelib        — core, zero deps: passphrase-file AND kms-envelope live here
  securegit/            @trinoris/securegit         — CLI, depends on securelib
  securelib-piv/        @trinoris/securelib-piv     — yubikey-piv, real PC/SC dependency
  securelib-fido2/      @trinoris/securelib-fido2   — yubikey-fido2, real CTAP2/HID dependency
```

Only two companion packages, not three. `kms-envelope`'s own design
above ("Zero new runtime dependencies is achievable, not just
aspirational") already settles that it ships inside `securelib` core —
hand-rolled SigV4/JWT request signing needs nothing PC/SC or CTAP2/HID
don't already rule out avoiding. There's no honest reason to push it
behind a dynamic import when it costs the core nothing to include
directly, the same way `passphrase-file` is. This corrects
[ARCHITECTURE.md](../../ARCHITECTURE.md)'s softer "worth deciding at
implementation time" hedge on this point — the more detailed design
above already decided it.

Each PIV/FIDO2 package is an ordinary workspace package with its own
`package.json`, depending on `@trinoris/securelib` (for the
`KeyProvider` type and crypto primitives) the same way `securegit`
already does. Neither is a dependency of `securelib` or `securegit` —
that's the entire point: a user who never touches a YubiKey never
installs PC/SC bindings, never mind whether they run `securegit` or
some future non-Git `securelib` consumer.

**The naming convention is the registry — no separate mapping to keep in
sync.** A provider `id` (the same string already stored in the
keyring's `wrapped[].provider` field, [05](05-key-hierarchy.md)) maps to
its package by prefixing `@trinoris/securelib-`, stripped of its own
`yubikey-` prefix (otherwise redundant under that scope):

| provider `id` | companion package |
|---|---|
| `yubikey-piv` | `@trinoris/securelib-piv` |
| `yubikey-fido2` | `@trinoris/securelib-fido2` |

`passphrase-file` and `kms-envelope` need no entry — both are built into
`securelib` itself, loaded eagerly, never through this path.

```typescript
// packages/securelib/src/registry.ts — built as shown, not just sketched
const BUILTIN: Record<string, (config: unknown) => KeyProvider> = {
  'passphrase-file': (config) => new PassphraseFileProvider(config as () => Promise<string> | string),
  'kms-envelope': (config) => {
    const { backend, backendTag, keyId } = config as KmsEnvelopeConfig;
    return new KmsEnvelopeProvider(backend, backendTag, keyId);
  },
};

const COMPANION_PACKAGE: Record<string, string> = {
  'yubikey-piv': '@trinoris/securelib-piv',
  'yubikey-fido2': '@trinoris/securelib-fido2',
};

export async function loadProvider(id: string, config: unknown): Promise<KeyProvider> {
  const builtin = BUILTIN[id];
  if (builtin) return builtin(config);

  const pkg = COMPANION_PACKAGE[id];
  if (!pkg) throw new ProviderError(`securegit: unknown provider id '${id}'`);

  let mod: { createProvider(config: unknown): KeyProvider };
  try {
    mod = await import(pkg);
  } catch (e) {
    throw new ProviderError(
      `securegit: provider '${id}' needs ${pkg}, which is not installed\n` +
        `  action: npm install ${pkg}`,
    );
  }
  return mod.createProvider(config);
}
```

`import(pkg)` — a dynamic import of a package specifier, not a relative
path — is what keeps this lazy: `securegit`'s own `package.json` never
lists `@trinoris/securelib-piv` as a dependency, so it's simply not on
disk unless a user installs it themselves, and the `import()` call is
never reached unless a repository's keyring actually names that
provider id. `securelib`'s own "zero runtime dependencies" claim
survives intact — this registry ships inside `securelib`, but every
`import()` target is optional, resolved only from the *consumer's* own
`node_modules`, never `securelib`'s.

Each companion package exports one function, `createProvider(config):
KeyProvider`, matching the shape `loadProvider` expects — the same
contract every `KeyProvider` implementation already satisfies
(`provider.conformance.test.ts`), just behind one more layer of
indirection so the core never has a static `import` naming a package it
doesn't depend on.

**Status: `registry.ts` and `loadProvider()` are built and tested** —
`packages/securelib/src/registry.ts`, `@trinoris/securelib/registry`.
Both `passphrase-file` and `kms-envelope` resolve from `BUILTIN` for
real. The two companion
packages (`@trinoris/securelib-piv`, `@trinoris/securelib-fido2`)
themselves don't exist yet — `loadProvider()` already gives an honest,
actionable error for both (`npm install @trinoris/securelib-piv`, etc.),
verified by `registry.test.ts` against the real absence of those
packages on disk, not a mock.

## Test Cases

| Test | Test File | Fixture | Status |
|------|-----------|---------|--------|
| Conformance suite passes for every provider | `src/provider.conformance.test.ts` | — | ✅ |
| `wrap` then `unwrap` returns the identical key | `src/provider.conformance.test.ts` | — | ✅ |
| `unwrap` with the wrong `repoId` fails | `src/provider.conformance.test.ts` | — | ✅ |
| `unwrap` with the wrong `generation` fails | `src/provider.conformance.test.ts` | — | ✅ |
| Two `wrap` calls on one key produce different payloads | `src/provider.test.ts` | — | ✅ |
| Wrong passphrase fails with a distinguishable error, not a crash | `src/provider.test.ts` | — | ✅ |
| scrypt parameters round-trip through the keyring | `src/keyring.test.ts` | — | ✅ |
| Raised scrypt parameters re-wrap on next unlock | `src/keyring.test.ts` | — | ✅ |
| `available()` never prompts | `src/provider.conformance.test.ts` | — | ✅ |
| Passphrase under 12 characters is refused at `init` | `src/provider.test.ts` | — | ✅ |
| `addProvider()` wraps every generation for the new provider, independently unlockable | `src/keyring.test.ts` | — | ✅ |
| `addProvider()` wraps every held generation, not just the current one | `src/keyring.test.ts` | — | ✅ |
| `addProvider()` refuses a colliding provider id | `src/keyring.test.ts` | — | ✅ |
| `addProvider()` refuses when the session does not hold every generation | `src/keyring.test.ts` | — | ✅ |
| `removeProvider()` deletes the named slot from every generation | `src/keyring.test.ts` | — | ✅ |
| Removing the last non-custodial provider is refused | `src/keyring.test.ts` | — | ✅ (`removeProvider()`'s "would leave a generation with no provider at all" check — in v1, with zero custodial providers, the same thing) |
| `removeProvider()` does not refuse when another provider remains | `src/keyring.test.ts` | — | ✅ |
| `removeProvider()` throws when the id was never present | `src/keyring.test.ts` | — | ✅ |
| `key unlock` tries every passphrase-file-shaped provider id present, not only the unlabeled default | `src/cli.test.ts` | — | ✅ |
| A custodial-only repository is a `verify` finding | `src/verify.test.ts` | — | ✅ |
| Provider never receives a path or file content | `src/provider.conformance.test.ts` | — | ✅ |
| `KmsEnvelopeProvider` passes the full conformance suite against a `FakeKmsBackend` | `src/provider.conformance.test.ts` | — | ✅ |
| `KmsEnvelopeProvider.wrap`/`unwrap` bind `repoId`/`generation` into the backend's own AAD/encryption-context field | `src/kms-envelope.test.ts` | — | ✅ (via `unwrap()` fails when the wrapped ciphertext was encrypted under a different `repoId`/`generation`, enforced by the fake's own context check) |
| `KmsEnvelopeProvider.unwrap` rejects a wrapped payload whose `keyId` doesn't match the caller's own configured key | `src/kms-envelope.test.ts` | — | ✅ — caught a real bug: `unwrap()` originally trusted the payload's own `keyId` instead of checking it, see "Concrete designs" above |
| `AwsKmsBackend`'s `Authorization` header matches AWS's documented SigV4 format; deterministic; sensitive to body/secret-key/timestamp | `src/aws-kms-backend.test.ts` | — | ✅ (structural — not verified against a real AWS-computed signature, see "Concrete designs" above) |
| `AwsKmsBackend.encrypt`/`decrypt` send the correct JSON action/body and decode the response | `src/aws-kms-backend.test.ts` | — | ✅ |
| `AwsKmsBackend` wraps and unwraps a real key via a real AWS KMS key | `src/aws-kms-backend.test.ts` | — | written, `describe.skipIf` — skipped: no real AWS credentials in this environment |
| A repository with only `kms-envelope` wrapping the current generation is a `verify` finding (existing custodial-only check, no new logic) | `src/verify.test.ts` | — | not built — `verify.ts` hasn't been extended to exercise a real `KmsEnvelopeProvider` yet, though the underlying custodial-only check it would reuse is already built and tested against `providers: KeyProvider[]` generically |
| `YubikeyPivProvider` passes the full conformance suite against a `FakePivCard` | `src/provider.conformance.test.ts` | — | ✅ |
| `YubikeyPivProvider.unwrap` throws a specific, actionable error when `ctx.interactive` is `false` | `src/piv.test.ts` | — | ✅ |
| `YubikeyPivProvider.wrap` never calls `PivCard.ecdh()` — only reads the card's public key | `src/piv.test.ts` | — | ✅ |
| `YubikeyFido2Provider` passes the full conformance suite against a `FakeFido2Authenticator` | `src/provider.conformance.test.ts` | — | ✅ |
| `YubikeyFido2Provider.unwrap` throws a specific, actionable error when `ctx.interactive` is `false` | `src/fido2.test.ts` | — | ✅ |
| `loadProvider('passphrase-file', ...)` resolves to a real, working provider — no dynamic `import()` needed | `src/registry.test.ts` | — | ✅ |
| `loadProvider('yubikey-piv'/'yubikey-fido2', ...)` with the companion package absent throws a `npm install @trinoris/securelib-*` error, not a raw module-resolution error | `src/registry.test.ts` | — | ✅ |
| `loadProvider()` with an unknown id rejects with `ProviderError`, distinctly from a missing companion package | `src/registry.test.ts` | — | ✅ |
| Neither `securelib` nor `securegit` lists a companion package as a dependency (T11, `package.test.ts`'s existing exact-dependency-list check already enforces this — no dedicated test needed) | `src/package.test.ts` | — | ✅ |
| `loadProvider('kms-envelope', ...)` resolves via `registry.ts`'s `BUILTIN` map, not a dynamic `import()` | `src/registry.test.ts` | — | ✅ |

## Relationship to Other Specs

- [01](01-threat-model.md) — the compulsion test behind `custodial`
- [05](05-key-hierarchy.md) — what is being wrapped
- [07](07-unlock-session.md) — `interactive: false` inside a filter
- [08](08-multi-recipient.md) — the other way a key is wrapped
- [09](09-rotation-recovery.md) — the `recovery-code` provider
