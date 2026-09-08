// yubikey-fido2: a different mechanism from PIV, for hardware that only
// speaks FIDO2 (no PIV applet), via the `hmac-secret` CTAP2 extension —
// designed for exactly this "derive a stable secret from a physical key"
// use, distinct from FIDO2's usual authentication role. Unlike PIV, there
// is no public-key precomputation: both wrap() and unwrap() need the
// physical authenticator present, since GetAssertion is the only operation
// that ever produces the secret. See
// specs/securegit/06-key-provider-port.md's "yubikey-fido2" design.
//
// The real CTAP2/HID transport is not built here, same honest boundary as
// piv.ts: `Fido2Authenticator` is the seam a real
// `@trinoris/securelib-fido2` companion package would implement against
// real hardware.

import { randomBytes } from 'node:crypto';
import {
  ProviderError,
  type KeyProvider,
  type ProviderContext,
  type ProviderInfo,
  type ProviderState,
  type WrappedKey,
} from './provider.js';
import { aeadEncrypt, aeadDecrypt, secret, type Secret } from './crypto.js';

export interface Fido2Authenticator {
  /** Requests the hmac-secret extension on this credential. */
  makeCredential(extensions: { hmacSecret: true }): Promise<{ credentialId: Buffer }>;
  /** Returns the stable 32-byte secret — only reproducible by the same physical key, presented with the same salt. */
  getAssertion(credentialId: Buffer, salt: Buffer): Promise<Buffer>;
}

const AAD_LABEL = Buffer.from('securegit/fido2-wrap/v1', 'utf8');
const SEP = Buffer.from([0x00]);
const SALT_LEN = 32;

export class YubikeyFido2Provider implements KeyProvider {
  readonly id: string;

  constructor(
    private readonly authenticator: Fido2Authenticator,
    id = 'yubikey-fido2',
  ) {
    this.id = id;
  }

  describe(): ProviderInfo {
    return {
      id: this.id,
      label: 'FIDO2 authenticator (hmac-secret)',
      custodial: false,
      requiresHardware: true,
    };
  }

  async available(): Promise<boolean> {
    // No non-interactive way to probe a FIDO2 authenticator's presence
    // without a real GetAssertion (which needs a touch) — unlike PIV's
    // getPublicKey, there is no cheap, promptless read. Real availability
    // surfaces at wrap()/unwrap() time instead, same honest limit the
    // design note above draws for interactivity generally.
    return true;
  }

  async init(ctx: { repoId: string; generation: number }): Promise<ProviderState> {
    void ctx;
    const { credentialId } = await this.authenticator.makeCredential({ hmacSecret: true });
    const salt = randomBytes(SALT_LEN);
    return { credentialId: credentialId.toString('hex'), salt: salt.toString('hex') };
  }

  async wrap(key: Buffer, ctx: ProviderContext): Promise<WrappedKey> {
    const { credentialId, salt } = requireState(ctx.state);
    const kek = await this.authenticator.getAssertion(Buffer.from(credentialId, 'hex'), Buffer.from(salt, 'hex'));
    const nonce = randomBytes(12);
    const aad = buildAad(ctx.repoId, ctx.generation);
    const { ciphertext, authTag } = aeadEncrypt(kek, nonce, key, aad);
    return {
      provider: this.id,
      payload: {
        credentialId,
        salt,
        nonce: nonce.toString('hex'),
        ciphertext: ciphertext.toString('hex'),
        authTag: authTag.toString('hex'),
      },
    };
  }

  async unwrap(wrapped: WrappedKey, ctx: ProviderContext): Promise<Secret> {
    // Same reasoning as PIV: GetAssertion requires user presence (a touch)
    // essentially always — no non-interactive path, ever. Checked before
    // touching the payload or the authenticator.
    if (!ctx.interactive) {
      throw new ProviderError(
        'securegit: yubikey-fido2 requires `securegit unlock` first; a Git filter cannot prompt for touch',
      );
    }
    const { credentialId, salt, nonce, ciphertext, authTag } = wrapped.payload;
    if (
      credentialId === undefined ||
      salt === undefined ||
      nonce === undefined ||
      ciphertext === undefined ||
      authTag === undefined
    ) {
      throw new ProviderError('wrapped key is missing a required field');
    }
    try {
      const kek = await this.authenticator.getAssertion(Buffer.from(credentialId, 'hex'), Buffer.from(salt, 'hex'));
      const aad = buildAad(ctx.repoId, ctx.generation);
      const key = aeadDecrypt(
        kek,
        Buffer.from(nonce, 'hex'),
        Buffer.from(ciphertext, 'hex'),
        Buffer.from(authTag, 'hex'),
        aad,
      );
      return secret(key);
    } catch (e) {
      if (e instanceof ProviderError) throw e;
      // Deliberately opaque, same reasoning as every other provider's
      // unwrap(): never reveal whether the wrong physical key was
      // presented or the repo/generation binding was the part that failed.
      throw new ProviderError('could not unwrap: wrong authenticator, or key belongs elsewhere');
    }
  }
}

function buildAad(repoId: string, generation: number): Buffer {
  const genBuf = Buffer.alloc(4);
  genBuf.writeUInt32BE(generation >>> 0);
  return Buffer.concat([AAD_LABEL, SEP, Buffer.from(repoId, 'utf8'), SEP, genBuf]);
}

function requireState(state: ProviderState): { credentialId: string; salt: string } {
  const { credentialId, salt } = state;
  if (typeof credentialId !== 'string' || typeof salt !== 'string') {
    throw new ProviderError('provider state is missing credentialId/salt');
  }
  return { credentialId, salt };
}
