// yubikey-piv: reuses a PIV card's own key-management slot (9d, by PIV
// convention) — the card's private key never leaves it. wrap() only ever
// touches the card's PUBLIC key (no card present required); unwrap() sends
// an ephemeral public key to the card and asks it to perform the ECDH
// operation itself, getting back only the resulting shared secret. Same
// ephemeral-ECDH-then-HKDF-then-AES-256-GCM shape as recipients.ts's own
// X25519 sharing, over P-256 (the curve PIV hardware actually speaks)
// instead. See specs/securegit/06-key-provider-port.md's "yubikey-piv"
// design.
//
// The real PC/SC transport (talking to actual hardware) is not built here
// — that's the honest boundary this file draws: `PivCard` is the seam a
// real `@trinoris/securelib-piv` companion package (registry.ts) would
// implement against real hardware; this file only needs a `PivCard` to
// exist, real or faked, and never assumes which.

import { createECDH, hkdfSync, randomBytes } from 'node:crypto';
import {
  ProviderError,
  type KeyProvider,
  type ProviderContext,
  type ProviderInfo,
  type ProviderState,
  type WrappedKey,
} from './provider.js';
import { aeadEncrypt, aeadDecrypt, secret, type Secret } from './crypto.js';

/** The seam: real PC/SC hardware access, or a fake, on either side of this. */
export interface PivCard {
  /** The card's own key-management slot public key — uncompressed P-256 point (65 bytes). */
  getPublicKey(slot: string): Promise<Buffer>;
  /** The card performs ECDH(card.priv-on-card, peerPublicKey) itself; only the shared secret comes back. */
  ecdh(slot: string, peerPublicKey: Buffer, pin: string): Promise<Buffer>;
}

const CURVE = 'prime256v1'; // P-256, NIST's name for the same curve
const WRAP_INFO = Buffer.from('securegit/piv-wrap/v1', 'utf8');
const WRAP_KEY_LEN = 32;
const AAD_LABEL = Buffer.from('securegit/piv-wrap/v1', 'utf8');
const SEP = Buffer.from([0x00]);

export class YubikeyPivProvider implements KeyProvider {
  readonly id: string;

  constructor(
    private readonly card: PivCard,
    private readonly slot: string,
    private readonly getPin: () => Promise<string> | string,
    id = 'yubikey-piv',
  ) {
    this.id = id;
  }

  describe(): ProviderInfo {
    return {
      id: this.id,
      label: 'YubiKey / PIV smartcard',
      custodial: false,
      requiresHardware: true,
    };
  }

  async available(): Promise<boolean> {
    try {
      await this.card.getPublicKey(this.slot);
      return true;
    } catch {
      return false;
    }
  }

  async init(ctx: { repoId: string; generation: number }): Promise<ProviderState> {
    void ctx;
    return { slot: this.slot };
  }

  async wrap(key: Buffer, ctx: ProviderContext): Promise<WrappedKey> {
    const { slot } = requireState(ctx.state);
    const cardPublicKey = await this.card.getPublicKey(slot);
    const ephemeral = createECDH(CURVE);
    ephemeral.generateKeys();
    const shared = ephemeral.computeSecret(cardPublicKey);
    const salt = randomBytes(16);
    const kek = Buffer.from(hkdfSync('sha256', shared, salt, WRAP_INFO, WRAP_KEY_LEN));
    const nonce = randomBytes(12);
    const aad = buildAad(ctx.repoId, ctx.generation);
    const { ciphertext, authTag } = aeadEncrypt(kek, nonce, key, aad);
    return {
      provider: this.id,
      payload: {
        slot,
        ephemeralPublicKey: ephemeral.getPublicKey().toString('hex'),
        salt: salt.toString('hex'),
        nonce: nonce.toString('hex'),
        ciphertext: ciphertext.toString('hex'),
        authTag: authTag.toString('hex'),
      },
    };
  }

  async unwrap(wrapped: WrappedKey, ctx: ProviderContext): Promise<Secret> {
    // Checked first, before touching the payload or prompting for a PIN —
    // a PIV card's private-key operation requires the PIN every time (and,
    // depending on the slot's touch policy, a physical touch), so there is
    // no non-interactive path, ever. A Git filter must never attempt this.
    if (!ctx.interactive) {
      throw new ProviderError(
        'securegit: yubikey-piv requires `securegit unlock` first; a Git filter cannot prompt for a PIN',
      );
    }
    const { slot, ephemeralPublicKey, salt, nonce, ciphertext, authTag } = wrapped.payload;
    if (
      slot === undefined ||
      ephemeralPublicKey === undefined ||
      salt === undefined ||
      nonce === undefined ||
      ciphertext === undefined ||
      authTag === undefined
    ) {
      throw new ProviderError('wrapped key is missing a required field');
    }
    const pin = await this.getPin();
    try {
      const shared = await this.card.ecdh(slot, Buffer.from(ephemeralPublicKey, 'hex'), pin);
      const kek = Buffer.from(hkdfSync('sha256', shared, Buffer.from(salt, 'hex'), WRAP_INFO, WRAP_KEY_LEN));
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
      // unwrap(): never reveal whether the PIN, the card, or the repo/
      // generation binding was the part that was wrong.
      throw new ProviderError('could not unwrap: wrong PIN, wrong card, or key belongs elsewhere');
    }
  }
}

function buildAad(repoId: string, generation: number): Buffer {
  const genBuf = Buffer.alloc(4);
  genBuf.writeUInt32BE(generation >>> 0);
  return Buffer.concat([AAD_LABEL, SEP, Buffer.from(repoId, 'utf8'), SEP, genBuf]);
}

function requireState(state: ProviderState): { slot: string } {
  const { slot } = state;
  if (typeof slot !== 'string') {
    throw new ProviderError('provider state is missing slot');
  }
  return { slot };
}
