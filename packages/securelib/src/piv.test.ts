import { describe, it, expect } from 'vitest';
import { createECDH, randomBytes } from 'node:crypto';
import { YubikeyPivProvider, type PivCard } from './piv.js';
import { ProviderError, type ProviderContext } from './provider.js';

/**
 * A real P-256 keypair standing in for the card, with a real ECDH
 * computation performed on `ecdh()` — the actual cryptography is real; only
 * "is a physical card present" is faked. See
 * specs/securegit/06-key-provider-port.md's "Test plan" for yubikey-piv.
 */
class FakePivCard implements PivCard {
  private readonly keyPair = createECDH('prime256v1');
  readonly publicKey: Buffer;
  correctPin = '123456';
  present = true;

  constructor() {
    this.keyPair.generateKeys();
    this.publicKey = this.keyPair.getPublicKey();
  }

  async getPublicKey(slot: string): Promise<Buffer> {
    void slot;
    if (!this.present) throw new Error('fake piv: no card present');
    return this.publicKey;
  }

  async ecdh(slot: string, peerPublicKey: Buffer, pin: string): Promise<Buffer> {
    void slot;
    if (!this.present) throw new Error('fake piv: no card present');
    if (pin !== this.correctPin) throw new Error('fake piv: wrong PIN');
    return this.keyPair.computeSecret(peerPublicKey);
  }
}

function ctx(state: ProviderContext['state'], over: Partial<ProviderContext> = {}): ProviderContext {
  return { repoId: 'repo-a', generation: 1, state, interactive: true, ...over };
}

describe('YubikeyPivProvider', () => {
  it('describe() reports custodial: false, requiresHardware: true', () => {
    const provider = new YubikeyPivProvider(new FakePivCard(), '9d', () => '123456');
    const info = provider.describe();
    expect(info.custodial).toBe(false);
    expect(info.requiresHardware).toBe(true);
  });

  it('wrap() only touches the card\'s public key — available() and wrap() never call ecdh()', async () => {
    const card = new FakePivCard();
    let ecdhCalls = 0;
    const tracked: PivCard = {
      getPublicKey: (slot) => card.getPublicKey(slot),
      ecdh: (slot, pub, pin) => {
        ecdhCalls++;
        return card.ecdh(slot, pub, pin);
      },
    };
    const provider = new YubikeyPivProvider(tracked, '9d', () => '123456');
    const state = await provider.init({ repoId: 'repo-a', generation: 1 });
    await provider.wrap(randomBytes(32), ctx(state));
    expect(ecdhCalls).toBe(0);
  });

  it('wrap() then unwrap() returns the identical key, via a real ECDH computation', async () => {
    const provider = new YubikeyPivProvider(new FakePivCard(), '9d', () => '123456');
    const state = await provider.init({ repoId: 'repo-a', generation: 1 });
    const key = randomBytes(32);
    const wrapped = await provider.wrap(key, ctx(state));
    const out = await provider.unwrap(wrapped, ctx(state));
    expect(Buffer.from(out).equals(key)).toBe(true);
  });

  it('unwrap() throws a specific, actionable error when ctx.interactive is false, before ever touching the card', async () => {
    const card = new FakePivCard();
    const provider = new YubikeyPivProvider(card, '9d', () => '123456');
    const state = await provider.init({ repoId: 'repo-a', generation: 1 });
    const wrapped = await provider.wrap(randomBytes(32), ctx(state));
    card.present = false; // proves unwrap() never reaches the card when non-interactive
    await expect(provider.unwrap(wrapped, ctx(state, { interactive: false }))).rejects.toThrow(
      /securegit unlock.*first.*cannot prompt for a PIN/s,
    );
  });

  it('unwrap() fails on the wrong PIN, with a ProviderError, not the raw card error', async () => {
    const card = new FakePivCard();
    const provider = new YubikeyPivProvider(card, '9d', () => 'not-the-real-pin');
    const state = await provider.init({ repoId: 'repo-a', generation: 1 });
    const wrapped = await provider.wrap(randomBytes(32), ctx(state));
    await expect(provider.unwrap(wrapped, ctx(state))).rejects.toBeInstanceOf(ProviderError);
  });

  it('available() reflects whether the card is present, without prompting', async () => {
    const card = new FakePivCard();
    const provider = new YubikeyPivProvider(card, '9d', () => '123456');
    expect(await provider.available()).toBe(true);
    card.present = false;
    expect(await provider.available()).toBe(false);
  });
});
