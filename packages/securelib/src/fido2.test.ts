import { describe, it, expect } from 'vitest';
import { randomBytes, createHmac } from 'node:crypto';
import { YubikeyFido2Provider, type Fido2Authenticator } from './fido2.js';
import { ProviderError, type ProviderContext } from './provider.js';

/**
 * Deterministic function of (this authenticator's own internal secret,
 * salt) — stands in for the real hmac-secret extension's
 * HMAC(credRandom, salt). Same credentialId+salt on the SAME instance
 * always returns the same secret; a different instance (a different
 * physical key) never does, even asked for the same credentialId. See
 * specs/securegit/06-key-provider-port.md's "Test plan" for yubikey-fido2.
 */
class FakeFido2Authenticator implements Fido2Authenticator {
  private readonly internalSecret = randomBytes(32);
  private readonly known = new Set<string>();
  present = true;

  async makeCredential(): Promise<{ credentialId: Buffer }> {
    if (!this.present) throw new Error('fake fido2: no authenticator present');
    const credentialId = randomBytes(16);
    this.known.add(credentialId.toString('hex'));
    return { credentialId };
  }

  async getAssertion(credentialId: Buffer, salt: Buffer): Promise<Buffer> {
    if (!this.present) throw new Error('fake fido2: no authenticator present');
    if (!this.known.has(credentialId.toString('hex'))) {
      throw new Error('fake fido2: unknown credential');
    }
    return createHmac('sha256', this.internalSecret).update(salt).digest();
  }
}

function ctx(state: ProviderContext['state'], over: Partial<ProviderContext> = {}): ProviderContext {
  return { repoId: 'repo-a', generation: 1, state, interactive: true, ...over };
}

describe('YubikeyFido2Provider', () => {
  it('describe() reports custodial: false, requiresHardware: true', () => {
    const provider = new YubikeyFido2Provider(new FakeFido2Authenticator());
    const info = provider.describe();
    expect(info.custodial).toBe(false);
    expect(info.requiresHardware).toBe(true);
  });

  it('wrap() then unwrap() returns the identical key, via a real hmac-secret-shaped derivation', async () => {
    const provider = new YubikeyFido2Provider(new FakeFido2Authenticator());
    const state = await provider.init({ repoId: 'repo-a', generation: 1 });
    const key = randomBytes(32);
    const wrapped = await provider.wrap(key, ctx(state));
    const out = await provider.unwrap(wrapped, ctx(state));
    expect(Buffer.from(out).equals(key)).toBe(true);
  });

  it('unwrap() throws a specific, actionable error when ctx.interactive is false, before ever touching the authenticator', async () => {
    const authenticator = new FakeFido2Authenticator();
    const provider = new YubikeyFido2Provider(authenticator);
    const state = await provider.init({ repoId: 'repo-a', generation: 1 });
    const wrapped = await provider.wrap(randomBytes(32), ctx(state));
    authenticator.present = false; // proves unwrap() never reaches the authenticator when non-interactive
    await expect(provider.unwrap(wrapped, ctx(state, { interactive: false }))).rejects.toThrow(
      /securegit unlock.*first.*cannot prompt for touch/s,
    );
  });

  it('unwrap() fails with a different physical authenticator, with a ProviderError, not the raw error', async () => {
    const provider = new YubikeyFido2Provider(new FakeFido2Authenticator());
    const state = await provider.init({ repoId: 'repo-a', generation: 1 });
    const wrapped = await provider.wrap(randomBytes(32), ctx(state));
    const differentPhysicalKey = new YubikeyFido2Provider(new FakeFido2Authenticator());
    await expect(differentPhysicalKey.unwrap(wrapped, ctx(state))).rejects.toBeInstanceOf(ProviderError);
  });
});
