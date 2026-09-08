import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import { KmsEnvelopeProvider, type KmsBackend } from './kms-envelope.js';
import { ProviderError, type ProviderContext } from './provider.js';

/**
 * In-memory Map<token, plaintext>, context checked exactly like a real
 * backend would enforce it (AWS's encryption context / GCP's and Azure's
 * AAD) — see specs/securegit/06-key-provider-port.md's "Test plan" for
 * kms-envelope. `rejectAll`, when set, makes every call fail — simulates a
 * revoked key or an unreachable network, without a real one.
 */
class FakeKmsBackend implements KmsBackend {
  private readonly store = new Map<string, { plaintext: Buffer; keyId: string; context: Record<string, string> }>();
  private counter = 0;
  rejectAll = false;

  async encrypt(rmkBytes: Buffer, keyId: string, context: Record<string, string>): Promise<Buffer> {
    if (this.rejectAll) throw new Error('fake kms: backend unavailable');
    const token = `token-${this.counter++}`;
    this.store.set(token, { plaintext: Buffer.from(rmkBytes), keyId, context });
    return Buffer.from(token, 'utf8');
  }

  async decrypt(wrappedRmkBytes: Buffer, keyId: string, context: Record<string, string>): Promise<Buffer> {
    if (this.rejectAll) throw new Error('fake kms: backend unavailable');
    const entry = this.store.get(wrappedRmkBytes.toString('utf8'));
    if (!entry) throw new Error('fake kms: unknown ciphertext');
    if (entry.keyId !== keyId || JSON.stringify(entry.context) !== JSON.stringify(context)) {
      throw new Error('fake kms: context mismatch');
    }
    return entry.plaintext;
  }
}

function ctx(state: ProviderContext['state'], over: Partial<ProviderContext> = {}): ProviderContext {
  return { repoId: 'repo-a', generation: 1, state, interactive: true, ...over };
}

describe('KmsEnvelopeProvider', () => {
  it('describe() reports custodial: true, and names the backend in the label', () => {
    const provider = new KmsEnvelopeProvider(new FakeKmsBackend(), 'aws', 'arn:aws:kms:us-east-1:1:key/abc');
    const info = provider.describe();
    expect(info.custodial).toBe(true);
    expect(info.requiresHardware).toBe(false);
    expect(info.label).toContain('aws');
  });

  it('init() persists keyId and backend into state — wrap/unwrap read it from ctx.state, not the constructor', async () => {
    const provider = new KmsEnvelopeProvider(new FakeKmsBackend(), 'gcp', 'projects/p/locations/l/keyRings/r/cryptoKeys/k');
    const state = await provider.init({ repoId: 'repo-a', generation: 1 });
    expect(state).toEqual({ keyId: 'projects/p/locations/l/keyRings/r/cryptoKeys/k', backend: 'gcp' });
  });

  it('wrap() then unwrap() returns the identical key via the backend', async () => {
    const provider = new KmsEnvelopeProvider(new FakeKmsBackend(), 'azure', 'https://vault.vault.azure.net/keys/k');
    const state = await provider.init({ repoId: 'repo-a', generation: 1 });
    const key = randomBytes(32);
    const wrapped = await provider.wrap(key, ctx(state));
    const out = await provider.unwrap(wrapped, ctx(state));
    expect(Buffer.from(out).equals(key)).toBe(true);
  });

  it('wrap() payload is flat string data: keyId, backend, ciphertext', async () => {
    const provider = new KmsEnvelopeProvider(new FakeKmsBackend(), 'aws', 'key-1');
    const state = await provider.init({ repoId: 'repo-a', generation: 1 });
    const wrapped = await provider.wrap(randomBytes(32), ctx(state));
    expect(Object.keys(wrapped.payload).sort()).toEqual(['backend', 'ciphertext', 'keyId']);
    expect(wrapped.payload.keyId).toBe('key-1');
    expect(wrapped.payload.backend).toBe('aws');
  });

  it('unwrap() fails when the backend rejects (revoked key, unreachable), with a ProviderError, not the raw backend error', async () => {
    const backend = new FakeKmsBackend();
    const provider = new KmsEnvelopeProvider(backend, 'aws', 'key-1');
    const state = await provider.init({ repoId: 'repo-a', generation: 1 });
    const wrapped = await provider.wrap(randomBytes(32), ctx(state));
    backend.rejectAll = true;
    await expect(provider.unwrap(wrapped, ctx(state))).rejects.toBeInstanceOf(ProviderError);
  });

  it('unwrap() throws ProviderError when the wrapped payload is missing keyId or ciphertext', async () => {
    const provider = new KmsEnvelopeProvider(new FakeKmsBackend(), 'aws', 'key-1');
    const state = await provider.init({ repoId: 'repo-a', generation: 1 });
    await expect(
      provider.unwrap({ provider: 'kms-envelope', payload: { keyId: 'key-1' } }, ctx(state)),
    ).rejects.toBeInstanceOf(ProviderError);
  });

  it('two providers pointed at different key ids never cross-decrypt each other\'s wrapped output', async () => {
    const backend = new FakeKmsBackend();
    const providerA = new KmsEnvelopeProvider(backend, 'aws', 'key-a');
    const providerB = new KmsEnvelopeProvider(backend, 'aws', 'key-b');
    const stateA = await providerA.init({ repoId: 'repo-a', generation: 1 });
    const stateB = await providerB.init({ repoId: 'repo-a', generation: 1 });
    const wrapped = await providerA.wrap(randomBytes(32), ctx(stateA));
    await expect(providerB.unwrap(wrapped, ctx(stateB))).rejects.toBeInstanceOf(ProviderError);
  });
});
