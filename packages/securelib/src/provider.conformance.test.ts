// One contract, run against every KeyProvider. `src/provider.test.ts` tests
// PassphraseFileProvider's own internals (scrypt parameters, its specific
// error strings); this file tests only what `src/provider.ts`'s port
// promises any implementation — the thing a future `tpm2`/`piv` provider
// would have to satisfy to be a drop-in. Valuable now, with one registered
// provider, as living documentation of the contract rather than a check
// that waits for a second implementation to exist.
// See specs/securegit/06-key-provider-port.md.

import { describe, it, expect } from 'vitest';
import { randomBytes, createECDH, createHmac } from 'node:crypto';
import { isSecret } from './crypto.js';
import {
  PassphraseFileProvider,
  ProviderError,
  type KeyProvider,
  type ProviderContext,
} from './provider.js';
import { KmsEnvelopeProvider, type KmsBackend } from './kms-envelope.js';
import { YubikeyPivProvider, type PivCard } from './piv.js';
import { YubikeyFido2Provider, type Fido2Authenticator } from './fido2.js';

const FAST_COST = { N: 2 ** 10, r: 8, p: 1 };

/**
 * In-memory Map<token, plaintext>, context checked exactly like a real
 * backend would enforce it — see kms-envelope.test.ts for the
 * provider-specific tests this same shape backs, and
 * specs/securegit/06-key-provider-port.md's "Test plan" for kms-envelope.
 */
class FakeKmsBackend implements KmsBackend {
  private readonly store = new Map<string, { plaintext: Buffer; keyId: string; context: Record<string, string> }>();
  private counter = 0;

  async encrypt(rmkBytes: Buffer, keyId: string, context: Record<string, string>): Promise<Buffer> {
    const token = `token-${this.counter++}`;
    this.store.set(token, { plaintext: Buffer.from(rmkBytes), keyId, context });
    return Buffer.from(token, 'utf8');
  }

  async decrypt(wrappedRmkBytes: Buffer, keyId: string, context: Record<string, string>): Promise<Buffer> {
    const entry = this.store.get(wrappedRmkBytes.toString('utf8'));
    if (!entry) throw new Error('fake kms: unknown ciphertext');
    if (entry.keyId !== keyId || JSON.stringify(entry.context) !== JSON.stringify(context)) {
      throw new Error('fake kms: context mismatch');
    }
    return entry.plaintext;
  }
}

/** A real P-256 keypair standing in for the card — see piv.test.ts. */
class FakePivCard implements PivCard {
  private readonly keyPair = createECDH('prime256v1');
  readonly publicKey: Buffer;

  constructor() {
    this.keyPair.generateKeys();
    this.publicKey = this.keyPair.getPublicKey();
  }

  async getPublicKey(): Promise<Buffer> {
    return this.publicKey;
  }

  async ecdh(_slot: string, peerPublicKey: Buffer): Promise<Buffer> {
    return this.keyPair.computeSecret(peerPublicKey);
  }
}

/** Deterministic (internal secret, salt) → secret — see fido2.test.ts. */
class FakeFido2Authenticator implements Fido2Authenticator {
  private readonly internalSecret = randomBytes(32);
  private readonly known = new Set<string>();

  async makeCredential(): Promise<{ credentialId: Buffer }> {
    const credentialId = randomBytes(16);
    this.known.add(credentialId.toString('hex'));
    return { credentialId };
  }

  async getAssertion(credentialId: Buffer, salt: Buffer): Promise<Buffer> {
    if (!this.known.has(credentialId.toString('hex'))) throw new Error('fake fido2: unknown credential');
    return createHmac('sha256', this.internalSecret).update(salt).digest();
  }
}

interface Registration {
  name: string;
  makeProvider: () => KeyProvider;
}

/** Every provider registered behind the port. Add a row here, not a new file, when a second one lands. */
const providers: Registration[] = [
  { name: 'passphrase-file', makeProvider: () => new PassphraseFileProvider(() => 'correct horse battery staple', FAST_COST) },
  { name: 'kms-envelope', makeProvider: () => new KmsEnvelopeProvider(new FakeKmsBackend(), 'aws', 'key-1') },
  { name: 'yubikey-piv', makeProvider: () => new YubikeyPivProvider(new FakePivCard(), '9d', () => '123456') },
  { name: 'yubikey-fido2', makeProvider: () => new YubikeyFido2Provider(new FakeFido2Authenticator()) },
];

/** The exact shape `keyring.ts` builds — see its `init`/`wrap`/`unwrap` call sites. */
function ctx(state: ProviderContext['state'], over: Partial<ProviderContext> = {}): ProviderContext {
  return { repoId: 'repo-a', generation: 1, state, interactive: true, ...over };
}

/**
 * Wraps `provider` so every argument passed to `init`/`wrap`/`unwrap` is
 * recorded, without changing behaviour. What this catches: a provider (or a
 * future caller) smuggling a file path or plaintext content into the call —
 * the port's `ProviderContext`/`wrap` signature has no field for either, and
 * this proves nothing slips one in as an extra property at runtime, not just
 * that the TypeScript types say so.
 */
function recordingCalls(provider: KeyProvider): { calls: { method: string; args: unknown[] }[] } {
  const calls: { method: string; args: unknown[] }[] = [];
  const mutable = provider as unknown as Record<string, (...args: unknown[]) => unknown>;
  for (const method of ['init', 'wrap', 'unwrap'] as const) {
    const original = mutable[method]!.bind(provider);
    mutable[method] = async (...args: unknown[]) => {
      calls.push({ method, args });
      return original(...args);
    };
  }
  return { calls };
}

function forbiddenKeys(value: unknown, seen = new Set<unknown>()): string[] {
  if (value === null || typeof value !== 'object' || seen.has(value)) return [];
  seen.add(value);
  const found: string[] = [];
  if (Buffer.isBuffer(value)) return found; // key material itself, not a container to inspect
  for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
    if (/path|content|plaintext/i.test(key)) found.push(key);
    found.push(...forbiddenKeys(v, seen));
  }
  return found;
}

describe.each(providers)('KeyProvider conformance: $name', ({ makeProvider }) => {
  it('describe() returns the ProviderInfo shape, and id matches the instance', () => {
    const provider = makeProvider();
    const info = provider.describe();
    expect(info.id).toBe(provider.id);
    expect(typeof info.label).toBe('string');
    expect(info.label.length).toBeGreaterThan(0);
    expect(typeof info.custodial).toBe('boolean');
    expect(typeof info.requiresHardware).toBe('boolean');
  });

  it('available() resolves to a boolean promptly, without waiting on operator input', async () => {
    const start = Date.now();
    const result = await makeProvider().available();
    expect(typeof result).toBe('boolean');
    expect(Date.now() - start).toBeLessThan(1000);
  });

  it('init() returns a flat, JSON-serialisable ProviderState', async () => {
    const state = await makeProvider().init({ repoId: 'repo-a', generation: 1 });
    const roundTripped: unknown = JSON.parse(JSON.stringify(state));
    expect(roundTripped).toEqual(state);
    for (const value of Object.values(state)) {
      expect(['string', 'number']).toContain(typeof value);
    }
  });

  it('wrap() then unwrap() returns the identical key', async () => {
    const provider = makeProvider();
    const state = await provider.init({ repoId: 'repo-a', generation: 1 });
    const key = randomBytes(32);
    const wrapped = await provider.wrap(key, ctx(state));
    const out = await provider.unwrap(wrapped, ctx(state));
    expect(Buffer.from(out).equals(key)).toBe(true);
  });

  it('unwrap() returns key material marked as a redacting Secret', async () => {
    const provider = makeProvider();
    const state = await provider.init({ repoId: 'repo-a', generation: 1 });
    const wrapped = await provider.wrap(randomBytes(32), ctx(state));
    const out = await provider.unwrap(wrapped, ctx(state));
    expect(isSecret(out)).toBe(true);
  });

  it('wrap() names the provider on the wrapped output, and payload is flat string data', async () => {
    const provider = makeProvider();
    const state = await provider.init({ repoId: 'repo-a', generation: 1 });
    const wrapped = await provider.wrap(randomBytes(32), ctx(state));
    expect(wrapped.provider).toBe(provider.id);
    for (const value of Object.values(wrapped.payload)) {
      expect(typeof value).toBe('string');
    }
    expect(() => JSON.stringify(wrapped)).not.toThrow();
  });

  it('unwrap() fails when repoId does not match what was wrapped', async () => {
    const provider = makeProvider();
    const state = await provider.init({ repoId: 'repo-a', generation: 1 });
    const wrapped = await provider.wrap(randomBytes(32), ctx(state, { repoId: 'repo-a' }));
    await expect(provider.unwrap(wrapped, ctx(state, { repoId: 'repo-b' }))).rejects.toThrow(ProviderError);
  });

  it('unwrap() fails when generation does not match what was wrapped', async () => {
    const provider = makeProvider();
    const state = await provider.init({ repoId: 'repo-a', generation: 1 });
    const wrapped = await provider.wrap(randomBytes(32), ctx(state, { generation: 1 }));
    await expect(provider.unwrap(wrapped, ctx(state, { generation: 2 }))).rejects.toThrow(ProviderError);
  });

  it('never receives a path or file content across a full init/wrap/unwrap cycle', async () => {
    const provider = makeProvider();
    const { calls } = recordingCalls(provider);
    const state = await provider.init({ repoId: 'repo-a', generation: 1 });
    const wrapped = await provider.wrap(randomBytes(32), ctx(state));
    await provider.unwrap(wrapped, ctx(state));

    expect(calls.map((c) => c.method)).toEqual(['init', 'wrap', 'unwrap']);
    for (const call of calls) {
      expect(forbiddenKeys(call.args)).toEqual([]);
    }
  });
});
