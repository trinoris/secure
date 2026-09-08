import { describe, it, expect } from 'vitest';
import { loadProvider, type KmsEnvelopeConfig } from './registry.js';
import { ProviderError } from './provider.js';
import type { KmsBackend } from './kms-envelope.js';

class FakeKmsBackend implements KmsBackend {
  async encrypt(rmkBytes: Buffer): Promise<Buffer> {
    return rmkBytes;
  }
  async decrypt(wrappedRmkBytes: Buffer): Promise<Buffer> {
    return wrappedRmkBytes;
  }
}

describe('loadProvider()', () => {
  it('resolves passphrase-file to a real, working provider — no dynamic import needed', async () => {
    const provider = await loadProvider('passphrase-file', () => 'a-real-passphrase-1234');
    expect(provider.id).toBe('passphrase-file');
    expect(provider.describe()).toEqual({
      id: 'passphrase-file',
      label: 'Passphrase (local file)',
      custodial: false,
      requiresHardware: false,
    });
  });

  it('resolves kms-envelope to a real, working provider — no dynamic import needed', async () => {
    const config: KmsEnvelopeConfig = { backend: new FakeKmsBackend(), backendTag: 'aws', keyId: 'key-1' };
    const provider = await loadProvider('kms-envelope', config);
    expect(provider.id).toBe('kms-envelope');
    expect(provider.describe().custodial).toBe(true);
  });

  it('rejects an unknown provider id, distinctly from a missing companion package', async () => {
    await expect(loadProvider('not-a-real-provider', undefined)).rejects.toThrow(
      /unknown provider id 'not-a-real-provider'/,
    );
  });

  it('an unknown provider id rejects with ProviderError', async () => {
    await expect(loadProvider('not-a-real-provider', undefined)).rejects.toBeInstanceOf(ProviderError);
  });

  it('yubikey-fido2, with the companion package not installed, gives an actionable npm install error', async () => {
    await expect(loadProvider('yubikey-fido2', undefined)).rejects.toThrow(
      /npm install @trinoris\/securelib-fido2/,
    );
  });

  it('a missing companion package rejects with ProviderError, not a raw module-resolution error', async () => {
    await expect(loadProvider('yubikey-fido2', undefined)).rejects.toBeInstanceOf(ProviderError);
  });

  // @trinoris/securelib-piv is a real sibling workspace package in this
  // monorepo (packages/securelib-piv) — unlike -fido2 above, `yubikey-piv`
  // genuinely resolves here, proving loadProvider()'s dynamic-import path
  // works end to end against a real companion package, not just the
  // BUILTIN path passphrase-file/kms-envelope already cover. A downstream
  // consumer that hasn't installed @trinoris/securelib-piv still gets the
  // "not installed" error above — this environment just isn't that case.
  it('resolves yubikey-piv via the real, installed @trinoris/securelib-piv companion package', async () => {
    const provider = await loadProvider('yubikey-piv', { slot: '9d', pin: () => '123456' });
    expect(provider.id).toBe('yubikey-piv');
    expect(provider.describe()).toEqual({
      id: 'yubikey-piv',
      label: 'YubiKey / PIV smartcard',
      custodial: false,
      requiresHardware: true,
    });
  });
});
