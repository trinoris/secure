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

  // Both @trinoris/securelib-piv and @trinoris/securelib-fido2 are real
  // sibling workspace packages in this monorepo (packages/securelib-piv,
  // packages/securelib-fido2) — loadProvider() genuinely resolves both,
  // proving the dynamic-import path works end to end against real
  // companion packages, not just the BUILTIN path passphrase-file/
  // kms-envelope already cover. What a downstream consumer sees when a
  // companion package genuinely isn't installed is covered separately —
  // see registry.not-installed.test.ts, which simulates that with
  // vi.mock() since both packages are unconditionally present here.
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

  it('resolves yubikey-fido2 via the real, installed @trinoris/securelib-fido2 companion package', async () => {
    const provider = await loadProvider('yubikey-fido2', {});
    expect(provider.id).toBe('yubikey-fido2');
    expect(provider.describe()).toEqual({
      id: 'yubikey-fido2',
      label: 'FIDO2 authenticator (hmac-secret)',
      custodial: false,
      requiresHardware: true,
    });
  });
});
