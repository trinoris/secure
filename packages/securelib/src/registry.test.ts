import { describe, it, expect } from 'vitest';
import { loadProvider } from './registry.js';
import { ProviderError } from './provider.js';

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

  it('rejects an unknown provider id, distinctly from a missing companion package', async () => {
    await expect(loadProvider('not-a-real-provider', undefined)).rejects.toThrow(
      /unknown provider id 'not-a-real-provider'/,
    );
  });

  it('an unknown provider id rejects with ProviderError', async () => {
    await expect(loadProvider('not-a-real-provider', undefined)).rejects.toBeInstanceOf(ProviderError);
  });

  it('yubikey-piv, with the companion package not installed, gives an actionable npm install error', async () => {
    await expect(loadProvider('yubikey-piv', undefined)).rejects.toThrow(
      /npm install @trinoris\/securelib-piv/,
    );
  });

  it('yubikey-fido2, with the companion package not installed, names its own package', async () => {
    await expect(loadProvider('yubikey-fido2', undefined)).rejects.toThrow(
      /npm install @trinoris\/securelib-fido2/,
    );
  });

  it('a missing companion package rejects with ProviderError, not a raw module-resolution error', async () => {
    await expect(loadProvider('yubikey-piv', undefined)).rejects.toBeInstanceOf(ProviderError);
  });
});
