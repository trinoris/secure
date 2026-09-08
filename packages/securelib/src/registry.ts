// Resolves a provider `id` (the same string stored in a keyring slot's
// `wrapped[].provider`, see keyring.ts) to a real KeyProvider, without this
// package ever holding a static import naming a package it doesn't depend
// on. See specs/securegit/06-key-provider-port.md's "Loading a provider
// package without paying for it".
//
// Two tiers: BUILTIN providers cost nothing extra (passphrase-file today;
// kms-envelope once built — its own design settles that it stays
// dependency-free enough to belong here too, unlike the two below).
// COMPANION_PACKAGE providers need a real native/hardware dependency
// (PC/SC, CTAP2/HID) that must never load unless a repository actually
// configures that provider — `import(pkg)` with a non-literal specifier is
// what keeps tsc from resolving it at build time, and keeps Node from
// loading it until this function actually runs.

import { PassphraseFileProvider, ProviderError, type KeyProvider } from './provider.js';
import { KmsEnvelopeProvider, type KmsBackend } from './kms-envelope.js';

export interface KmsEnvelopeConfig {
  backend: KmsBackend;
  backendTag: 'aws' | 'gcp' | 'azure';
  keyId: string;
}

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

interface CompanionModule {
  createProvider(config: unknown): KeyProvider;
}

export async function loadProvider(id: string, config: unknown): Promise<KeyProvider> {
  const builtin = BUILTIN[id];
  if (builtin) return builtin(config);

  const pkg = COMPANION_PACKAGE[id];
  if (!pkg) {
    throw new ProviderError(`securegit: unknown provider id '${id}'`);
  }

  let mod: CompanionModule;
  try {
    mod = (await import(pkg)) as CompanionModule;
  } catch {
    throw new ProviderError(
      `securegit: provider '${id}' needs ${pkg}, which is not installed\n` +
        `  action: npm install ${pkg}`,
    );
  }
  return mod.createProvider(config);
}
