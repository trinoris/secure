import { describe, it, expect, vi } from 'vitest';
import { ProviderError } from './provider.js';

// Both @trinoris/securelib-piv and @trinoris/securelib-fido2 are real
// sibling workspace packages in this monorepo now (packages/securelib-piv,
// packages/securelib-fido2) — registry.test.ts's own tests prove
// loadProvider() resolves them for real. That leaves no genuinely-absent
// companion package left to test the *other* branch against: what a
// downstream consumer who hasn't installed one sees. vi.mock() simulates
// exactly that — a dynamic import() that fails — without needing an
// actually-uninstalled package, kept in its own file so this mock never
// leaks into registry.test.ts's real-resolution tests.
vi.mock('@trinoris/securelib-fido2', () => {
  throw new Error("Cannot find module '@trinoris/securelib-fido2'");
});

describe('loadProvider() when a companion package genuinely is not installed', () => {
  it('gives an actionable npm install error', async () => {
    const { loadProvider } = await import('./registry.js');
    await expect(loadProvider('yubikey-fido2', undefined)).rejects.toThrow(
      /npm install @trinoris\/securelib-fido2/,
    );
  });

  it('rejects with ProviderError, not a raw module-resolution error', async () => {
    const { loadProvider } = await import('./registry.js');
    await expect(loadProvider('yubikey-fido2', undefined)).rejects.toBeInstanceOf(ProviderError);
  });
});
