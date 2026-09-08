import { describe, it, expect } from 'vitest';
import { AzureKmsBackend, type HttpTransport } from './azure-kms-backend.js';

const CREDENTIALS = { tenantId: 'tenant-1', clientId: 'client-1', clientSecret: 'secret-1' };
const KEY_ID = 'https://myvault.vault.azure.net/keys/mykey/abc123def456';

function fakeTransport(responses: { statusCode: number; body: string }[]): {
  transport: HttpTransport;
  calls: { host: string; path: string; headers: Record<string, string>; body: string }[];
} {
  const calls: { host: string; path: string; headers: Record<string, string>; body: string }[] = [];
  let i = 0;
  return {
    calls,
    transport: async (opts) => {
      calls.push(opts);
      return responses[i++] ?? responses[responses.length - 1]!;
    },
  };
}

describe('AzureKmsBackend', () => {
  it('encrypt() exchanges an AAD token, then calls the key\'s /encrypt with a fresh IV it generated', async () => {
    const { transport, calls } = fakeTransport([
      { statusCode: 200, body: JSON.stringify({ access_token: 'fake-token' }) },
      {
        statusCode: 200,
        body: JSON.stringify({
          value: Buffer.from('fake-ciphertext').toString('base64url'),
          tag: Buffer.alloc(16, 7).toString('base64url'),
        }),
      },
    ]);
    const backend = new AzureKmsBackend({ credentials: CREDENTIALS, transport });
    const rmk = Buffer.from('a'.repeat(32));
    const wrapped = await backend.encrypt(rmk, KEY_ID, { repoId: 'repo-a', generation: '1' });

    expect(calls).toHaveLength(2);
    expect(calls[0]!.host).toBe('login.microsoftonline.com');
    expect(calls[0]!.path).toBe('/tenant-1/oauth2/v2.0/token');
    expect(calls[0]!.body).toContain('grant_type=client_credentials');
    expect(calls[0]!.body).toContain('scope=https%3A%2F%2Fvault.azure.net%2F.default');

    expect(calls[1]!.host).toBe('myvault.vault.azure.net');
    expect(calls[1]!.path).toBe('/keys/mykey/abc123def456/encrypt?api-version=7.4');
    expect(calls[1]!.headers.authorization).toBe('Bearer fake-token');
    const sentBody = JSON.parse(calls[1]!.body) as Record<string, unknown>;
    expect(sentBody.alg).toBe('A256GCM');
    expect(sentBody.value).toBe(rmk.toString('base64url'));
    expect(typeof sentBody.iv).toBe('string');

    // wrapped packs iv(12) ‖ tag(16) ‖ ciphertext
    expect(wrapped.length).toBe(12 + 16 + Buffer.from('fake-ciphertext').length);
    expect(wrapped.subarray(12, 28).equals(Buffer.alloc(16, 7))).toBe(true);
    expect(wrapped.subarray(28).equals(Buffer.from('fake-ciphertext'))).toBe(true);
  });

  it('wrap() then unwrap() round-trips through a fake Key Vault that actually performs AES-256-GCM', async () => {
    // A fake that does real AES-256-GCM under a fixed vault key — proves
    // the iv/tag pack-unpack framing is correct, not just that two mocks
    // agree with each other trivially.
    const { createCipheriv, createDecipheriv, randomBytes } = await import('node:crypto');
    const vaultKey = randomBytes(32);
    const { transport } = fakeTransport([{ statusCode: 200, body: JSON.stringify({ access_token: 't' }) }]);
    const realTransport: HttpTransport = async (opts) => {
      if (opts.host === 'login.microsoftonline.com') return transport(opts);
      const req = JSON.parse(opts.body) as { alg: string; value: string; iv: string; tag?: string; aad: string };
      const iv = Buffer.from(req.iv, 'base64url');
      const aad = Buffer.from(req.aad, 'base64url');
      if (opts.path.endsWith('/encrypt?api-version=7.4')) {
        const cipher = createCipheriv('aes-256-gcm', vaultKey, iv);
        cipher.setAAD(aad);
        const ciphertext = Buffer.concat([cipher.update(Buffer.from(req.value, 'base64url')), cipher.final()]);
        return {
          statusCode: 200,
          body: JSON.stringify({ value: ciphertext.toString('base64url'), tag: cipher.getAuthTag().toString('base64url') }),
        };
      }
      const decipher = createDecipheriv('aes-256-gcm', vaultKey, iv);
      decipher.setAuthTag(Buffer.from(req.tag!, 'base64url'));
      decipher.setAAD(aad);
      const plaintext = Buffer.concat([decipher.update(Buffer.from(req.value, 'base64url')), decipher.final()]);
      return { statusCode: 200, body: JSON.stringify({ value: plaintext.toString('base64url') }) };
    };
    const backend = new AzureKmsBackend({ credentials: CREDENTIALS, transport: realTransport });
    const rmk = Buffer.from('b'.repeat(32));
    const wrapped = await backend.encrypt(rmk, KEY_ID, { repoId: 'repo-a', generation: '1' });
    const unwrapped = await backend.decrypt(wrapped, KEY_ID, { repoId: 'repo-a', generation: '1' });
    expect(unwrapped.equals(rmk)).toBe(true);
  });

  it('decrypt() rejects a wrapped value too short to contain iv+tag, without ever calling the network', async () => {
    const { transport, calls } = fakeTransport([{ statusCode: 200, body: '{}' }]);
    const backend = new AzureKmsBackend({ credentials: CREDENTIALS, transport });
    await expect(backend.decrypt(Buffer.alloc(10), KEY_ID, {})).rejects.toThrow(/too short/);
    expect(calls).toHaveLength(0);
  });

  it('rejects a keyId that is not a valid Key Vault key identifier', async () => {
    const { transport } = fakeTransport([{ statusCode: 200, body: JSON.stringify({ access_token: 't' }) }]);
    const backend = new AzureKmsBackend({ credentials: CREDENTIALS, transport });
    await expect(backend.encrypt(Buffer.from('a'.repeat(32)), 'not-a-url', {})).rejects.toThrow();
  });

  it('a non-200 token exchange throws before ever calling Key Vault', async () => {
    const { transport, calls } = fakeTransport([{ statusCode: 401, body: '{"error":"invalid_client"}' }]);
    const backend = new AzureKmsBackend({ credentials: CREDENTIALS, transport });
    await expect(backend.encrypt(Buffer.from('a'.repeat(32)), KEY_ID, {})).rejects.toThrow(/401.*invalid_client/s);
    expect(calls).toHaveLength(1);
  });
});

const hasRealCredentials =
  !!process.env.AZURE_TENANT_ID && !!process.env.AZURE_CLIENT_ID && !!process.env.AZURE_CLIENT_SECRET && !!process.env.AZURE_KMS_TEST_KEY_ID;

/**
 * The actual verification gate this design's own test plan calls for:
 * skipped unless real Azure AD app credentials and a real Managed HSM
 * oct-HSM key are configured (AZURE_TENANT_ID, AZURE_CLIENT_ID,
 * AZURE_CLIENT_SECRET, AZURE_KMS_TEST_KEY_ID — the key's full kid URL).
 */
describe.skipIf(!hasRealCredentials)('AzureKmsBackend against real Azure Key Vault', () => {
  it('wraps and unwraps a real 32-byte key via a real Managed HSM key', async () => {
    const backend = new AzureKmsBackend({
      credentials: {
        tenantId: process.env.AZURE_TENANT_ID!,
        clientId: process.env.AZURE_CLIENT_ID!,
        clientSecret: process.env.AZURE_CLIENT_SECRET!,
      },
    });
    const keyId = process.env.AZURE_KMS_TEST_KEY_ID!;
    const rmk = Buffer.from('c'.repeat(32));
    const wrapped = await backend.encrypt(rmk, keyId, { repoId: 'test-repo', generation: '1' });
    const unwrapped = await backend.decrypt(wrapped, keyId, { repoId: 'test-repo', generation: '1' });
    expect(unwrapped.equals(rmk)).toBe(true);
  });
});
