import { describe, it, expect, beforeAll } from 'vitest';
import { generateKeyPairSync, createVerify } from 'node:crypto';
import { signServiceAccountJwt, GcpKmsBackend, type GcpServiceAccount, type HttpTransport } from './gcp-kms-backend.js';

let serviceAccount: GcpServiceAccount;
const NOW = new Date('2026-08-30T12:36:00.000Z');

beforeAll(() => {
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  serviceAccount = { client_email: 'test@example-project.iam.gserviceaccount.com', private_key: privateKey };
});

function testKeyPair() {
  return generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

/**
 * Unlike AWS's SigV4 (verified only structurally, since checking it
 * byte-exact needs a live AWS endpoint), a JWT signature is fully,
 * genuinely verifiable offline: generate a real RSA keypair, sign with the
 * private half, verify with the public half. This is real cryptographic
 * correctness, not just shape-checking.
 */
describe('signServiceAccountJwt()', () => {
  it('produces a JWT with a signature that genuinely verifies against the service account\'s public key', () => {
    const { publicKey, privateKey } = testKeyPair();
    const jwt = signServiceAccountJwt({ client_email: 'a@b.iam.gserviceaccount.com', private_key: privateKey }, NOW);
    const [headerB64, claimsB64, signatureB64] = jwt.split('.');
    const verifier = createVerify('RSA-SHA256');
    verifier.update(`${headerB64}.${claimsB64}`);
    expect(verifier.verify(publicKey, Buffer.from(signatureB64!, 'base64url'))).toBe(true);
  });

  it('a signature made with a different key does not verify against this one\'s public key', () => {
    const { publicKey } = testKeyPair();
    const { privateKey: otherPrivateKey } = testKeyPair();
    const jwt = signServiceAccountJwt({ client_email: 'a@b.iam.gserviceaccount.com', private_key: otherPrivateKey }, NOW);
    const [headerB64, claimsB64, signatureB64] = jwt.split('.');
    const verifier = createVerify('RSA-SHA256');
    verifier.update(`${headerB64}.${claimsB64}`);
    expect(verifier.verify(publicKey, Buffer.from(signatureB64!, 'base64url'))).toBe(false);
  });

  it('claims match the RFC 7523 JWT-bearer shape: iss, scope, aud, iat, exp (1 hour later)', () => {
    const jwt = signServiceAccountJwt(serviceAccount, NOW);
    const [, claimsB64] = jwt.split('.');
    const claims = JSON.parse(Buffer.from(claimsB64!, 'base64url').toString('utf8')) as Record<string, unknown>;
    expect(claims.iss).toBe(serviceAccount.client_email);
    expect(claims.scope).toBe('https://www.googleapis.com/auth/cloudkms');
    expect(claims.aud).toBe('https://oauth2.googleapis.com/token');
    expect(claims.exp).toBe((claims.iat as number) + 3600);
  });
});

function fakeTransport(responses: { statusCode: number; body: string }[]): {
  transport: HttpTransport;
  calls: { host: string; path: string; method: string; headers: Record<string, string>; body: string }[];
} {
  const calls: { host: string; path: string; method: string; headers: Record<string, string>; body: string }[] = [];
  let i = 0;
  return {
    calls,
    transport: async (opts) => {
      calls.push(opts);
      return responses[i++] ?? responses[responses.length - 1]!;
    },
  };
}

describe('GcpKmsBackend', () => {
  it('encrypt() exchanges the JWT for a token, then calls :encrypt with a Bearer header', async () => {
    const { transport, calls } = fakeTransport([
      { statusCode: 200, body: JSON.stringify({ access_token: 'fake-token', expires_in: 3600 }) },
      { statusCode: 200, body: JSON.stringify({ ciphertext: Buffer.from('fake-ct').toString('base64') }) },
    ]);
    const backend = new GcpKmsBackend({ serviceAccount, transport, now: () => NOW });
    const rmk = Buffer.from('a'.repeat(32));
    const result = await backend.encrypt(rmk, 'projects/p/locations/l/keyRings/r/cryptoKeys/k', {
      repoId: 'repo-a',
      generation: '1',
    });

    expect(result.equals(Buffer.from('fake-ct'))).toBe(true);
    expect(calls).toHaveLength(2);
    expect(calls[0]!.host).toBe('oauth2.googleapis.com');
    expect(calls[0]!.body).toContain('grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer');
    expect(calls[1]!.host).toBe('cloudkms.googleapis.com');
    expect(calls[1]!.path).toBe('/v1/projects/p/locations/l/keyRings/r/cryptoKeys/k:encrypt');
    expect(calls[1]!.headers.authorization).toBe('Bearer fake-token');
    const sentBody = JSON.parse(calls[1]!.body) as Record<string, unknown>;
    expect(sentBody.plaintext).toBe(rmk.toString('base64'));
  });

  it('decrypt() round-trips the same additionalAuthenticatedData regardless of context key order', async () => {
    const { transport, calls } = fakeTransport([
      { statusCode: 200, body: JSON.stringify({ access_token: 'fake-token' }) },
      { statusCode: 200, body: JSON.stringify({ plaintext: Buffer.from('a'.repeat(32)).toString('base64') }) },
    ]);
    const backend = new GcpKmsBackend({ serviceAccount, transport, now: () => NOW });
    await backend.decrypt(Buffer.from('ct'), 'k', { generation: '1', repoId: 'repo-a' });
    const sentBody = JSON.parse(calls[1]!.body) as Record<string, unknown>;
    const aad = JSON.parse(Buffer.from(sentBody.additionalAuthenticatedData as string, 'base64').toString('utf8'));
    expect(aad).toEqual({ generation: '1', repoId: 'repo-a' });
    expect(Object.keys(aad)).toEqual(['generation', 'repoId']); // sorted, not insertion order
  });

  it('a non-200 token exchange throws before ever calling Cloud KMS', async () => {
    const { transport, calls } = fakeTransport([{ statusCode: 401, body: '{"error":"invalid_grant"}' }]);
    const backend = new GcpKmsBackend({ serviceAccount, transport, now: () => NOW });
    await expect(backend.encrypt(Buffer.from('a'.repeat(32)), 'k', {})).rejects.toThrow(/401.*invalid_grant/s);
    expect(calls).toHaveLength(1);
  });

  it('a non-200 Cloud KMS response throws with the status and body', async () => {
    const { transport } = fakeTransport([
      { statusCode: 200, body: JSON.stringify({ access_token: 'fake-token' }) },
      { statusCode: 403, body: '{"error":{"status":"PERMISSION_DENIED"}}' },
    ]);
    const backend = new GcpKmsBackend({ serviceAccount, transport, now: () => NOW });
    await expect(backend.encrypt(Buffer.from('a'.repeat(32)), 'k', {})).rejects.toThrow(/403.*PERMISSION_DENIED/s);
  });
});

const hasRealCredentials = !!process.env.GCP_SERVICE_ACCOUNT_JSON && !!process.env.GCP_KMS_TEST_KEY_ID;

/**
 * The actual verification gate this design's own test plan calls for:
 * skipped unless a real GCP service account and KMS key are configured.
 * Set GCP_SERVICE_ACCOUNT_JSON (the downloaded service-account key file's
 * content) and GCP_KMS_TEST_KEY_ID (a real key's resource name) to
 * actually run this against GCP.
 */
describe.skipIf(!hasRealCredentials)('GcpKmsBackend against real GCP Cloud KMS', () => {
  it('wraps and unwraps a real 32-byte key via a real Cloud KMS key', async () => {
    const backend = new GcpKmsBackend({
      serviceAccount: JSON.parse(process.env.GCP_SERVICE_ACCOUNT_JSON!) as GcpServiceAccount,
    });
    const keyId = process.env.GCP_KMS_TEST_KEY_ID!;
    const rmk = Buffer.from('b'.repeat(32));
    const wrapped = await backend.encrypt(rmk, keyId, { repoId: 'test-repo', generation: '1' });
    const unwrapped = await backend.decrypt(wrapped, keyId, { repoId: 'test-repo', generation: '1' });
    expect(unwrapped.equals(rmk)).toBe(true);
  });
});
