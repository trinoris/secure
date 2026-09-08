import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  signKmsRequest,
  AwsKmsBackend,
  resolveAwsCredentials,
  resolveAwsRegion,
  type HttpTransport,
} from './aws-kms-backend.js';

const CREDENTIALS = { accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' };
const NOW = new Date('2026-08-30T12:36:00.000Z');

/**
 * These tests verify the SigV4 orchestration is well-formed, deterministic,
 * and sensitive to every input it's supposed to be — NOT that it's
 * byte-exact against a real AWS-computed signature. This project has no
 * AWS credentials to test against; the actual verification gate is the
 * real-credentials-gated integration test below, skipped here. See
 * aws-kms-backend.ts's own header comment and
 * specs/securegit/06-key-provider-port.md's kms-envelope design note for
 * why this is still an honest, shippable first cut.
 */
describe('signKmsRequest()', () => {
  it('produces an Authorization header matching AWS\'s documented format exactly', () => {
    const signed = signKmsRequest({
      region: 'us-east-1',
      credentials: CREDENTIALS,
      target: 'TrentService.Encrypt',
      body: '{}',
      now: NOW,
    });
    expect(signed.headers.Authorization).toMatch(
      /^AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE\/20260830\/us-east-1\/kms\/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=[0-9a-f]{64}$/,
    );
  });

  it('x-amz-date matches the given clock, in AWS\'s required basic ISO 8601 format', () => {
    const signed = signKmsRequest({ region: 'us-east-1', credentials: CREDENTIALS, target: 'T', body: '{}', now: NOW });
    expect(signed.headers['x-amz-date']).toBe('20260830T123600Z');
  });

  it('host is derived from the region', () => {
    const signed = signKmsRequest({ region: 'eu-west-1', credentials: CREDENTIALS, target: 'T', body: '{}', now: NOW });
    expect(signed.host).toBe('kms.eu-west-1.amazonaws.com');
  });

  it('is deterministic — identical inputs (including the same clock) produce the identical signature', () => {
    const a = signKmsRequest({ region: 'us-east-1', credentials: CREDENTIALS, target: 'T', body: '{"a":1}', now: NOW });
    const b = signKmsRequest({ region: 'us-east-1', credentials: CREDENTIALS, target: 'T', body: '{"a":1}', now: NOW });
    expect(a.headers.Authorization).toBe(b.headers.Authorization);
  });

  it('the signature changes when the body changes — the payload is bound into it', () => {
    const a = signKmsRequest({ region: 'us-east-1', credentials: CREDENTIALS, target: 'T', body: '{"a":1}', now: NOW });
    const b = signKmsRequest({ region: 'us-east-1', credentials: CREDENTIALS, target: 'T', body: '{"a":2}', now: NOW });
    expect(a.headers.Authorization).not.toBe(b.headers.Authorization);
  });

  it('the signature changes when the secret key changes', () => {
    const a = signKmsRequest({ region: 'us-east-1', credentials: CREDENTIALS, target: 'T', body: '{}', now: NOW });
    const b = signKmsRequest({
      region: 'us-east-1',
      credentials: { ...CREDENTIALS, secretAccessKey: 'a-different-secret-key-entirely' },
      target: 'T',
      body: '{}',
      now: NOW,
    });
    expect(a.headers.Authorization).not.toBe(b.headers.Authorization);
  });

  it('the signature changes when the timestamp changes', () => {
    const a = signKmsRequest({ region: 'us-east-1', credentials: CREDENTIALS, target: 'T', body: '{}', now: NOW });
    const b = signKmsRequest({
      region: 'us-east-1',
      credentials: CREDENTIALS,
      target: 'T',
      body: '{}',
      now: new Date(NOW.getTime() + 1000),
    });
    expect(a.headers.Authorization).not.toBe(b.headers.Authorization);
  });

  it('adds x-amz-security-token to the signed headers when a session token is given', () => {
    const signed = signKmsRequest({
      region: 'us-east-1',
      credentials: { ...CREDENTIALS, sessionToken: 'a-session-token' },
      target: 'T',
      body: '{}',
      now: NOW,
    });
    expect(signed.headers.Authorization).toContain(
      'SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target',
    );
    expect(signed.headers['x-amz-security-token']).toBe('a-session-token');
  });
});

function fakeTransport(response: { statusCode: number; body: string }): {
  transport: HttpTransport;
  calls: { host: string; headers: Record<string, string>; body: string }[];
} {
  const calls: { host: string; headers: Record<string, string>; body: string }[] = [];
  return {
    calls,
    transport: async (opts) => {
      calls.push(opts);
      return response;
    },
  };
}

describe('AwsKmsBackend', () => {
  it('encrypt() sends a well-formed TrentService.Encrypt request and decodes the response', async () => {
    const ciphertext = Buffer.from('fake-ciphertext-bytes');
    const { transport, calls } = fakeTransport({
      statusCode: 200,
      body: JSON.stringify({ CiphertextBlob: ciphertext.toString('base64'), KeyId: 'key-1' }),
    });
    const backend = new AwsKmsBackend({ region: 'us-east-1', credentials: CREDENTIALS, transport });
    const rmk = Buffer.from('a'.repeat(32));
    const result = await backend.encrypt(rmk, 'key-1', { repoId: 'repo-a', generation: '1' });

    expect(result.equals(ciphertext)).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.headers['x-amz-target']).toBe('TrentService.Encrypt');
    expect(calls[0]!.headers.Authorization).toMatch(/^AWS4-HMAC-SHA256 /);
    const sentBody = JSON.parse(calls[0]!.body) as Record<string, unknown>;
    expect(sentBody.KeyId).toBe('key-1');
    expect(sentBody.Plaintext).toBe(rmk.toString('base64'));
    expect(sentBody.EncryptionContext).toEqual({ repoId: 'repo-a', generation: '1' });
  });

  it('decrypt() sends a well-formed TrentService.Decrypt request and decodes the response', async () => {
    const plaintext = Buffer.from('a'.repeat(32));
    const { transport, calls } = fakeTransport({
      statusCode: 200,
      body: JSON.stringify({ Plaintext: plaintext.toString('base64'), KeyId: 'key-1' }),
    });
    const backend = new AwsKmsBackend({ region: 'us-east-1', credentials: CREDENTIALS, transport });
    const result = await backend.decrypt(Buffer.from('ciphertext'), 'key-1', { repoId: 'repo-a', generation: '1' });

    expect(result.equals(plaintext)).toBe(true);
    expect(calls[0]!.headers['x-amz-target']).toBe('TrentService.Decrypt');
    const sentBody = JSON.parse(calls[0]!.body) as Record<string, unknown>;
    expect(sentBody.CiphertextBlob).toBe(Buffer.from('ciphertext').toString('base64'));
  });

  it('a non-200 response throws with the status and body, not silently', async () => {
    const { transport } = fakeTransport({ statusCode: 403, body: '{"__type":"AccessDeniedException"}' });
    const backend = new AwsKmsBackend({ region: 'us-east-1', credentials: CREDENTIALS, transport });
    await expect(backend.encrypt(Buffer.from('a'.repeat(32)), 'key-1', {})).rejects.toThrow(
      /403.*AccessDeniedException/s,
    );
  });
});

const AWS_ENV_KEYS = [
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_SESSION_TOKEN',
  'AWS_PROFILE',
  'AWS_SHARED_CREDENTIALS_FILE',
  'AWS_CONFIG_FILE',
  'AWS_REGION',
  'AWS_DEFAULT_REGION',
] as const;

describe('resolveAwsCredentials() / resolveAwsRegion()', () => {
  let savedEnv: Record<string, string | undefined>;
  let workDir: string;

  beforeEach(async () => {
    savedEnv = Object.fromEntries(AWS_ENV_KEYS.map((k) => [k, process.env[k]]));
    for (const k of AWS_ENV_KEYS) delete process.env[k];
    workDir = await mkdtemp(join(tmpdir(), 'aws-kms-cred-test-'));
  });

  afterEach(async () => {
    for (const k of AWS_ENV_KEYS) {
      if (savedEnv[k] === undefined) delete process.env[k];
      else process.env[k] = savedEnv[k];
    }
    await rm(workDir, { recursive: true, force: true });
  });

  it('prefers explicit env vars over any profile file, and never even reads one when they\'re set', async () => {
    process.env.AWS_ACCESS_KEY_ID = 'AKIAENVEXAMPLE';
    process.env.AWS_SECRET_ACCESS_KEY = 'env-secret';
    process.env.AWS_SESSION_TOKEN = 'env-session-token';
    // Points at a file that doesn't exist — proves env vars short-circuit
    // before any file read is even attempted.
    process.env.AWS_SHARED_CREDENTIALS_FILE = join(workDir, 'does-not-exist');

    const creds = await resolveAwsCredentials();
    expect(creds).toEqual({
      accessKeyId: 'AKIAENVEXAMPLE',
      secretAccessKey: 'env-secret',
      sessionToken: 'env-session-token',
    });
  });

  it('falls back to the [default] profile in the credentials file when no env vars are set', async () => {
    const credsPath = join(workDir, 'credentials');
    await writeFile(
      credsPath,
      '[default]\naws_access_key_id = AKIADEFAULT\naws_secret_access_key = default-secret\n',
    );
    process.env.AWS_SHARED_CREDENTIALS_FILE = credsPath;

    const creds = await resolveAwsCredentials();
    expect(creds).toEqual({ accessKeyId: 'AKIADEFAULT', secretAccessKey: 'default-secret' });
  });

  it('AWS_PROFILE selects a named section instead of [default]', async () => {
    const credsPath = join(workDir, 'credentials');
    await writeFile(
      credsPath,
      '[default]\naws_access_key_id = AKIADEFAULT\naws_secret_access_key = default-secret\n\n' +
        '[work]\naws_access_key_id = AKIAWORK\naws_secret_access_key = work-secret\naws_session_token = work-token\n',
    );
    process.env.AWS_SHARED_CREDENTIALS_FILE = credsPath;
    process.env.AWS_PROFILE = 'work';

    const creds = await resolveAwsCredentials();
    expect(creds).toEqual({ accessKeyId: 'AKIAWORK', secretAccessKey: 'work-secret', sessionToken: 'work-token' });
  });

  it('throws an actionable error when neither env vars nor a usable profile section exist', async () => {
    process.env.AWS_SHARED_CREDENTIALS_FILE = join(workDir, 'does-not-exist');
    await expect(resolveAwsCredentials()).rejects.toThrow(/could not resolve AWS credentials/);
  });

  it('resolveAwsRegion(): AWS_REGION wins over AWS_DEFAULT_REGION and the config file', async () => {
    process.env.AWS_REGION = 'eu-west-1';
    process.env.AWS_DEFAULT_REGION = 'us-east-1';
    expect(await resolveAwsRegion()).toBe('eu-west-1');
  });

  it('resolveAwsRegion(): falls back to [default] in the config file', async () => {
    const configPath = join(workDir, 'config');
    await writeFile(configPath, '[default]\nregion = ap-southeast-2\n');
    process.env.AWS_CONFIG_FILE = configPath;
    expect(await resolveAwsRegion()).toBe('ap-southeast-2');
  });

  it('resolveAwsRegion(): a named profile is looked up as [profile <name>], not [<name>] — the real ~/.aws/config asymmetry', async () => {
    const configPath = join(workDir, 'config');
    await writeFile(configPath, '[default]\nregion = us-east-1\n\n[profile work]\nregion = eu-central-1\n');
    process.env.AWS_CONFIG_FILE = configPath;
    process.env.AWS_PROFILE = 'work';
    expect(await resolveAwsRegion()).toBe('eu-central-1');
  });

  it('resolveAwsRegion(): returns undefined, never a hardcoded default, when nothing resolves', async () => {
    process.env.AWS_CONFIG_FILE = join(workDir, 'does-not-exist');
    expect(await resolveAwsRegion()).toBeUndefined();
  });

  it('AwsKmsBackend.fromEnvironment() resolves both credentials and region and builds a working backend', async () => {
    process.env.AWS_ACCESS_KEY_ID = 'AKIAENVEXAMPLE';
    process.env.AWS_SECRET_ACCESS_KEY = 'env-secret';
    process.env.AWS_REGION = 'eu-west-1';
    const backend = await AwsKmsBackend.fromEnvironment();
    expect(backend).toBeInstanceOf(AwsKmsBackend);
  });

  it('AwsKmsBackend.fromEnvironment() throws an actionable error when region cannot be resolved', async () => {
    process.env.AWS_ACCESS_KEY_ID = 'AKIAENVEXAMPLE';
    process.env.AWS_SECRET_ACCESS_KEY = 'env-secret';
    process.env.AWS_CONFIG_FILE = join(workDir, 'does-not-exist');
    await expect(AwsKmsBackend.fromEnvironment()).rejects.toThrow(/could not resolve an AWS region/);
  });
});

/**
 * The actual verification gate this design's own test plan calls for:
 * skipped unless real AWS credentials are present in the environment
 * (aws-vault-style, never committed). Set AWS_ACCESS_KEY_ID,
 * AWS_SECRET_ACCESS_KEY, AWS_REGION, and AWS_KMS_TEST_KEY_ID (a real KMS
 * key's ARN or id you control) to actually run this against AWS.
 */
const hasRealCredentials =
  !!process.env.AWS_ACCESS_KEY_ID && !!process.env.AWS_SECRET_ACCESS_KEY && !!process.env.AWS_KMS_TEST_KEY_ID;

describe.skipIf(!hasRealCredentials)('AwsKmsBackend against real AWS KMS', () => {
  it('wraps and unwraps a real 32-byte key via a real KMS key', async () => {
    const backend = new AwsKmsBackend({
      region: process.env.AWS_REGION ?? 'us-east-1',
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
        ...(process.env.AWS_SESSION_TOKEN ? { sessionToken: process.env.AWS_SESSION_TOKEN } : {}),
      },
    });
    const keyId = process.env.AWS_KMS_TEST_KEY_ID!;
    const rmk = Buffer.from('b'.repeat(32));
    const wrapped = await backend.encrypt(rmk, keyId, { repoId: 'test-repo', generation: '1' });
    const unwrapped = await backend.decrypt(wrapped, keyId, { repoId: 'test-repo', generation: '1' });
    expect(unwrapped.equals(rmk)).toBe(true);
  });
});
