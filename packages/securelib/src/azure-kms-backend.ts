// A real KmsBackend (kms-envelope.ts) for Azure Key Vault — no
// @azure/keyvault-keys dependency, same "zero new runtime dependencies"
// design as aws-kms-backend.ts/gcp-kms-backend.ts. Two real HTTPS calls per
// operation: an Azure AD client-credentials token exchange, then the
// key's encrypt/decrypt REST call.
//
// Genuinely different shape from AWS/GCP, confirmed against Microsoft's
// own REST API reference (Key Vault "encrypt"/"decrypt" operations,
// KeyOperationsParameters/KeyOperationResult): AES-GCM (A256GCM) requires
// the CALLER to supply a fresh IV — Azure does not generate one — and
// returns the GCM auth tag as a separate field rather than appending it to
// the ciphertext. This backend generates a random 12-byte IV per wrap
// (never reused, same discipline as every other nonce in this codebase)
// and packs `iv ‖ tag ‖ ciphertext` into the single opaque Buffer
// KmsBackend's interface expects, so kms-envelope.ts's own design never
// has to know any of this.
//
// Real prerequisite, not this file's problem to solve: A256GCM on a
// symmetric key needs an Azure Key Vault **Managed HSM** with an
// oct-HSM key — standard Key Vault historically supports only RSA/EC
// keys, not symmetric ones.
//
// Honest limit, same as the other two backends: not verified against a
// real Azure tenant — no credentials exist in this environment to test
// against.

import { randomBytes } from 'node:crypto';
import { request as httpsRequest } from 'node:https';
import type { KmsBackend } from './kms-envelope.js';

export interface AzureCredentials {
  tenantId: string;
  clientId: string;
  clientSecret: string;
}

export type HttpTransport = (opts: {
  host: string;
  path: string;
  method: 'POST';
  headers: Record<string, string>;
  body: string;
}) => Promise<{ statusCode: number; body: string }>;

export interface AzureKmsBackendOptions {
  credentials: AzureCredentials;
  transport?: HttpTransport;
}

/**
 * `keyId` here is Azure's own key identifier shape — the full `kid` URL
 * Key Vault itself returns, e.g.
 * `https://myvault.vault.azure.net/keys/mykey/abc123def456` — not a
 * separately-configured vault/key/version. This is what
 * `KmsEnvelopeProvider` persists into `state.keyId` (05-key-hierarchy.md),
 * so it must be the actual source of truth for which key gets used, the
 * same way an AWS ARN or GCP resource name already is for their backends
 * — never something the backend quietly ignores in favor of its own
 * constructor config.
 */
function parseKeyId(keyId: string): { host: string; keyName: string; keyVersion: string } {
  const url = new URL(keyId);
  const parts = url.pathname.split('/').filter(Boolean); // ['keys', name, version]
  if (parts.length !== 3 || parts[0] !== 'keys') {
    throw new Error(`azure kms: keyId is not a valid Key Vault key identifier: ${keyId}`);
  }
  return { host: url.host, keyName: parts[1]!, keyVersion: parts[2]! };
}

const API_VERSION = '7.4';
const ALG = 'A256GCM';
const IV_LEN = 12;
const TAG_LEN = 16;

const realTransport: HttpTransport = (opts) =>
  new Promise((resolve, reject) => {
    const req = httpsRequest(
      {
        host: opts.host,
        method: opts.method,
        path: opts.path,
        headers: { ...opts.headers, 'Content-Length': Buffer.byteLength(opts.body) },
      },
      (res) => {
        let data = '';
        res.on('data', (chunk: Buffer) => {
          data += chunk.toString('utf8');
        });
        res.on('end', () => resolve({ statusCode: res.statusCode ?? 0, body: data }));
      },
    );
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });

export class AzureKmsBackend implements KmsBackend {
  private readonly transport: HttpTransport;

  constructor(private readonly options: AzureKmsBackendOptions) {
    this.transport = options.transport ?? realTransport;
  }

  async encrypt(rmkBytes: Buffer, keyId: string, context: Record<string, string>): Promise<Buffer> {
    const key = parseKeyId(keyId);
    const token = await this.getAccessToken();
    const iv = randomBytes(IV_LEN);
    const body = JSON.stringify({
      alg: ALG,
      value: rmkBytes.toString('base64url'),
      iv: iv.toString('base64url'),
      aad: contextToAad(context).toString('base64url'),
    });
    const response = await this.call(key, 'encrypt', token, body);
    const parsed = JSON.parse(response) as { value: string; tag: string };
    const ciphertext = Buffer.from(parsed.value, 'base64url');
    const tag = Buffer.from(parsed.tag, 'base64url');
    return Buffer.concat([iv, tag, ciphertext]);
  }

  async decrypt(wrappedRmkBytes: Buffer, keyId: string, context: Record<string, string>): Promise<Buffer> {
    if (wrappedRmkBytes.length < IV_LEN + TAG_LEN) {
      throw new Error('azure kms: wrapped value is too short to contain iv+tag');
    }
    const key = parseKeyId(keyId);
    const iv = wrappedRmkBytes.subarray(0, IV_LEN);
    const tag = wrappedRmkBytes.subarray(IV_LEN, IV_LEN + TAG_LEN);
    const ciphertext = wrappedRmkBytes.subarray(IV_LEN + TAG_LEN);
    const token = await this.getAccessToken();
    const body = JSON.stringify({
      alg: ALG,
      value: ciphertext.toString('base64url'),
      iv: iv.toString('base64url'),
      tag: tag.toString('base64url'),
      aad: contextToAad(context).toString('base64url'),
    });
    const response = await this.call(key, 'decrypt', token, body);
    const parsed = JSON.parse(response) as { value: string };
    return Buffer.from(parsed.value, 'base64url');
  }

  private async getAccessToken(): Promise<string> {
    const body =
      `grant_type=client_credentials&client_id=${encodeURIComponent(this.options.credentials.clientId)}` +
      `&client_secret=${encodeURIComponent(this.options.credentials.clientSecret)}` +
      `&scope=${encodeURIComponent('https://vault.azure.net/.default')}`;
    const response = await this.transport({
      host: 'login.microsoftonline.com',
      path: `/${this.options.credentials.tenantId}/oauth2/v2.0/token`,
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });
    if (response.statusCode !== 200) {
      throw new Error(`Azure AD token exchange failed: HTTP ${response.statusCode}: ${response.body}`);
    }
    const parsed = JSON.parse(response.body) as { access_token: string };
    return parsed.access_token;
  }

  private async call(
    key: { host: string; keyName: string; keyVersion: string },
    operation: 'encrypt' | 'decrypt',
    token: string,
    body: string,
  ): Promise<string> {
    const path = `/keys/${key.keyName}/${key.keyVersion}/${operation}?api-version=${API_VERSION}`;
    const response = await this.transport({
      host: key.host,
      path,
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body,
    });
    if (response.statusCode !== 200) {
      throw new Error(`Azure Key Vault request failed: HTTP ${response.statusCode}: ${response.body}`);
    }
    return response.body;
  }
}

/** Same deterministic-JSON-over-sorted-keys AAD encoding as gcp-kms-backend.ts. */
function contextToAad(context: Record<string, string>): Buffer {
  const sorted = Object.fromEntries(Object.entries(context).sort(([a], [b]) => a.localeCompare(b)));
  return Buffer.from(JSON.stringify(sorted), 'utf8');
}
