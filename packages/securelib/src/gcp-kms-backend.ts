// A real KmsBackend (kms-envelope.ts) for GCP Cloud KMS — no
// @google-cloud/kms dependency, same "zero new runtime dependencies"
// design as aws-kms-backend.ts. Two real HTTPS calls per operation: a
// service-account JWT (RS256, node:crypto) exchanged for an OAuth access
// token, then the actual Cloud KMS encrypt/decrypt REST call.
//
// Honest limit, same as aws-kms-backend.ts: not verified against a real
// GCP project — no credentials exist in this environment to test against.
// The JWT-bearer service-account flow and Cloud KMS's encrypt/decrypt REST
// shape are both implemented against Google's published API, structurally
// tested, not byte-verified against a live response. See
// specs/securegit/06-key-provider-port.md's kms-envelope design.

import { createSign } from 'node:crypto';
import { request as httpsRequest } from 'node:https';
import type { KmsBackend } from './kms-envelope.js';

export interface GcpServiceAccount {
  client_email: string;
  private_key: string;
  /** Present in a real downloaded service-account JSON key; unused here beyond documentation. */
  project_id?: string;
}

/** Injected so tests can capture requests without a real network call. */
export type HttpTransport = (opts: {
  host: string;
  path: string;
  method: 'GET' | 'POST';
  headers: Record<string, string>;
  body: string;
}) => Promise<{ statusCode: number; body: string }>;

export interface GcpKmsBackendOptions {
  serviceAccount: GcpServiceAccount;
  transport?: HttpTransport;
  /** Overridable for tests; a real cached token would go here too, out of scope for this first cut (matches AwsKmsBackend's own scope — see its header comment). */
  now?: () => Date;
}

const TOKEN_HOST = 'oauth2.googleapis.com';
const KMS_HOST = 'cloudkms.googleapis.com';
const SCOPE = 'https://www.googleapis.com/auth/cloudkms';

function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url');
}

/**
 * The JWT-bearer service-account assertion Google's OAuth token endpoint
 * exchanges for a real access token — RFC 7523. Exported for direct
 * testing of the signing step without a network call.
 */
export function signServiceAccountJwt(serviceAccount: GcpServiceAccount, now: Date): string {
  const header = { alg: 'RS256', typ: 'JWT' };
  const issuedAt = Math.floor(now.getTime() / 1000);
  const claims = {
    iss: serviceAccount.client_email,
    scope: SCOPE,
    aud: `https://${TOKEN_HOST}/token`,
    iat: issuedAt,
    exp: issuedAt + 3600,
  };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`;
  const signature = createSign('RSA-SHA256').update(signingInput).sign(serviceAccount.private_key);
  return `${signingInput}.${base64url(signature)}`;
}

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

export class GcpKmsBackend implements KmsBackend {
  private readonly transport: HttpTransport;
  private readonly now: () => Date;

  constructor(private readonly options: GcpKmsBackendOptions) {
    this.transport = options.transport ?? realTransport;
    this.now = options.now ?? (() => new Date());
  }

  async encrypt(rmkBytes: Buffer, keyId: string, context: Record<string, string>): Promise<Buffer> {
    const token = await this.getAccessToken();
    const body = JSON.stringify({
      plaintext: rmkBytes.toString('base64'),
      additionalAuthenticatedData: contextToAad(context),
    });
    const response = await this.call('POST', `/v1/${keyId}:encrypt`, token, body);
    const parsed = JSON.parse(response) as { ciphertext: string };
    return Buffer.from(parsed.ciphertext, 'base64');
  }

  async decrypt(wrappedRmkBytes: Buffer, keyId: string, context: Record<string, string>): Promise<Buffer> {
    const token = await this.getAccessToken();
    const body = JSON.stringify({
      ciphertext: wrappedRmkBytes.toString('base64'),
      additionalAuthenticatedData: contextToAad(context),
    });
    const response = await this.call('POST', `/v1/${keyId}:decrypt`, token, body);
    const parsed = JSON.parse(response) as { plaintext: string };
    return Buffer.from(parsed.plaintext, 'base64');
  }

  private async getAccessToken(): Promise<string> {
    const assertion = signServiceAccountJwt(this.options.serviceAccount, this.now());
    const body = `grant_type=${encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer')}&assertion=${assertion}`;
    const response = await this.transport({
      host: TOKEN_HOST,
      path: '/token',
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });
    if (response.statusCode !== 200) {
      throw new Error(`GCP OAuth token exchange failed: HTTP ${response.statusCode}: ${response.body}`);
    }
    const parsed = JSON.parse(response.body) as { access_token: string };
    return parsed.access_token;
  }

  private async call(method: 'GET' | 'POST', path: string, token: string, body: string): Promise<string> {
    const response = await this.transport({
      host: KMS_HOST,
      path,
      method,
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body,
    });
    if (response.statusCode !== 200) {
      throw new Error(`GCP Cloud KMS request failed: HTTP ${response.statusCode}: ${response.body}`);
    }
    return response.body;
  }
}

/**
 * GCP Cloud KMS's AAD field is raw bytes, not a structured context map like
 * AWS's encryption context — a deterministic JSON encoding (sorted keys, so
 * the same context always produces the same bytes regardless of insertion
 * order) is what actually gets bound into the ciphertext.
 */
function contextToAad(context: Record<string, string>): string {
  const sorted = Object.fromEntries(Object.entries(context).sort(([a], [b]) => a.localeCompare(b)));
  return Buffer.from(JSON.stringify(sorted), 'utf8').toString('base64');
}
