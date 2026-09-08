// A real KmsBackend (kms-envelope.ts) for AWS KMS — one signed HTTPS
// request each way, built from node:crypto + node:https alone, no
// @aws-sdk/client-kms dependency. Implements AWS Signature Version 4
// exactly as AWS's own published algorithm specifies:
// https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
//
// Honest limit, stated plainly: the SigV4 *orchestration* below (canonical
// request construction, the HMAC signing-key derivation chain, request/
// response shape) has not been verified against a real AWS KMS endpoint in
// this environment — there are no AWS credentials here to test against.
// The cryptographic primitives it calls (SHA-256, HMAC-SHA256) are
// node:crypto's own, not reimplemented here, so a bug in this file causes
// AWS to reject the request (a functional failure, loud and immediate),
// not a silent confidentiality problem — wrong signatures don't decrypt
// anything. See kms-envelope.ts's design note in
// specs/securegit/06-key-provider-port.md for why this is still safe to
// ship as a first cut: verify against a real AWS account (or the
// credentials-gated integration test below) before relying on it.

import { createHash, createHmac } from 'node:crypto';
import { request as httpsRequest } from 'node:https';
import type { KmsBackend } from './kms-envelope.js';

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

/** Injected so tests can capture the signed request without a real network call. */
export type HttpTransport = (opts: {
  host: string;
  headers: Record<string, string>;
  body: string;
}) => Promise<{ statusCode: number; body: string }>;

export interface AwsKmsBackendOptions {
  region: string;
  credentials: AwsCredentials;
  transport?: HttpTransport;
}

const SERVICE = 'kms';
const ALGORITHM = 'AWS4-HMAC-SHA256';

function sha256Hex(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

function hmac(key: Buffer, data: string): Buffer {
  return createHmac('sha256', key).update(data, 'utf8').digest();
}

/** `YYYYMMDDTHHMMSSZ` / `YYYYMMDD`, per AWS's required ISO 8601 basic format. */
function amzTimestamp(now: Date): { amzDate: string; dateStamp: string } {
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  return { amzDate, dateStamp: amzDate.slice(0, 8) };
}

function deriveSigningKey(secretAccessKey: string, dateStamp: string, region: string): Buffer {
  const kDate = hmac(Buffer.from('AWS4' + secretAccessKey, 'utf8'), dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, SERVICE);
  return hmac(kService, 'aws4_request');
}

export interface SignedRequest {
  host: string;
  headers: Record<string, string>;
  body: string;
}

/**
 * Builds a fully-signed AWS KMS JSON-1.1 POST request. Exported (not just
 * used internally) so its output — the canonical-request/signing-key
 * chain the algorithm actually hinges on — is directly unit-testable
 * without a network call.
 */
export function signKmsRequest(opts: {
  region: string;
  credentials: AwsCredentials;
  target: string; // e.g. "TrentService.Encrypt"
  body: string;
  now?: Date;
}): SignedRequest {
  const host = `kms.${opts.region}.amazonaws.com`;
  const { amzDate, dateStamp } = amzTimestamp(opts.now ?? new Date());
  const payloadHash = sha256Hex(opts.body);

  const headersToSign: Record<string, string> = {
    host,
    'content-type': 'application/x-amz-json-1.1',
    'x-amz-date': amzDate,
    'x-amz-target': opts.target,
    ...(opts.credentials.sessionToken ? { 'x-amz-security-token': opts.credentials.sessionToken } : {}),
  };

  // AWS requires header names lowercase and sorted in the canonical form.
  const signedHeaderNames = Object.keys(headersToSign).sort();
  const canonicalHeaders = signedHeaderNames.map((name) => `${name}:${headersToSign[name]!.trim()}\n`).join('');
  const signedHeaders = signedHeaderNames.join(';');

  // POST /, no query string — every KMS action is one JSON body to "/".
  const canonicalRequest = ['POST', '/', '', canonicalHeaders, signedHeaders, payloadHash].join('\n');

  const credentialScope = `${dateStamp}/${opts.region}/${SERVICE}/aws4_request`;
  const stringToSign = [ALGORITHM, amzDate, credentialScope, sha256Hex(canonicalRequest)].join('\n');

  const signingKey = deriveSigningKey(opts.credentials.secretAccessKey, dateStamp, opts.region);
  const signature = createHmac('sha256', signingKey).update(stringToSign, 'utf8').digest('hex');

  const authorization =
    `${ALGORITHM} Credential=${opts.credentials.accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return {
    host,
    headers: { ...headersToSign, Authorization: authorization },
    body: opts.body,
  };
}

const realTransport: HttpTransport = (opts) =>
  new Promise((resolve, reject) => {
    const req = httpsRequest(
      {
        host: opts.host,
        method: 'POST',
        path: '/',
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
    req.write(opts.body);
    req.end();
  });

export class AwsKmsBackend implements KmsBackend {
  private readonly transport: HttpTransport;

  constructor(private readonly options: AwsKmsBackendOptions) {
    this.transport = options.transport ?? realTransport;
  }

  async encrypt(rmkBytes: Buffer, keyId: string, context: Record<string, string>): Promise<Buffer> {
    const body = JSON.stringify({ KeyId: keyId, Plaintext: rmkBytes.toString('base64'), EncryptionContext: context });
    const response = await this.call('TrentService.Encrypt', body);
    const parsed = JSON.parse(response) as { CiphertextBlob: string };
    return Buffer.from(parsed.CiphertextBlob, 'base64');
  }

  async decrypt(wrappedRmkBytes: Buffer, keyId: string, context: Record<string, string>): Promise<Buffer> {
    const body = JSON.stringify({
      CiphertextBlob: wrappedRmkBytes.toString('base64'),
      KeyId: keyId,
      EncryptionContext: context,
    });
    const response = await this.call('TrentService.Decrypt', body);
    const parsed = JSON.parse(response) as { Plaintext: string };
    return Buffer.from(parsed.Plaintext, 'base64');
  }

  private async call(target: string, body: string): Promise<string> {
    const signed = signKmsRequest({
      region: this.options.region,
      credentials: this.options.credentials,
      target,
      body,
    });
    const response = await this.transport({ host: signed.host, headers: signed.headers, body: signed.body });
    if (response.statusCode !== 200) {
      throw new Error(`AWS KMS request failed: HTTP ${response.statusCode}: ${response.body}`);
    }
    return response.body;
  }
}
