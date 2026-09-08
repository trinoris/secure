// The real Fido2Authenticator transport (specs/securegit/06-key-provider-
// port.md's "yubikey-fido2" design) — talks to an actual FIDO2 authenticator
// via already-installed system tools (libfido2's `fido2-token`,
// `fido2-cred`, `fido2-assert`), not a native CTAP2/HID addon. Same
// reasoning as @trinoris/securelib-piv choosing pkcs11-tool/ykman over
// hand-rolled PC/SC: libfido2 is the mature, widely-used reference
// implementation of this protocol, and hand-rolling raw CTAP2 HID framing
// against real hardware would carry the same real risk this package's PIV
// sibling deliberately avoided. Zero npm dependencies — the only real
// dependency is the *system* having libfido2's CLI tools installed.
//
// Verified against a real, physical YubiKey 5C NFC (firmware 5.8.0) during
// development, manually, one command at a time (each needs a physical
// touch, so it can't be scripted end-to-end unattended the way PIV's ECDH
// verification could): MakeCredential with the hmac-secret extension
// requested, no PIN needed (this key's "Always Require User Verification"
// is off, so touch alone — no -v/uv — is sufficient); GetAssertion with the
// same credential and salt run twice, with two *different* challenges,
// produced the byte-identical hmac secret both times — proving the secret
// depends only on (credential, salt), never the per-call challenge, exactly
// what wrap()/unwrap() in fido2.ts need. A third GetAssertion with a
// *different* salt produced a different secret, confirming salt-sensitivity.

import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { YubikeyFido2Provider, type Fido2Authenticator } from '@trinoris/securelib/fido2';
import type { KeyProvider } from '@trinoris/securelib/provider';

/**
 * The subprocess boundary, injected — same reasoning as
 * @trinoris/securelib-piv's `RealPivCard.runner`. Resolves with stdout on
 * a zero exit; rejects on a nonzero one, matching `execFile`'s own
 * behaviour.
 */
export type Runner = (command: string, args: string[]) => Promise<{ stdout: string }>;

const execFile = promisify(execFileCb);
const defaultRunner: Runner = (command, args) => execFile(command, args);

/**
 * Not a real, resolvable domain — CLI-driven CTAP2 talks to the device
 * directly, with no browser-origin validation the way WebAuthn-in-browser
 * has, so this is purely a namespacing label for this tool's own
 * credentials, never sent anywhere it would need to mean anything else.
 */
const RP_ID = 'securegit.trinoris.local';
const USER_NAME = 'securegit';

export interface RealFido2AuthenticatorOptions {
  /** Explicit `/dev/hidrawN` path. Auto-discovered via `fido2-token -L` (first result) if omitted. */
  device?: string;
  runner?: Runner;
}

export class RealFido2Authenticator implements Fido2Authenticator {
  private readonly runner: Runner;
  private readonly explicitDevice: string | undefined;

  constructor(options: RealFido2AuthenticatorOptions = {}) {
    this.runner = options.runner ?? defaultRunner;
    this.explicitDevice = options.device;
  }

  async makeCredential(extensions: { hmacSecret: true }): Promise<{ credentialId: Buffer }> {
    void extensions; // the interface's only shape — hmac-secret (-h) is always requested below
    const device = await this.resolveDevice();
    const workDir = await mkdtemp(join(tmpdir(), 'securelib-fido2-'));
    try {
      const inputPath = join(workDir, 'cred_param');
      const clientDataHash = randomBytes(32);
      const userId = randomBytes(32);
      await writeFile(
        inputPath,
        [clientDataHash.toString('base64'), RP_ID, USER_NAME, userId.toString('base64')].join('\n') + '\n',
      );

      let stdout: string;
      try {
        ({ stdout } = await this.runner('fido2-cred', ['-M', '-h', '-i', inputPath, device]));
      } catch (e) {
        throw new Error('securelib-fido2: FIDO2 MakeCredential failed', { cause: e });
      }

      // fido2-cred -M -h output: clientDataHash, rpId, fmt, authData,
      // credId, sig, cert — credential id is line 5 (index 4).
      const credentialIdB64 = stdout.split('\n')[4];
      if (!credentialIdB64) {
        throw new Error('securelib-fido2: unexpected fido2-cred output shape (missing credential id)');
      }
      return { credentialId: Buffer.from(credentialIdB64, 'base64') };
    } finally {
      await rm(workDir, { recursive: true, force: true });
    }
  }

  async getAssertion(credentialId: Buffer, salt: Buffer): Promise<Buffer> {
    const device = await this.resolveDevice();
    const workDir = await mkdtemp(join(tmpdir(), 'securelib-fido2-'));
    try {
      const inputPath = join(workDir, 'assert_param');
      const clientDataHash = randomBytes(32);
      await writeFile(
        inputPath,
        [clientDataHash.toString('base64'), RP_ID, credentialId.toString('base64'), salt.toString('base64')].join('\n') + '\n',
      );

      let stdout: string;
      try {
        ({ stdout } = await this.runner('fido2-assert', ['-G', '-h', '-i', inputPath, device]));
      } catch (e) {
        // Deliberately opaque, same reasoning as every other provider's
        // unwrap()/ecdh(): never reveal whether the wrong physical key was
        // presented, the credential was unknown, or something else failed.
        throw new Error('securelib-fido2: FIDO2 GetAssertion failed', { cause: e });
      }

      // fido2-assert -G -h output (non-resident credential): clientDataHash,
      // rpId, authData, sig, hmac secret — hmac secret is line 5 (index 4).
      const hmacSecretB64 = stdout.split('\n')[4];
      if (!hmacSecretB64) {
        throw new Error('securelib-fido2: unexpected fido2-assert output shape (missing hmac secret)');
      }
      return Buffer.from(hmacSecretB64, 'base64');
    } finally {
      await rm(workDir, { recursive: true, force: true });
    }
  }

  private async resolveDevice(): Promise<string> {
    if (this.explicitDevice) return this.explicitDevice;
    const { stdout } = await this.runner('fido2-token', ['-L']);
    // fido2-token -L output: "/dev/hidraw1: vendor=0x1050, product=0x0407 (...)" per line.
    const line = stdout.split('\n').find((l) => l.includes(':'));
    if (!line) {
      throw new Error('securelib-fido2: no FIDO2 authenticator found (fido2-token -L reported none)');
    }
    return line.split(':')[0]!.trim();
  }
}

export interface Fido2ProviderConfig {
  device?: string;
}

/**
 * The contract `@trinoris/securelib`'s `registry.ts` (`loadProvider()`)
 * expects from every companion package — see
 * specs/securegit/06-key-provider-port.md's "Loading a provider package
 * without paying for it".
 */
export function createProvider(config: unknown): KeyProvider {
  const { device } = (config ?? {}) as Fido2ProviderConfig;
  const authenticator = new RealFido2Authenticator(device !== undefined ? { device } : {});
  return new YubikeyFido2Provider(authenticator);
}
