// The real PivCard transport (specs/securegit/06-key-provider-port.md's
// "yubikey-piv" design) — talks to an actual PIV smartcard's key-management
// slot via already-installed system tools (`ykman`, OpenSC's `pkcs11-tool`),
// not a native PC/SC addon. That's the second of the two real options the
// design spec named ("shelling out to an already-installed external tool
// ... and parsing its output"), chosen deliberately here: hand-rolling raw
// PC/SC APDU bytes (VERIFY PIN, GENERAL AUTHENTICATE dynamic authentication
// templates) against real, limited-retry hardware carries real risk of a
// malformed command burning a PIN or PUK try, where OpenSC's own mature PIV
// driver already gets both right. Zero npm dependencies either way — this
// package's only real dependency is the *system* having `ykman` and
// `pkcs11-tool` installed, an operational prerequisite documented in this
// package's README, not a supply-chain one.
//
// Verified against a real, physical YubiKey 5C NFC (firmware 5.8.0) during
// development: the shared secret this module's ecdh() produced via the
// card matched, byte for byte, an independent node:crypto computation of
// ECDH(ephemeral.privateKey, card.publicKey) using the same ephemeral key
// — genuine proof the on-card operation is correct, not merely that this
// code runs without error.

import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPublicKey } from 'node:crypto';
import { YubikeyPivProvider, type PivCard } from '@trinoris/securelib/piv';
import type { KeyProvider } from '@trinoris/securelib/provider';

/**
 * The subprocess boundary, injected rather than called directly — the
 * same reasoning `PivCard` itself is injected into `YubikeyPivProvider`
 * (piv.ts): lets tests exercise `RealPivCard`'s own logic (slot mapping,
 * SPKI encoding, temp-file lifecycle, error wrapping) against a fake
 * `ykman`/`pkcs11-tool`, without a physical key attached — real hardware
 * remains the thing `index.test.ts`'s `describe.skipIf` suite verifies
 * separately, not something every other test needs to touch too. Resolves
 * with stdout on a zero exit; rejects (matching `execFile`'s own real
 * behaviour) on a nonzero one.
 */
export type Runner = (command: string, args: string[]) => Promise<{ stdout: string }>;

const execFile = promisify(execFileCb);
const defaultRunner: Runner = (command, args) => execFile(command, args);

/**
 * OpenSC's own PIV driver convention, not this package's invention — the
 * numeric PKCS#11 object id each standard PIV slot maps to. Empirically
 * confirmed for `9d` against real hardware (`pkcs11-tool --list-objects
 * --type privkey` reported `ID: 03` for a key generated in slot 9d); the
 * rest follow the same documented OpenSC mapping.
 */
const OPENSC_SLOT_ID: Record<string, string> = {
  '9a': '01',
  '9c': '02',
  '9d': '03',
  '9e': '04',
};

export interface RealPivCardOptions {
  /** Path to OpenSC's PKCS#11 module. Debian/Ubuntu default shown; override for other distros. */
  pkcs11Module?: string;
  /** Defaults to a real `execFile`-backed runner; override in tests. */
  runner?: Runner;
}

const DEFAULT_MODULE = '/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so';

export class RealPivCard implements PivCard {
  private readonly module: string;
  private readonly runner: Runner;

  constructor(options: RealPivCardOptions = {}) {
    this.module = options.pkcs11Module ?? DEFAULT_MODULE;
    this.runner = options.runner ?? defaultRunner;
  }

  /**
   * Reads the slot's public key straight from the card's own metadata —
   * `ykman piv keys export` needs no PIN and no certificate to exist in the
   * slot, unlike the PKCS#11 route `ecdh()` below has to take.
   */
  async getPublicKey(slot: string): Promise<Buffer> {
    const { stdout } = await this.runner('ykman', ['piv', 'keys', 'export', slot, '-']);
    const keyObject = createPublicKey(stdout);
    const spkiDer = keyObject.export({ type: 'spki', format: 'der' });
    // The raw uncompressed EC point is the DER's final 65 bytes (0x04 ‖ X ‖ Y) —
    // SPKI's fixed prefix for a P-256 key is always the same 26-byte header.
    return spkiDer.subarray(spkiDer.length - 65);
  }

  /**
   * The private-key operation happens ON the card — only the resulting
   * shared secret ever comes back to this process. Goes through OpenSC's
   * PKCS#11 ECDH1-DERIVE mechanism rather than a raw APDU GENERAL
   * AUTHENTICATE this package hand-constructs itself, for the reason in
   * this file's header comment.
   *
   * Honest limit, not hidden: `pin` is passed as a `pkcs11-tool` CLI
   * argument, which is briefly visible to other local users via `ps` for
   * the duration of this one subprocess call — the same exposure every
   * CLI-driven smartcard tool (`ykman`, `pkcs11-tool` itself) already has.
   * Not different from this process's own command line already carrying
   * secrets transiently in other tools throughout this codebase; worth
   * knowing, not a regression this package introduces.
   */
  async ecdh(slot: string, peerPublicKey: Buffer, pin: string): Promise<Buffer> {
    const openscId = OPENSC_SLOT_ID[slot];
    if (!openscId) {
      throw new Error(`securelib-piv: unknown PIV slot '${slot}' — no OpenSC PKCS#11 object id mapping`);
    }

    const workDir = await mkdtemp(join(tmpdir(), 'securelib-piv-'));
    try {
      const peerSpkiPath = join(workDir, 'peer-pub.der');
      const outPath = join(workDir, 'shared-secret.bin');
      await writeFile(peerSpkiPath, encodeSpki(peerPublicKey));

      try {
        await this.runner('pkcs11-tool', [
          '--module', this.module,
          '--derive',
          '--id', openscId,
          '--input-file', peerSpkiPath,
          '--output-file', outPath,
          '--mechanism', 'ECDH1-DERIVE',
          '--login',
          '--pin', pin,
        ]);
      } catch (e) {
        // Deliberately opaque about *why* — same reasoning as
        // YubikeyPivProvider.unwrap()'s own opaque error above it: never
        // reveal whether the PIN, the slot, or something else was wrong.
        // pkcs11-tool's own stderr (wrong-PIN text, retry counts) is
        // logged by the caller's own diagnostics if needed, not smuggled
        // into this error's message.
        throw new Error('securelib-piv: PIV ECDH derive failed', { cause: e });
      }

      return await readFile(outPath);
    } finally {
      await rm(workDir, { recursive: true, force: true });
    }
  }
}

/** P-256 SubjectPublicKeyInfo DER, built from a raw 65-byte uncompressed point — the fixed shape `pkcs11-tool --input-file` requires. */
function encodeSpki(rawPoint: Buffer): Buffer {
  const keyObject = createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: rawPoint.subarray(1, 33).toString('base64url'), y: rawPoint.subarray(33, 65).toString('base64url') },
    format: 'jwk',
  });
  return keyObject.export({ type: 'spki', format: 'der' });
}

export interface PivProviderConfig {
  slot: string;
  pin: () => Promise<string> | string;
  pkcs11Module?: string;
}

/**
 * The contract `@trinoris/securelib`'s `registry.ts` (`loadProvider()`)
 * expects from every companion package — see
 * specs/securegit/06-key-provider-port.md's "Loading a provider package
 * without paying for it". Wraps a `RealPivCard` into a ready-to-use
 * `YubikeyPivProvider`, the same construction shape `piv.test.ts`'s fakes
 * already exercise, just with real hardware underneath.
 */
export function createProvider(config: unknown): KeyProvider {
  const { slot, pin, pkcs11Module } = config as PivProviderConfig;
  const card = new RealPivCard(pkcs11Module !== undefined ? { pkcs11Module } : {});
  return new YubikeyPivProvider(card, slot, pin);
}
