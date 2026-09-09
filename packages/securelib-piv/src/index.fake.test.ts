import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { writeFile, stat } from 'node:fs/promises';
import { RealPivCard, createProvider, type Runner } from './index.js';

/**
 * Covers RealPivCard's own logic (slot mapping, argv construction, SPKI
 * encoding, temp-file lifecycle, error wrapping) against a fake `ykman`/
 * `pkcs11-tool`, without a physical key attached — real hardware and the
 * actual on-card cryptography remain index.test.ts's job, verified there
 * once against a genuine YubiKey and not re-proven here. A fake success
 * path for ecdh() can't prove anything cryptographically meaningful (there
 * is no real ECDH happening), so this file's ecdh() coverage focuses on
 * argv shape, the error-wrapping contract, and cleanup — exactly the
 * things a fake CAN prove that real hardware alone doesn't make easy to
 * exercise (e.g. a rejection path, without spending a real PIN try).
 */

function fakeRunner(handler: (command: string, args: string[]) => Promise<{ stdout: string }>): {
  runner: Runner;
  calls: { command: string; args: string[] }[];
} {
  const calls: { command: string; args: string[] }[] = [];
  return {
    calls,
    runner: async (command, args) => {
      calls.push({ command, args });
      return handler(command, args);
    },
  };
}

function testPublicKeyPem(): string {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1', publicKeyEncoding: { type: 'spki', format: 'pem' } });
  return publicKey as unknown as string;
}

describe('RealPivCard.getPublicKey()', () => {
  it('calls `ykman piv keys export <slot> -` and returns the raw 65-byte uncompressed point', async () => {
    const pem = testPublicKeyPem();
    const { runner, calls } = fakeRunner(async () => ({ stdout: pem }));
    const card = new RealPivCard({ runner });

    const pub = await card.getPublicKey('9d');

    expect(calls).toEqual([{ command: 'ykman', args: ['piv', 'keys', 'export', '9d', '-'] }]);
    expect(pub.length).toBe(65);
    expect(pub[0]).toBe(0x04);
  });

  it('propagates a runner failure as-is — reading the public key needs no PIN, nothing sensitive to wrap', async () => {
    const { runner } = fakeRunner(async () => {
      throw new Error('ykman: no such slot');
    });
    const card = new RealPivCard({ runner });
    await expect(card.getPublicKey('9d')).rejects.toThrow('ykman: no such slot');
  });
});

describe('RealPivCard.ecdh()', () => {
  it('rejects an unknown slot before ever invoking the runner', async () => {
    const { runner, calls } = fakeRunner(async () => ({ stdout: '' }));
    const card = new RealPivCard({ runner });
    await expect(card.ecdh('9x', randomBytes(65), '123456')).rejects.toThrow(/unknown PIV slot/);
    expect(calls).toHaveLength(0);
  });

  it('builds the expected pkcs11-tool argv: module, mapped --id, ECDH1-DERIVE, --login, the given --pin', async () => {
    const { runner, calls } = fakeRunner(async (_command, args) => {
      const outIdx = args.indexOf('--output-file');
      await writeFile(args[outIdx + 1]!, Buffer.from('fake-shared-secret'));
      return { stdout: '' };
    });
    const card = new RealPivCard({ runner, pkcs11Module: '/custom/opensc-pkcs11.so' });

    // A real SPKI-encodable point — RealPivCard writes it to a temp file
    // before invoking the runner, so it must round-trip through node:crypto.
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const rawPoint = (publicKey.export({ type: 'spki', format: 'der' }) as Buffer).subarray(-65);

    await card.ecdh('9d', rawPoint, '123456');

    expect(calls).toHaveLength(1);
    expect(calls[0]!.command).toBe('pkcs11-tool');
    const args = calls[0]!.args;
    expect(args).toEqual(
      expect.arrayContaining([
        '--module', '/custom/opensc-pkcs11.so',
        '--derive',
        '--id', '03', // 9d -> OpenSC's own object id 03, per the mapping confirmed against real hardware
        '--mechanism', 'ECDH1-DERIVE',
        '--login',
        '--pin', '123456',
      ]),
    );
  });

  it('returns exactly the bytes pkcs11-tool wrote to --output-file', async () => {
    const secret = randomBytes(32);
    const { runner } = fakeRunner(async (_command, args) => {
      const outIdx = args.indexOf('--output-file');
      await writeFile(args[outIdx + 1]!, secret);
      return { stdout: '' };
    });
    const card = new RealPivCard({ runner });
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const rawPoint = (publicKey.export({ type: 'spki', format: 'der' }) as Buffer).subarray(-65);

    const result = await card.ecdh('9d', rawPoint, '123456');
    expect(result.equals(secret)).toBe(true);
  });

  it('a runner rejection (wrong PIN, card removed, ...) is wrapped, not surfaced raw', async () => {
    const { runner } = fakeRunner(async () => {
      throw new Error('pkcs11-tool: Login failed: CKR_PIN_INCORRECT');
    });
    const card = new RealPivCard({ runner });
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const rawPoint = (publicKey.export({ type: 'spki', format: 'der' }) as Buffer).subarray(-65);

    const failure = card.ecdh('9d', rawPoint, 'wrong-pin');
    await expect(failure).rejects.toThrow('securelib-piv: PIV ECDH derive failed');
    await expect(failure).rejects.toMatchObject({ cause: expect.objectContaining({ message: expect.stringContaining('CKR_PIN_INCORRECT') }) });
  });

  it('cleans up its temp working directory whether the runner succeeds or fails', async () => {
    let capturedDir = '';
    const { runner } = fakeRunner(async (_command, args) => {
      const outIdx = args.indexOf('--output-file');
      capturedDir = args[outIdx + 1]!.split('/').slice(0, -1).join('/');
      await writeFile(args[outIdx + 1]!, Buffer.from('x'));
      return { stdout: '' };
    });
    const card = new RealPivCard({ runner });
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const rawPoint = (publicKey.export({ type: 'spki', format: 'der' }) as Buffer).subarray(-65);

    await card.ecdh('9d', rawPoint, '123456');
    await expect(stat(capturedDir)).rejects.toThrow();
  });
});

describe('createProvider()', () => {
  // registry.ts's loadProvider() entry point (06-key-provider-port.md,
  // "Loading a provider package without paying for it") — the contract is
  // "construct a usable KeyProvider from a plain config object," which
  // needs no I/O and no real hardware to verify.

  it('builds a KeyProvider with the default id "yubikey-piv"', () => {
    const provider = createProvider({ slot: '9d', pin: () => '123456' });
    expect(provider.id).toBe('yubikey-piv');
    expect(provider.describe().id).toBe('yubikey-piv');
  });

  it('accepts a config with no pkcs11Module', () => {
    expect(() => createProvider({ slot: '9d', pin: () => '123456' })).not.toThrow();
  });

  it('accepts a config with an explicit pkcs11Module', () => {
    expect(() =>
      createProvider({ slot: '9d', pin: () => '123456', pkcs11Module: '/usr/lib/opensc-pkcs11.so' }),
    ).not.toThrow();
  });
});
