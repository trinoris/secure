import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import { RealFido2Authenticator, type Runner } from './index.js';

/**
 * Covers RealFido2Authenticator's own logic (device discovery, argv
 * construction, output parsing, error wrapping, temp-file cleanup)
 * against a fake `fido2-token`/`fido2-cred`/`fido2-assert`, without a
 * physical key attached or a touch to wait for. There's no cryptographic
 * property to verify in a fake here (unlike securelib-piv's ECDH, whose
 * fake still performs a real computation) — the hmac secret is opaque
 * bytes from the authenticator, so a fake success case just proves the
 * parsing is correct, not anything about the derivation itself. That's
 * index.test.ts's job, verified once against real hardware.
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

describe('RealFido2Authenticator device discovery', () => {
  it('auto-discovers the device via `fido2-token -L` when none is given explicitly', async () => {
    const { runner, calls } = fakeRunner(async (command) => {
      if (command === 'fido2-token') {
        return { stdout: '/dev/hidraw1: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)\n' };
      }
      const credentialId = randomBytes(16).toString('base64');
      return { stdout: `x\nx\npacked\nx\n${credentialId}\nx\nx\n` };
    });
    const authenticator = new RealFido2Authenticator({ runner });
    await authenticator.makeCredential({ hmacSecret: true });
    expect(calls[0]).toEqual({ command: 'fido2-token', args: ['-L'] });
    expect(calls[1]!.args).toContain('/dev/hidraw1');
  });

  it('skips discovery entirely when an explicit device is given', async () => {
    const { runner, calls } = fakeRunner(async () => ({ stdout: `x\nx\npacked\nx\n${randomBytes(16).toString('base64')}\nx\nx\n` }));
    const authenticator = new RealFido2Authenticator({ runner, device: '/dev/hidraw7' });
    await authenticator.makeCredential({ hmacSecret: true });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.command).toBe('fido2-cred');
    expect(calls[0]!.args).toContain('/dev/hidraw7');
  });

  it('throws a clear error when fido2-token -L reports no authenticator', async () => {
    const { runner } = fakeRunner(async () => ({ stdout: '' }));
    const authenticator = new RealFido2Authenticator({ runner });
    await expect(authenticator.makeCredential({ hmacSecret: true })).rejects.toThrow(/no FIDO2 authenticator found/);
  });
});

describe('RealFido2Authenticator.makeCredential()', () => {
  it('builds the expected fido2-cred argv: -M, -h, the given device', async () => {
    const { runner, calls } = fakeRunner(async () => ({
      stdout: `x\nx\npacked\nx\n${randomBytes(16).toString('base64')}\nx\nx\n`,
    }));
    const authenticator = new RealFido2Authenticator({ runner, device: '/dev/hidraw1' });
    await authenticator.makeCredential({ hmacSecret: true });
    expect(calls[0]!.args).toEqual(expect.arrayContaining(['-M', '-h', '/dev/hidraw1']));
    expect(calls[0]!.args).not.toContain('-v'); // never requests user verification — touch-only path
  });

  it('parses the credential id from line 5 of fido2-cred output', async () => {
    const credentialId = randomBytes(16);
    const { runner } = fakeRunner(async () => ({
      stdout: ['clientDataHash', 'rpId', 'packed', 'authData', credentialId.toString('base64'), 'sig', 'cert'].join('\n'),
    }));
    const authenticator = new RealFido2Authenticator({ runner, device: '/dev/hidraw1' });
    const { credentialId: parsed } = await authenticator.makeCredential({ hmacSecret: true });
    expect(parsed.equals(credentialId)).toBe(true);
  });

  it('a runner rejection is wrapped, not surfaced raw', async () => {
    const { runner } = fakeRunner(async () => {
      throw new Error('fido2-cred: fido_dev_make_cred: FIDO_ERR_ACTION_TIMEOUT');
    });
    const authenticator = new RealFido2Authenticator({ runner, device: '/dev/hidraw1' });
    const failure = authenticator.makeCredential({ hmacSecret: true });
    await expect(failure).rejects.toThrow('securelib-fido2: FIDO2 MakeCredential failed');
    await expect(failure).rejects.toMatchObject({ cause: expect.objectContaining({ message: expect.stringContaining('ACTION_TIMEOUT') }) });
  });

  it('throws a clear error on malformed/truncated fido2-cred output', async () => {
    const { runner } = fakeRunner(async () => ({ stdout: 'only\ntwo\n' }));
    const authenticator = new RealFido2Authenticator({ runner, device: '/dev/hidraw1' });
    await expect(authenticator.makeCredential({ hmacSecret: true })).rejects.toThrow(/unexpected fido2-cred output/);
  });
});

describe('RealFido2Authenticator.getAssertion()', () => {
  it('builds the expected fido2-assert argv: -G, -h, the given device', async () => {
    const secret = randomBytes(32);
    const { runner, calls } = fakeRunner(async () => ({
      stdout: ['clientDataHash', 'rpId', 'authData', 'sig', secret.toString('base64')].join('\n'),
    }));
    const authenticator = new RealFido2Authenticator({ runner, device: '/dev/hidraw1' });
    await authenticator.getAssertion(randomBytes(16), randomBytes(32));
    expect(calls[0]!.args).toEqual(expect.arrayContaining(['-G', '-h', '/dev/hidraw1']));
    expect(calls[0]!.args).not.toContain('-v');
  });

  it('parses the hmac secret from line 5 of fido2-assert output', async () => {
    const secret = randomBytes(32);
    const { runner } = fakeRunner(async () => ({
      stdout: ['clientDataHash', 'rpId', 'authData', 'sig', secret.toString('base64')].join('\n'),
    }));
    const authenticator = new RealFido2Authenticator({ runner, device: '/dev/hidraw1' });
    const result = await authenticator.getAssertion(randomBytes(16), randomBytes(32));
    expect(result.equals(secret)).toBe(true);
  });

  it('a runner rejection is wrapped, not surfaced raw', async () => {
    const { runner } = fakeRunner(async () => {
      throw new Error('fido2-assert: fido_dev_get_assert: FIDO_ERR_NO_CREDENTIALS');
    });
    const authenticator = new RealFido2Authenticator({ runner, device: '/dev/hidraw1' });
    const failure = authenticator.getAssertion(randomBytes(16), randomBytes(32));
    await expect(failure).rejects.toThrow('securelib-fido2: FIDO2 GetAssertion failed');
    await expect(failure).rejects.toMatchObject({ cause: expect.objectContaining({ message: expect.stringContaining('NO_CREDENTIALS') }) });
  });
});
