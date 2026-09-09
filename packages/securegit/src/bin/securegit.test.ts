import { describe, it, expect } from 'vitest';
import { interactiveSecretLabels, type SecretPrompt } from './securegit.js';

// `promptSecret()`/`promptWithConfirm()` themselves (real terminal raw mode,
// no echo, retry-on-mismatch) aren't exercised here — there's no TTY inside
// a test runner to give them, the same reason `readStdin()` next to them has
// never been unit-tested either (this whole file is deliberately thin; see
// its own header comment). Verified manually against a real pseudo-terminal:
// the prompt appears, nothing typed is echoed, backspace works, a mismatched
// confirmation is rejected and re-prompted, and the confirmed value reaches
// the command correctly. What *is* fully unit-testable, and the part most
// likely to silently break as commands are added later, is which secret(s)
// get prompted for at all, and whether each needs confirmation — that's pure
// and covered exhaustively below.

function newPassphrase(label = 'New passphrase: '): SecretPrompt {
  return { label, confirm: true };
}

function existingSecret(label: string): SecretPrompt {
  return { label, confirm: false };
}

describe('interactiveSecretLabels()', () => {
  it('init needs a new (confirmed) passphrase when SECUREGIT_PASSPHRASE is unset', () => {
    expect(interactiveSecretLabels(['init'], {})).toEqual([newPassphrase()]);
  });

  it('init needs nothing when SECUREGIT_PASSPHRASE is already set', () => {
    expect(interactiveSecretLabels(['init'], { SECUREGIT_PASSPHRASE: 'x'.repeat(12) })).toEqual([]);
  });

  it('an empty SECUREGIT_PASSPHRASE still counts as unset', () => {
    expect(interactiveSecretLabels(['init'], { SECUREGIT_PASSPHRASE: '' })).toEqual([newPassphrase()]);
  });

  it('unlock needs an existing (unconfirmed) passphrase when unset', () => {
    expect(interactiveSecretLabels(['unlock'], {})).toEqual([existingSecret('Passphrase: ')]);
  });

  it('unlock --ttl 3600 still needs a passphrase when unset (flags do not confuse the check)', () => {
    expect(interactiveSecretLabels(['unlock', '--ttl', '3600'], {})).toEqual([existingSecret('Passphrase: ')]);
  });

  it('identity init needs a new (confirmed) passphrase when unset', () => {
    expect(interactiveSecretLabels(['identity', 'init'], {})).toEqual([newPassphrase()]);
  });

  it('identity show needs nothing', () => {
    expect(interactiveSecretLabels(['identity', 'show'], {})).toEqual([]);
  });

  it('key add-provider passphrase-file needs a new (confirmed) passphrase when unset', () => {
    expect(interactiveSecretLabels(['key', 'add-provider', 'passphrase-file', '--label', 'x'], {})).toEqual([
      newPassphrase(),
    ]);
  });

  it('key add-provider yubikey-piv needs an existing (unconfirmed) PIN when SECUREGIT_PIV_PIN is unset', () => {
    expect(interactiveSecretLabels(['key', 'add-provider', 'yubikey-piv', '--slot', '9d'], {})).toEqual([
      existingSecret('YubiKey PIV PIN: '),
    ]);
  });

  it('key add-provider yubikey-piv needs nothing when SECUREGIT_PIV_PIN is set', () => {
    expect(
      interactiveSecretLabels(['key', 'add-provider', 'yubikey-piv', '--slot', '9d'], { SECUREGIT_PIV_PIN: '123456' }),
    ).toEqual([]);
  });

  it('key add-provider yubikey-fido2 needs nothing (touch-based, no stdin secret)', () => {
    expect(interactiveSecretLabels(['key', 'add-provider', 'yubikey-fido2'], {})).toEqual([]);
  });

  it('key import-recovery needs the code (unconfirmed) then a new passphrase (confirmed), in order, when neither is set', () => {
    expect(interactiveSecretLabels(['key', 'import-recovery', '--in', 'r.enc'], {})).toEqual([
      existingSecret('Recovery code: '),
      newPassphrase(),
    ]);
  });

  it('key import-recovery needs only the new passphrase when the code is already set', () => {
    expect(
      interactiveSecretLabels(['key', 'import-recovery', '--in', 'r.enc'], { SECUREGIT_RECOVERY_CODE: 'ABC' }),
    ).toEqual([newPassphrase()]);
  });

  it('key import-recovery needs only the code when the passphrase is already set', () => {
    expect(
      interactiveSecretLabels(['key', 'import-recovery', '--in', 'r.enc'], {
        SECUREGIT_PASSPHRASE: 'x'.repeat(12),
      }),
    ).toEqual([existingSecret('Recovery code: ')]);
  });

  it('key import-recovery needs nothing when both are already set', () => {
    expect(
      interactiveSecretLabels(['key', 'import-recovery', '--in', 'r.enc'], {
        SECUREGIT_RECOVERY_CODE: 'ABC',
        SECUREGIT_PASSPHRASE: 'x'.repeat(12),
      }),
    ).toEqual([]);
  });

  it('key list, key rotate, and other key subcommands need nothing', () => {
    expect(interactiveSecretLabels(['key', 'list'], {})).toEqual([]);
    expect(interactiveSecretLabels(['key', 'rotate', '--confirm-recipients', '1'], {})).toEqual([]);
  });

  it('commands that read stdin as file content never trigger a prompt', () => {
    for (const argv of [
      ['clean', '--', 'file.txt'],
      ['smudge', '--', 'file.txt'],
      ['encrypt', '-'],
      ['decrypt', '-'],
      ['status'],
      ['verify'],
    ]) {
      expect(interactiveSecretLabels(argv, {})).toEqual([]);
    }
  });

  it('a --repo flag before the command does not confuse which command is being run', () => {
    expect(interactiveSecretLabels(['--repo', '/some/path', 'init'], {})).toEqual([newPassphrase()]);
  });

  it('a --repo flag after the command does not confuse which command is being run', () => {
    expect(interactiveSecretLabels(['identity', 'init', '--repo', '/some/path'], {})).toEqual([newPassphrase()]);
  });
});
