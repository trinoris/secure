import { describe, it, expect, vi } from 'vitest';
import {
  promptSecret,
  promptWithConfirm,
  resolveStdin,
  type PromptIO,
  type SecretPrompt,
} from './securegit.js';

/**
 * A fake `PromptIO`: feeding it a string via `type()` drives `promptSecret()`
 * exactly the way real keystrokes would, without a real TTY — there isn't
 * one inside a test runner (the same reason `promptSecret()` itself was
 * never unit-tested before this file existed; verified instead against a
 * real pseudo-terminal, see specs/securegit/10-cli-contract.md's
 * "Interactive secret prompting"). `type()` resolves once the handler
 * registered via `onData` has processed every character, so a test can
 * simply `await` a full simulated line of input.
 */
function fakePromptIO(): {
  io: PromptIO;
  written: string[];
  type: (text: string) => Promise<void>;
  exitCalls: number[];
  rawModeCalls: boolean[];
} {
  const written: string[] = [];
  const exitCalls: number[] = [];
  const rawModeCalls: boolean[] = [];
  let handler: ((chunk: string) => void) | null = null;
  const io: PromptIO = {
    write: (text) => written.push(text),
    onData: (h) => {
      handler = h;
    },
    offData: () => {
      handler = null;
    },
    setRawMode: (enabled) => rawModeCalls.push(enabled),
    resume: () => {},
    pause: () => {},
    exit: (code) => exitCalls.push(code),
  };
  return {
    io,
    written,
    exitCalls,
    rawModeCalls,
    // A real microtask/macrotask tick after firing, so a caller that awaits
    // each type() call sequentially only proceeds once promptSecret()'s
    // internal `await` chain has actually resumed and re-registered its
    // next `onData` handler (relevant for promptWithConfirm()'s second
    // prompt, and resolveStdin()'s second-and-later secret).
    type: async (text) => {
      handler?.(text);
      await new Promise((resolve) => setImmediate(resolve));
    },
  };
}

describe('promptSecret()', () => {
  it('writes the label, then resolves with the typed line on Enter (\\n)', async () => {
    const fake = fakePromptIO();
    const result = promptSecret('Passphrase: ', fake.io);
    await fake.type('correct horse battery staple\n');
    expect(await result).toBe('correct horse battery staple');
    expect(fake.written[0]).toBe('Passphrase: ');
  });

  it('resolves on \\r too (a real terminal in raw mode sends \\r for Enter)', async () => {
    const fake = fakePromptIO();
    const result = promptSecret('Passphrase: ', fake.io);
    await fake.type('hunter2\r');
    expect(await result).toBe('hunter2');
  });

  it('never echoes what was typed — the only thing written is the label and the trailing newline', async () => {
    const fake = fakePromptIO();
    const result = promptSecret('Passphrase: ', fake.io);
    await fake.type('super-secret-value\n');
    await result;
    expect(fake.written.join('')).toBe('Passphrase: \n');
  });

  it('backspace (0x7f) removes the last character', async () => {
    const fake = fakePromptIO();
    const result = promptSecret('Passphrase: ', fake.io);
    await fake.type('wrongpass');
    await fake.type('\x7f\x7f\x7f\x7f');
    await fake.type('word\n');
    expect(await result).toBe('wrongword');
  });

  it('Ctrl-H (0x08) also acts as backspace', async () => {
    const fake = fakePromptIO();
    const result = promptSecret('x: ', fake.io);
    await fake.type('ab\x08c\n');
    expect(await result).toBe('ac');
  });

  it('backspace on empty input is a no-op, not a crash or negative-length slice', async () => {
    const fake = fakePromptIO();
    const result = promptSecret('x: ', fake.io);
    await fake.type('\x7f\x7fok\n');
    expect(await result).toBe('ok');
  });

  it('Ctrl-C (0x03) restores the terminal and exits 130, without resolving the promise', async () => {
    const fake = fakePromptIO();
    const result = promptSecret('Passphrase: ', fake.io);
    let settled = false;
    void result.then(() => {
      settled = true;
    });
    await fake.type('partial\x03');
    await Promise.resolve();
    await Promise.resolve();
    expect(fake.exitCalls).toEqual([130]);
    expect(settled).toBe(false);
  });

  it('puts the terminal into raw mode before reading and takes it out afterward', async () => {
    const fake = fakePromptIO();
    const result = promptSecret('x: ', fake.io);
    expect(fake.rawModeCalls).toEqual([true]);
    await fake.type('a\n');
    await result;
    expect(fake.rawModeCalls).toEqual([true, false]);
  });

  it('handles a UTF-8 multi-byte character typed as one chunk', async () => {
    const fake = fakePromptIO();
    const result = promptSecret('x: ', fake.io);
    await fake.type('pässwörd\n');
    expect(await result).toBe('pässwörd');
  });
});

describe('promptWithConfirm()', () => {
  it('confirm: false prompts exactly once, no "Confirm" prompt at all', async () => {
    const fake = fakePromptIO();
    const prompt: SecretPrompt = { label: 'PIN: ', confirm: false };
    const result = promptWithConfirm(prompt, fake.io);
    await fake.type('123456\n');
    expect(await result).toBe('123456');
    expect(fake.written).toEqual(['PIN: ', '\n']);
  });

  it('confirm: true prompts twice and resolves once both entries match', async () => {
    const fake = fakePromptIO();
    const prompt: SecretPrompt = { label: 'New passphrase: ', confirm: true };
    const result = promptWithConfirm(prompt, fake.io);
    await fake.type('correct horse battery staple\n');
    await fake.type('correct horse battery staple\n');
    expect(await result).toBe('correct horse battery staple');
    expect(fake.written).toContain('New passphrase: ');
    expect(fake.written).toContain('Confirm passphrase: ');
  });

  it('confirm: true rejects a mismatch, prints a message, and re-prompts from the start', async () => {
    const fake = fakePromptIO();
    const prompt: SecretPrompt = { label: 'New passphrase: ', confirm: true };
    const result = promptWithConfirm(prompt, fake.io);
    await fake.type('first attempt one\n');
    await fake.type('typo in the confirm\n');
    await fake.type('second attempt two\n');
    await fake.type('second attempt two\n');
    expect(await result).toBe('second attempt two');
    expect(fake.written.some((w) => w.includes("didn't match"))).toBe(true);
  });
});

describe('resolveStdin()', () => {
  it('when not a TTY, always reads stdin directly — never prompts, regardless of argv', async () => {
    const readStdin = vi.fn().mockResolvedValue(Buffer.from('piped content'));
    const fake = fakePromptIO();
    const result = await resolveStdin(['init'], { isTTY: false, env: {}, io: fake.io, readStdin });
    expect(result.toString('utf8')).toBe('piped content');
    expect(fake.written).toEqual([]);
  });

  it('on a TTY, a command needing no secret (e.g. status) reads stdin directly, no prompt', async () => {
    const readStdin = vi.fn().mockResolvedValue(Buffer.alloc(0));
    const fake = fakePromptIO();
    const result = await resolveStdin(['status'], { isTTY: true, env: {}, io: fake.io, readStdin });
    expect(readStdin).toHaveBeenCalledOnce();
    expect(fake.written).toEqual([]);
    expect(result.length).toBe(0);
  });

  it('on a TTY, init prompts and returns the typed passphrase as a single trailing-newline-terminated buffer', async () => {
    const readStdin = vi.fn();
    const fake = fakePromptIO();
    const resultPromise = resolveStdin(['init'], { isTTY: true, env: {}, io: fake.io, readStdin });
    await fake.type('correct horse battery staple\n');
    await fake.type('correct horse battery staple\n');
    const result = await resultPromise;
    expect(result.toString('utf8')).toBe('correct horse battery staple\n');
    expect(readStdin).not.toHaveBeenCalled();
  });

  it('on a TTY, key import-recovery prompts for both secrets, in order, joined by newlines', async () => {
    const readStdin = vi.fn();
    const fake = fakePromptIO();
    const resultPromise = resolveStdin(['key', 'import-recovery', '--in', 'r.enc'], {
      isTTY: true,
      env: {},
      io: fake.io,
      readStdin,
    });
    await fake.type('RECOVERY-CODE-HERE\n');
    await fake.type('a new passphrase!!\n');
    await fake.type('a new passphrase!!\n');
    const result = await resultPromise;
    expect(result.toString('utf8')).toBe('RECOVERY-CODE-HERE\na new passphrase!!\n');
  });

  it('on a TTY, a command whose only secret is already in env skips the prompt entirely', async () => {
    const readStdin = vi.fn();
    const fake = fakePromptIO();
    const result = await resolveStdin(['init'], {
      isTTY: true,
      env: { SECUREGIT_PASSPHRASE: 'x'.repeat(12) },
      io: fake.io,
      readStdin,
    });
    expect(fake.written).toEqual([]);
    expect(readStdin).toHaveBeenCalledOnce();
    void result;
  });
});
