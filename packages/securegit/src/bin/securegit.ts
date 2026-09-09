#!/usr/bin/env node
// The real executable: wires process.argv/env/stdin/stdout to runCli().
// Deliberately thin — every decision lives in cli.ts, which is unit-tested
// without touching a real process. See specs/securegit/10-cli-contract.md.

import { homedir } from 'node:os';
import { runCli, runFilterProcess } from '../cli.js';
import { installStdoutGuard } from '../process.js';

/**
 * `SECUREGIT_HOME`, when set, overrides `os.homedir()` for every path this
 * tool resolves under `~/.securegit/` (keyring, session, identity). Exists
 * for the same reason `GNUPGHOME` exists for gpg: `os.homedir()` is
 * genuinely a different filesystem location per environment even for "the
 * same" machine and the same repository — WSL (`/home/<user>`) and native
 * Windows (`C:\Users\<user>`, reachable from WSL at `/mnt/c/Users/<user>`)
 * are the sharpest everyday case, but any dual-boot or multi-account setup
 * has the identical shape. `securegit` never guesses across this split on
 * its own (silently trying a second candidate home would be exactly the
 * kind of implicit, unaudited key-search path the rest of this tool goes
 * out of its way to avoid) — an explicit override is the only way in. See
 * docs/securegit/02-faq.md and specs/securegit/05-key-hierarchy.md.
 */
function resolveHome(): string {
  const override = process.env.SECUREGIT_HOME;
  return override !== undefined && override.length > 0 ? override : homedir();
}

async function readStdin(): Promise<Buffer> {
  if (process.stdin.isTTY) return Buffer.alloc(0);
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

const CTRL_C = String.fromCharCode(3);
const BACKSPACE = String.fromCharCode(127);
const CTRL_H = String.fromCharCode(8);

/**
 * The raw-mode terminal operations `promptSecret()` needs — abstracted for
 * the same reason `FilterProcessIO`/`CliIO` abstract `process.*` elsewhere
 * in this codebase: a fake implementation lets a test drive synthetic
 * keystrokes and inspect what got written, without a real TTY (there isn't
 * one inside a test runner). `realPromptIO()` (below) is the only
 * implementation `main()` ever actually uses.
 */
export interface PromptIO {
  write: (text: string) => void;
  onData: (handler: (chunk: string) => void) => void;
  offData: (handler: (chunk: string) => void) => void;
  setRawMode: (enabled: boolean) => void;
  resume: () => void;
  pause: () => void;
  exit: (code: number) => void;
}

function realPromptIO(): PromptIO {
  process.stdin.setEncoding('utf8');
  return {
    write: (text) => {
      process.stdout.write(text);
    },
    onData: (handler) => {
      process.stdin.on('data', handler);
    },
    offData: (handler) => {
      process.stdin.removeListener('data', handler);
    },
    setRawMode: (enabled) => {
      process.stdin.setRawMode?.(enabled);
    },
    resume: () => {
      process.stdin.resume();
    },
    pause: () => {
      process.stdin.pause();
    },
    exit: (code) => {
      process.exit(code);
    },
  };
}

/**
 * Reads one line of input without echoing it — not even asterisks, so the
 * terminal reveals nothing at all about the secret, not even its length
 * (the same choice `ssh`'s and `sudo`'s own prompts make). Only ever called
 * from a real TTY, so raw mode is always meaningful there; a fake `io` in a
 * test never actually needs one.
 */
export async function promptSecret(label: string, io: PromptIO = realPromptIO()): Promise<string> {
  io.write(label);
  return new Promise((resolve) => {
    let input = '';
    const onData = (chunk: string): void => {
      for (const char of chunk) {
        if (char === '\n' || char === '\r') {
          io.setRawMode(false);
          io.pause();
          io.offData(onData);
          io.write('\n');
          resolve(input);
          return;
        }
        if (char === CTRL_C) {
          // Restore the terminal before exiting — the same courtesy it
          // gets back after any other interactive command.
          io.setRawMode(false);
          io.write('\n');
          io.exit(130);
          return; // a fake `io.exit` in a test doesn't actually stop this
        }
        if (char === BACKSPACE || char === CTRL_H) {
          input = input.slice(0, -1);
          continue;
        }
        input += char;
      }
    };
    io.setRawMode(true);
    io.resume();
    io.onData(onData);
  });
}

/**
 * Which secret(s) `resolvePassphrase()`/`resolvePin()`/
 * `resolveImportRecoverySecrets()` (`src/cli.ts`) would otherwise silently
 * read as an empty string from a bare, un-piped TTY — the real gap
 * `readStdin()` used to leave as a follow-up. Named here, one command at a
 * time, rather than a blanket "TTY means prompt": `clean`/`smudge`/
 * `encrypt`/`decrypt -` also read `process.stdin`, but as file content, not
 * a secret — prompting there would silently corrupt that content instead.
 * Returns entries in the exact order the corresponding `resolve*` function
 * expects to find them, one per stdin line; empty when every secret this
 * command needs already has its environment variable set, or the command
 * needs none at all. `confirm: true` marks a secret being *created* right
 * now (init, identity init, a provider's new passphrase, a recovery
 * import's new passphrase) — a typo there isn't caught until some later
 * unlock, possibly much later, by which point there's no way to know what
 * was actually typed, since nothing was ever echoed. `confirm: false`
 * marks entering an *existing* secret (unlock, a PIV PIN, a recovery
 * code) — a typo there fails immediately and obviously, so asking twice
 * would only add friction to a command run often, for no real safety gain.
 */
export interface SecretPrompt {
  label: string;
  confirm: boolean;
}

export function interactiveSecretLabels(argv: string[], env: NodeJS.ProcessEnv): SecretPrompt[] {
  const repoIdx = argv.indexOf('--repo');
  const [cmd, ...rest] = repoIdx === -1 ? argv : [...argv.slice(0, repoIdx), ...argv.slice(repoIdx + 2)];
  const hasEnv = (name: string): boolean => {
    const v = env[name];
    return v !== undefined && v.length > 0;
  };

  if (cmd === 'init' || (cmd === 'identity' && rest[0] === 'init')) {
    return hasEnv('SECUREGIT_PASSPHRASE') ? [] : [{ label: 'New passphrase: ', confirm: true }];
  }
  if (cmd === 'unlock') {
    return hasEnv('SECUREGIT_PASSPHRASE') ? [] : [{ label: 'Passphrase: ', confirm: false }];
  }
  if (cmd === 'key' && rest[0] === 'add-provider') {
    const type = rest.slice(1).find((a) => !a.startsWith('--'));
    if (type === 'passphrase-file') {
      return hasEnv('SECUREGIT_PASSPHRASE') ? [] : [{ label: 'New passphrase: ', confirm: true }];
    }
    if (type === 'yubikey-piv') {
      return hasEnv('SECUREGIT_PIV_PIN') ? [] : [{ label: 'YubiKey PIV PIN: ', confirm: false }];
    }
    return [];
  }
  if (cmd === 'key' && rest[0] === 'import-recovery') {
    const prompts: SecretPrompt[] = [];
    if (!hasEnv('SECUREGIT_RECOVERY_CODE')) prompts.push({ label: 'Recovery code: ', confirm: false });
    if (!hasEnv('SECUREGIT_PASSPHRASE')) prompts.push({ label: 'New passphrase: ', confirm: true });
    return prompts;
  }
  return [];
}

/** Prompts once, or (`confirm: true`) until two consecutive entries match. */
export async function promptWithConfirm(prompt: SecretPrompt, io: PromptIO = realPromptIO()): Promise<string> {
  if (!prompt.confirm) return promptSecret(prompt.label, io);
  for (;;) {
    const first = await promptSecret(prompt.label, io);
    const second = await promptSecret('Confirm passphrase: ', io);
    if (first === second) return first;
    io.write("securegit: those didn't match — try again\n");
  }
}

export interface ResolveStdinOptions {
  isTTY: boolean;
  env: NodeJS.ProcessEnv;
  io: PromptIO;
  readStdin: () => Promise<Buffer>;
}

const REAL_RESOLVE_STDIN_OPTIONS: ResolveStdinOptions = {
  get isTTY() {
    return process.stdin.isTTY ?? false;
  },
  get env() {
    return process.env;
  },
  get io() {
    return realPromptIO();
  },
  readStdin,
};

export async function resolveStdin(
  argv: string[],
  opts: ResolveStdinOptions = REAL_RESOLVE_STDIN_OPTIONS,
): Promise<Buffer> {
  if (!opts.isTTY) return opts.readStdin();
  const prompts = interactiveSecretLabels(argv, opts.env);
  if (prompts.length === 0) return opts.readStdin();
  const values: string[] = [];
  for (const prompt of prompts) {
    values.push(await promptWithConfirm(prompt, opts.io));
  }
  return Buffer.from(`${values.join('\n')}\n`, 'utf8');
}

/**
 * `filter-process` is a long-running stream, not a single request/response —
 * it can't go through `readStdin()`/`runCli()`'s whole-buffer, one-shot
 * contract, so it's intercepted here before either runs. The stdout guard
 * (11-filter-process.md, implementation note 1) is installed for the whole
 * lifetime of this call: a stray `console.log` anywhere underneath —
 * including in a dependency — would otherwise corrupt whichever blob is
 * mid-flight on the real protocol stream.
 */
async function runFilterProcessMain(): Promise<void> {
  const guard = installStdoutGuard(process.stdout);
  try {
    const code = await runFilterProcess({
      cwd: process.cwd(),
      env: process.env,
      home: resolveHome(),
      onData: (handler) => process.stdin.on('data', handler),
      onEnd: (handler) => process.stdin.on('end', handler),
      write: guard.write,
      stderr: (message) => {
        process.stderr.write(`${message}\n`);
      },
    });
    process.exitCode = code;
  } finally {
    guard.restore();
  }
}

async function main(): Promise<void> {
  if (process.argv[2] === 'filter-process') {
    return runFilterProcessMain();
  }

  const argv = process.argv.slice(2);
  const stdin = await resolveStdin(argv);
  const code = await runCli({
    argv,
    cwd: process.cwd(),
    env: process.env,
    stdin,
    home: resolveHome(),
    stdout: (chunk) => {
      process.stdout.write(chunk);
    },
    stderr: (message) => {
      process.stderr.write(`${message}\n`);
    },
    info: (message) => {
      process.stderr.write(`${message}\n`);
    },
  });
  process.exitCode = code;
}

main().catch((e: unknown) => {
  process.stderr.write(`securegit: fatal: ${(e as Error).message}\n`);
  process.exitCode = 4;
});
