// The command surface: wires config/install/keyring/provider/session/filter/
// envelope into `securegit <command>`.
//
// Every command takes an injected CliIO rather than touching process.* — that
// is the seam that makes this testable without spawning real subprocesses.
// `bin/securegit.ts` is the thin adapter that wires process.argv/stdin/stdout
// to this function for the real executable.
// See specs/securegit/10-cli-contract.md.

import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, readdir, writeFile, unlink, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { keyFingerprint } from '@trinoris/securelib/crypto';
import {
  ConfigError,
  initConfig,
  readConfig,
  resolveKeyringPath,
  setBindPath,
  type RepoConfig,
} from '@trinoris/securelib/config';
import { InstallError, install, protect, unprotect, DEFAULT_PROTECT_PATTERNS } from './install.js';
import { AgentInstallError, installAgentTargets, listAgentTargets, AGENT_TARGET_IDS } from './agent-install.js';
import {
  KeyringError,
  addProvider,
  removeProvider,
  createKeyring,
  findLikelyWindowsHome,
  keyringFromRecoveredGenerations,
  parseKeyId,
  readKeyringFile,
  rewrapOutdatedGenerations,
  rotateKeyring,
  unlockKeyring,
  writeKeyringFile,
  type KeyringFile,
} from '@trinoris/securelib/keyring';
import { PassphraseFileProvider, ProviderError, type KeyProvider } from '@trinoris/securelib/provider';
import { loadProvider } from '@trinoris/securelib/registry';
import {
  keySourceFromSessionKey,
  lockSession,
  lockedKeySource,
  readSession,
  resolveSessionPath,
  writeSession,
} from '@trinoris/securelib/session';
import { LockedError, clean, smudge, textconv } from './filter.js';
import type { KeySource } from '@trinoris/securelib/provider';
import { EnvelopeError, parseEnvelope, seal, unseal } from '@trinoris/securelib/envelope';
import {
  verify,
  verifyExitCode,
  accessReport,
  historyReport,
  metadataReport,
  recoveryPathStatus,
  TEXTCONV_NOTES_REF,
  checkAttr,
  listTrackedPaths,
  readIndexBlob,
} from './verify.js';
import { merge } from './merge.js';
import {
  IdentityError,
  createIdentity,
  decodePublicKey,
  detectLocalSigningKey,
  generateSigningKeyPair,
  identityFingerprint,
  identityPath,
  readIdentityFile,
  signingKeyFingerprint,
  signingKeyPath,
  unlockIdentity,
  writeIdentityFile,
  type X25519KeyPair,
} from '@trinoris/securelib/identity';
import {
  RecipientError,
  appendRemovedRecipientLogEntry,
  recipientPath,
  recipientsDir,
  readRecipientFile,
  removedRecipientsLogPath,
  unlockFromRecipientFile,
  wrapAllGenerations,
  wrapForRecipient,
  writeRecipientFile,
  type RecipientFile,
} from '@trinoris/securelib/recipients';
import {
  RecoveryError,
  appendRecoveryLogEntry,
  exportRecovery,
  formatRecoveryCode,
  generateExportId,
  importRecovery,
  parseRecoveryCode,
  readRecoveryFile,
  recoveryFilePath,
  recoveryLogPath,
  writeRecoveryFile,
} from '@trinoris/securelib/recovery';
import { FilterProcessServer } from './process.js';

const execFile = promisify(execFileCb);

export const EXIT_OK = 0;
export const EXIT_LOCKED = 1;
export const EXIT_MISCONFIGURED = 2;
export const EXIT_CRYPTO = 3;
export const EXIT_USAGE = 4;
export const EXIT_LEAK = 5;

export interface CliIO {
  /** Command and its arguments — NOT including "node" or the script path. */
  argv: string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
  /** File content for clean/smudge/encrypt/decrypt/inspect; whole-buffer. */
  stdin: Buffer;
  /** Equivalent of os.homedir(), injected so tests never touch the real one. */
  home: string;
  /** The content channel. Only clean/smudge/textconv/encrypt/decrypt write here. */
  stdout: (chunk: Buffer) => void;
  /**
   * Errors, and every report-type command's actual human-readable report
   * (status, identity show, verify, inspect) — that report is the point of
   * running the command, not a diagnostic aside, so `--quiet` never touches
   * it. Never receives plaintext or key material.
   */
  stderr: (message: string) => void;
  /**
   * One-shot success confirmations ("initialized repository …", "unlocked
   * (generation …)") — suppressed under `--quiet`, unlike `stderr`. Never
   * receives plaintext or key material.
   */
  info: (message: string) => void;
  // The `| undefined` (beyond plain optionality) is deliberate under this
  // project's `exactOptionalPropertyTypes` — tests assign `now: undefined`
  // explicitly to assert the real, no-injected-clock fallback path, as
  // distinct from simply omitting the key.
  now?: (() => Date) | undefined;
}

const USAGE =
  'usage: securegit <init|install|protect|unprotect|unlock|lock|status|identity|key|agent|verify|reencrypt|clean|smudge|textconv|merge|encrypt|decrypt|inspect|filter-process> ...';

// ---------------------------------------------------------------------------
// `--help` / `-h` / `help`
//
// One data structure drives three outputs: the human-readable per-command
// help (`securegit <command> --help`, `securegit help <command>`), the
// top-level command list (`securegit --help`, `securegit help`), and the
// machine-readable manifest (`securegit help --json`) — a coding agent or
// script can introspect the entire CLI surface from this one call, without
// reading source or docs. Keep this in sync with 10-cli-contract.md; that
// spec remains the authority if the two ever disagree.
// ---------------------------------------------------------------------------

interface HelpEntry {
  usage: string;
  summary: string;
  /** Additional paragraphs, rendered one per line after `summary`. */
  details?: string[];
  flags?: Array<{ flag: string; desc: string }>;
  examples?: string[];
  /** For a group command (`key`, `identity`): its subcommand names, in display order. */
  subcommands?: string[];
}

const HELP_CATEGORIES: Array<{ title: string; commands: string[] }> = [
  { title: 'Repository', commands: ['init', 'install', 'protect', 'unprotect', 'status', 'verify', 'reencrypt'] },
  { title: 'Session', commands: ['unlock', 'lock'] },
  { title: 'Identity and sharing', commands: ['identity', 'key'] },
  { title: 'Ad hoc (no repository needed)', commands: ['encrypt', 'decrypt', 'inspect'] },
  { title: 'AI coding agents', commands: ['agent'] },
  { title: 'Invoked by Git, not by people', commands: ['clean', 'smudge', 'textconv', 'merge', 'filter-process'] },
];

export const HELP: Record<string, HelpEntry> = {
  init: {
    usage: 'securegit init [--bind-path] [--pad-to <n>]',
    summary: 'Set up this repository: create .securegit/config.json and its first key (generation 1).',
    details: [
      'Prompts for a new passphrase on stdin to lock that key behind — at least 12 characters, no',
      'other rule. Non-interactively, set SECUREGIT_PASSPHRASE instead of piping stdin. Refuses if you',
      'are not inside a Git repository, or if this one is already set up. Neither flag can be changed',
      'by re-running init — bindPath has its own update path (key rotate --bind-path); padTo does not',
      'need one.',
    ],
    flags: [
      { flag: '--bind-path', desc: 'fold the file path into encryption, so moving ciphertext between paths fails' },
      { flag: '--pad-to <n>', desc: 'round encrypted file sizes up to the nearest multiple of n bytes (default: off)' },
    ],
    examples: ['securegit init', 'SECUREGIT_PASSPHRASE="correct horse battery staple" securegit init'],
  },
  install: {
    usage: 'securegit install [--process] [--no-required] [--bin <cmd>] [--force]',
    summary: 'Write the local .git/config entries that make Git actually call securegit on protected paths.',
    details: [
      'Required once per clone, and easy to forget — nothing visibly breaks if skipped, Git simply',
      'never invokes the filter, and "protected" files check out as plaintext. Idempotent: safe to',
      'run again if unsure whether it already happened.',
    ],
    flags: [
      { flag: '--process', desc: 'use the long-running filter-process protocol instead of one clean/smudge call per file' },
      { flag: '--no-required', desc: 'do not fail a checkout when the filter itself is unavailable' },
      { flag: '--bin <cmd>', desc: 'the command Git should invoke instead of the resolved securegit on PATH' },
      { flag: '--force', desc: 'overwrite filter configuration this tool did not originally write' },
    ],
    examples: ['securegit install'],
  },
  protect: {
    usage: 'securegit protect [<pattern>...] [--no-residue]',
    summary: 'Add path patterns to .gitattributes so Git routes them through the encryption filter.',
    details: [
      'Called with no pattern at all, protects a conservative default set of common secret-shaped',
      'filenames instead — a fast-setup path for a first-time repository. The confirmation printed',
      'afterward names exactly which patterns were applied; .gitattributes has the durable record.',
    ],
    flags: [{ flag: '--no-residue', desc: 'skip adding .gitignore entries for editor/merge residue files' }],
    examples: ['securegit protect', "securegit protect '.env' 'config/production.*'"],
  },
  unprotect: {
    usage: 'securegit unprotect <pattern>...',
    summary: 'Remove path patterns from .gitattributes. Forward-only, like key rotation.',
    details: [
      'Already-committed blobs under a removed pattern stay encrypted until the file is next edited',
      'and re-added (or `reencrypt` is run). A pattern that was never protected is a silent no-op.',
    ],
    examples: ["securegit unprotect '*.pem'"],
  },
  status: {
    usage: 'securegit status [--json]',
    summary: 'Show whether this repository is unlocked, its current generation, and any advisory warnings.',
    flags: [{ flag: '--json', desc: 'machine-readable report to stdout instead of the human-readable form on stderr' }],
    examples: ['securegit status', 'securegit status --json'],
  },
  verify: {
    usage: 'securegit verify [--history | --access] [--json]',
    summary: 'Audit this repository: config sanity, leaked plaintext, commit history, or who can read it.',
    details: [
      'No flags: fast enough for a pre-commit hook. --history walks every commit (CI/pre-push speed,',
      'not pre-commit). --access reports every recipient and recovery export on file. Exits 5',
      '(base form and --history only) if a protected path\'s committed content is not real ciphertext.',
    ],
    flags: [
      { flag: '--history', desc: 'walk the full commit history, not just the current checkout' },
      { flag: '--access', desc: 'report who can currently read this repository' },
      { flag: '--json', desc: 'machine-readable report to stdout' },
    ],
    examples: ['securegit verify', 'securegit verify --history || exit 1', 'securegit verify --access --json'],
  },
  reencrypt: {
    usage: 'securegit reencrypt [--paths <pathspec>] [--dry-run]',
    summary: 'Move protected files onto the current key generation, without touching the worktree file.',
    flags: [
      { flag: '--paths <pathspec>', desc: 'a prefix match (not full git pathspec syntax) limiting which files move' },
      { flag: '--dry-run', desc: 'report what would move, without staging anything' },
    ],
    examples: ['securegit reencrypt', 'securegit reencrypt --dry-run'],
  },
  unlock: {
    usage: 'securegit unlock [--ttl <seconds>]',
    summary: 'Unwrap this repository\'s key(s) once and cache the result for a bounded time (default 8 hours).',
    details: [
      'Tries the local keyring first, then — only if none exists — bootstraps from a recipient entry',
      'plus this machine\'s own identity. Non-interactively: SECUREGIT_PASSPHRASE (or',
      'SECUREGIT_SESSION_KEY, or SECUREGIT_PIV_PIN for a YubiKey-PIV provider) supplies the secret',
      'instead of a prompt — see the CLI guide\'s "For scripts and agents" section. "no keyring found"',
      'for a repository you know is set up usually means a different home directory than the one',
      'that ran `init` (WSL vs. native Windows is the common case) — set SECUREGIT_HOME to point at it.',
    ],
    flags: [{ flag: '--ttl <seconds>', desc: 'cache lifetime; capped at 86400 (24 hours)' }],
    examples: ['securegit unlock', 'securegit unlock --ttl 3600'],
  },
  lock: {
    usage: 'securegit lock',
    summary: 'Remove the session cache immediately. Nothing is lost — unlock again whenever needed.',
    examples: ['securegit lock'],
  },
  identity: {
    usage: 'securegit identity <init|show>',
    summary: 'Manage this machine\'s personal identity keypair, used to receive shared access.',
    subcommands: ['init', 'show'],
  },
  'identity init': {
    usage: 'securegit identity init [--label <label>] [--generate-signing-key]',
    summary: 'Generate this machine\'s X25519 identity keypair. Refuses if one already exists.',
    details: [
      'Prompts for a new passphrase on stdin to lock the private half behind — at least 12 characters,',
      'no other rule (this passphrase protects your identity only; it is unrelated to any repository\'s',
      'own passphrase). Non-interactively, set SECUREGIT_PASSPHRASE instead of piping stdin.',
    ],
    flags: [
      { flag: '--label <label>', desc: 'a human-readable name for this identity' },
      { flag: '--generate-signing-key', desc: 'generate a signing keypair too, only if none is already recorded' },
    ],
    examples: ['securegit identity init', 'SECUREGIT_PASSPHRASE="correct horse battery staple" securegit identity init'],
  },
  'identity show': {
    usage: 'securegit identity show',
    summary: 'Print this identity\'s public key and fingerprint — safe to paste anywhere, share with a teammate.',
    examples: ['securegit identity show'],
  },
  key: {
    usage: 'securegit key <subcommand> ...',
    summary: 'Everything about keys: generations, hardware/passphrase providers, teammates, and recovery.',
    subcommands: [
      'list',
      'rotate',
      'add-recipient',
      'remove-recipient',
      'list-recipients',
      'add-provider',
      'remove-provider',
      'export-recovery',
      'import-recovery',
    ],
  },
  'key list': {
    usage: 'securegit key list [--json]',
    summary: 'List every generation: fingerprint, creation date, current marker, and which providers unlock it.',
    details: ['No key required — this is keyring metadata, not anything requiring decryption.'],
    examples: ['securegit key list', 'securegit key list --json'],
  },
  'key rotate': {
    usage: 'securegit key rotate [--bind-path] --confirm-recipients <n>',
    summary: 'Create a new key generation and rewrap it for every current provider and recipient.',
    details: [
      'Prints the recipient list and refuses unless --confirm-recipients matches it exactly — a',
      'deliberate speed bump against rotating without noticing who is actually still on the list.',
      'Refuses a dirty working tree or a locked repository too (locked is checked first).',
    ],
    flags: [{ flag: '--bind-path', desc: 'also flip config.json\'s bindPath to true, once rotation succeeds' }],
    examples: ['securegit key rotate --confirm-recipients 3'],
  },
  'key add-recipient': {
    usage: 'securegit key add-recipient <pubkey> [--label <label>] [--signing-key <ssh-public-key>]',
    summary: 'Share every generation you currently hold with a teammate\'s public key.',
    details: ['Writes .securegit/recipients/<fingerprint>.json — commit and push it for them to use it.'],
    examples: ['securegit key add-recipient SGPUB1... --label alice'],
  },
  'key remove-recipient': {
    usage: 'securegit key remove-recipient <fingerprint>',
    summary: 'Delete a recipient entry. Forward-only: does not revoke generations already shared.',
    details: ['Pair with `key rotate` when you need the forward-only distinction to actually matter.'],
    examples: ['securegit key remove-recipient a1b2c3d4e5f60718'],
  },
  'key list-recipients': {
    usage: 'securegit key list-recipients [--json]',
    summary: 'List every recipient: fingerprint, label, added-at, and which generations they cover.',
    examples: ['securegit key list-recipients'],
  },
  'key add-provider': {
    usage: 'securegit key add-provider <passphrase-file|yubikey-piv|yubikey-fido2> [options]',
    summary: 'Add another way to unlock the same keys, without replacing what already works.',
    details: [
      'passphrase-file needs --label (a second, independent passphrase, at least 12 characters, read',
      'from stdin — not SECUREGIT_PASSPHRASE, which already means the *current* unlock credential for',
      'this call). yubikey-piv needs --slot <slot> (e.g. 9d) and SECUREGIT_PIV_PIN or a PIN prompt.',
      'yubikey-fido2 takes an optional --device <path> and needs a physical touch. Needs the',
      'repository already unlocked.',
    ],
    flags: [
      { flag: '--label <label>', desc: 'passphrase-file only: names the new provider id' },
      { flag: '--slot <slot>', desc: 'yubikey-piv only: the PIV slot to use, e.g. 9d' },
      { flag: '--device <path>', desc: 'yubikey-fido2 only: a specific authenticator device path' },
    ],
    examples: ['securegit key add-provider yubikey-piv --slot 9d', 'securegit key add-provider yubikey-fido2'],
  },
  'key remove-provider': {
    usage: 'securegit key remove-provider <id>',
    summary: 'Delete a provider\'s wrapped slot. Refuses if it is the last one able to unlock any generation.',
    examples: ['securegit key remove-provider yubikey-piv'],
  },
  'key export-recovery': {
    usage: 'securegit key export-recovery --out <file>',
    summary: 'Write a recovery file and print a one-time recovery code — your safety net if every key is lost.',
    details: [
      'Reads from the already-unlocked session; exits locked if there is none. The code is printed',
      'once, to stderr, and never written anywhere by securegit itself — store it separately from',
      'the file it decrypts.',
    ],
    examples: ['securegit key export-recovery --out recovery.enc'],
  },
  'key import-recovery': {
    usage: 'securegit key import-recovery --in <file>',
    summary: 'Rebuild a keyring from a recovery file and its code, wrapped under a freshly chosen passphrase.',
    details: [
      'Needs two secrets: SECUREGIT_RECOVERY_CODE and SECUREGIT_PASSPHRASE (or, with neither set,',
      'two lines on stdin: the code, then the new passphrase) — the new passphrase must be at least',
      '12 characters, the same rule `init` applies.',
    ],
    examples: ['securegit key import-recovery --in recovery.enc'],
  },
  agent: {
    usage: 'securegit agent <install|list>',
    summary: 'Write instruction files so a coding agent (Claude, Cursor, Copilot, Kiro) knows securegit\'s workflow.',
    subcommands: ['install', 'list'],
  },
  'agent install': {
    usage: `securegit agent install [${AGENT_TARGET_IDS.join('|')}]... [--force]`,
    summary: 'Write the skill/rule/instructions file for the given targets, or all of them with none given.',
    details: [
      'Idempotent and safe to re-run. Refuses (exit 2) to overwrite a file at the same path this',
      'command did not originally write; --force overwrites it anyway.',
    ],
    flags: [{ flag: '--force', desc: 'overwrite a file this command did not originally write' }],
    examples: ['securegit agent install', 'securegit agent install claude cursor'],
  },
  'agent list': {
    usage: 'securegit agent list [<target>...] [--json]',
    summary: 'Print the targets and exact paths `agent install` would write, without writing anything.',
    examples: ['securegit agent list'],
  },
  clean: {
    usage: 'securegit clean -- <path>',
    summary: 'Invoked by Git on checkin: plaintext on stdin, ciphertext on stdout. Not meant to be run by hand.',
    examples: ['git config filter.securegit.clean "securegit clean -- %f"'],
  },
  smudge: {
    usage: 'securegit smudge -- <path>',
    summary: 'Invoked by Git on checkout: ciphertext on stdin, plaintext on stdout. Not meant to be run by hand.',
    flags: [{ flag: '--strict', desc: 'fail rather than passing ciphertext through when locked' }],
    examples: ['git config filter.securegit.smudge "securegit smudge -- %f"'],
  },
  textconv: {
    usage: 'securegit textconv -- <file>',
    summary: 'Invoked by Git for diff display: plaintext to stdout, never written to the object database.',
    examples: ['git config diff.securegit.textconv "securegit textconv --"'],
  },
  merge: {
    usage: 'securegit merge -- <base> <ours> <theirs> <markerSize> <path>',
    summary: 'The three-way merge driver Git invokes on a protected path. Writes ciphertext to <ours> directly.',
    examples: ['git config merge.securegit.driver "securegit merge -- %O %A %B %L %P"'],
  },
  'filter-process': {
    usage: 'securegit filter-process',
    summary: 'The long-running pkt-line filter server (git config filter.securegit.process). Not run by hand.',
    examples: ['git config filter.securegit.process "securegit filter-process"'],
  },
  encrypt: {
    usage: 'securegit encrypt <file> [--out <file>]',
    summary: 'Envelope a file outside of any Git repository, using the same code path as the filter.',
    details: ["'-' works as stdin/stdout for either argument."],
    examples: ['securegit encrypt secret.txt --out secret.txt.enc', 'securegit encrypt - --out - < in > out'],
  },
  decrypt: {
    usage: 'securegit decrypt <file> [--out <file>]',
    summary: 'The inverse of encrypt.',
    examples: ['securegit decrypt secret.txt.enc --out secret.txt'],
  },
  inspect: {
    usage: 'securegit inspect <file> [--json]',
    summary: 'Print an envelope\'s header fields (generation, algorithm, flags) without needing a key.',
    flags: [{ flag: '--json', desc: 'machine-readable header fields to stdout' }],
    examples: ['securegit inspect secret.txt.enc'],
  },
};

const GLOBAL_FLAGS: Array<{ flag: string; desc: string }> = [
  { flag: '--repo <path>', desc: 'operate on a repository other than the current directory' },
  { flag: '--json', desc: 'machine-readable output, for the commands that support it' },
  { flag: '--quiet', desc: 'suppress one-line success confirmations; never hides errors or a report' },
  { flag: '-v, --verbose', desc: 'per-file tracing on clean/smudge/merge, to stderr; never plaintext or key material' },
  { flag: '-h, --help', desc: 'show help — for a command, or, alone, this overview' },
];

const ENV_VARS: Array<{ name: string; desc: string }> = [
  { name: 'SECUREGIT_PASSPHRASE', desc: 'unlocks the local keyring non-interactively, instead of a prompt' },
  { name: 'SECUREGIT_SESSION_KEY', desc: 'a session file\'s own content, passed through instead of reading the file' },
  { name: 'SECUREGIT_PIV_PIN', desc: 'a YubiKey PIV provider\'s PIN, non-interactively' },
  { name: 'SECUREGIT_RECOVERY_CODE', desc: '`key import-recovery`\'s recovery code, non-interactively' },
  { name: 'SECUREGIT_IDENTITY_FILE', desc: 'an identity file other than the default `~/.securegit/identity.json`' },
  {
    name: 'SECUREGIT_HOME',
    desc: 'overrides where ~/.securegit/ is resolved from — set this if the same repository is also used from a different home directory (WSL vs. native Windows is the common case)',
  },
];

const EXIT_CODE_HELP: Array<{ code: number; meaning: string }> = [
  { code: EXIT_OK, meaning: 'success' },
  { code: EXIT_LOCKED, meaning: 'locked — a key was needed and unavailable; run `securegit unlock`' },
  { code: EXIT_MISCONFIGURED, meaning: 'misconfigured — repository, attributes, or git config wrong' },
  { code: EXIT_CRYPTO, meaning: 'cryptographic failure — wrong key for this file, or corrupted ciphertext' },
  { code: EXIT_USAGE, meaning: 'usage error — missing argument, unknown flag, or unknown command' },
  { code: EXIT_LEAK, meaning: '`verify` found a leak — a protected path is not actually encrypted' },
];

function formatFlags(flags: Array<{ flag: string; desc: string }>): string {
  const width = Math.max(...flags.map((f) => f.flag.length));
  return flags.map((f) => `  ${f.flag.padEnd(width)}  ${f.desc}`).join('\n');
}

function renderCommandHelp(name: string, entry: HelpEntry): string {
  const lines = [`usage: ${entry.usage}`, '', entry.summary];
  if (entry.details && entry.details.length > 0) {
    lines.push('', ...entry.details);
  }
  if (entry.subcommands && entry.subcommands.length > 0) {
    lines.push(
      '',
      'Subcommands:',
      ...entry.subcommands.map((s) => `  ${s}`),
      '',
      `Run \`securegit ${name} <subcommand> --help\` for details on one of these.`,
    );
  }
  if (entry.flags && entry.flags.length > 0) {
    lines.push('', 'Flags:', formatFlags(entry.flags));
  }
  if (entry.examples && entry.examples.length > 0) {
    lines.push('', 'Examples:', ...entry.examples.map((e) => `  ${e}`));
  }
  lines.push('', 'See docs/securegit/05-cli-guide.md and specs/securegit/10-cli-contract.md for full details.');
  return lines.join('\n');
}

/**
 * Shown once, only on the bare top-level `securegit --help`/`-h`/`help` —
 * never on a per-command `--help`, never on stdout (which must stay
 * data-only for a filter tool — 10-cli-contract.md's "stdout carries data
 * only"), and never on any command Git itself invokes. A splash earns its
 * place only where output is already 100% for a human who typed `--help`
 * on purpose; anywhere else it would be noise at best and, on stdout, file
 * corruption. `--quiet` suppresses it — the rest of the help text (the
 * part someone's actually asking for) still prints either way.
 */
const SPLASH = `
       o--o  O  o--o
     o-o  |  |  |  o-o
   o-o o--o  |  o--o o-o
   |   |  \\ (*) /  |   |
   o---o---\\(o)/---o---o
        \\  /   \\  /
        / /|_|_|\\ \\
       / /  | |  \\ \\
      o--'  / \\  '--o

       T R I N O R I S
`;

function renderTopLevelHelp(quiet: boolean): string {
  const lines = [
    ...(quiet ? [] : [SPLASH]),
    'securegit — client-side Git encryption: a transparent clean/smudge filter',
    'that encrypts selected files on your own workstation.',
    '',
    'usage: securegit <command> [args] [flags]',
    '',
  ];
  for (const category of HELP_CATEGORIES) {
    lines.push(`${category.title}:`);
    const width = Math.max(...category.commands.map((c) => c.length));
    for (const name of category.commands) {
      const entry = HELP[name];
      lines.push(`  ${name.padEnd(width)}  ${entry ? entry.summary : ''}`);
    }
    lines.push('');
  }
  lines.push('Global flags:', formatFlags(GLOBAL_FLAGS), '');
  lines.push(
    'Environment variables:',
    formatFlags(ENV_VARS.map((v) => ({ flag: v.name, desc: v.desc }))),
    '',
  );
  lines.push(
    'Run `securegit <command> --help` or `securegit help <command>` for exact flags and examples',
    '(e.g. `securegit key rotate --help`, for a subcommand). `securegit help --json` prints the',
    'same information as a machine-readable manifest.',
    '',
    'Full reference: docs/securegit/05-cli-guide.md, specs/securegit/10-cli-contract.md',
  );
  return lines.join('\n');
}

function helpManifest(): unknown {
  return {
    commands: HELP,
    categories: HELP_CATEGORIES,
    globalFlags: GLOBAL_FLAGS,
    envVars: ENV_VARS,
    exitCodes: EXIT_CODE_HELP,
  };
}

/** `--help`/`-h` before the `--` separator only — a path after it may legally begin with `-`. */
function wantsHelp(args: string[]): boolean {
  const sepIdx = args.indexOf('--');
  const scanned = sepIdx === -1 ? args : args.slice(0, sepIdx);
  return scanned.includes('--help') || scanned.includes('-h');
}

/** `key <subcommand> --help` / `identity <subcommand> --help` — looks up the combined help entry. */
function groupHelp(name: string, args: string[]): string {
  const sub = args.find((a) => !a.startsWith('-'));
  const entry = sub !== undefined ? HELP[`${name} ${sub}`] : undefined;
  return entry ? renderCommandHelp(`${name} ${sub}`, entry) : renderCommandHelp(name, HELP[name]!);
}

function resolvePassphrase(io: CliIO): string {
  const fromEnv = io.env.SECUREGIT_PASSPHRASE;
  if (fromEnv !== undefined && fromEnv.length > 0) return fromEnv;
  return io.stdin.toString('utf8').replace(/\r?\n$/, '');
}

/**
 * A YubiKey PIV PIN, same shape as `resolvePassphrase` — `SECUREGIT_PIV_PIN`
 * first, stdin otherwise. Deliberately its own function, not a shared
 * "resolve any secret" helper: the two are conceptually different secrets
 * (one unlocks a local file, the other authenticates to hardware), and
 * keeping them separate means a future third kind of secret doesn't have to
 * shoehorn itself into a generic name.
 */
function resolvePin(io: CliIO): string {
  const fromEnv = io.env.SECUREGIT_PIV_PIN;
  if (fromEnv !== undefined && fromEnv.length > 0) return fromEnv;
  return io.stdin.toString('utf8').replace(/\r?\n$/, '');
}

function sessionPathFor(config: RepoConfig, io: CliIO): string {
  return resolveSessionPath(config.repoId, io.env, io.home);
}

type Loaded = { ok: true; config: RepoConfig; keys: KeySource } | { ok: false; code: number };

/**
 * `SECUREGIT_PASSPHRASE` as a filter-time source (07-unlock-session.md's
 * "Non-interactive unlock" table, second precedence): unwraps the *local*
 * keyring file directly, bypassing the session entirely — no `unlock` ever
 * has to run, nothing is written to disk. Fails closed (a locked-shaped
 * `KeySource`, never a throw) on a missing local keyring, a wrong
 * passphrase, or a keyring for a different `repoId` — the same set of
 * outcomes `readSession()`/`keySourceFromSessionKey()` already fail closed
 * on, so every source in this precedence chain behaves identically to a
 * caller that only ever sees the returned `KeySource`.
 *
 * Deliberately uncached here: scrypt unwrap is meant to cost real
 * wall-clock time once per unlock, not once per file, and there is no way
 * for a one-shot `clean`/`smudge` process to remember it paid that cost
 * already — each invocation is a fresh process. `runFilterProcess` below
 * caches this per server lifetime instead, which is the one context where
 * "once" is actually achievable without writing a session to disk.
 */
/**
 * Every passphrase-file-shaped provider id actually present in `file`,
 * each given the same `passphrase` — no hardware providers, deliberately:
 * this backs only `keySourceFromPassphraseEnv`, whose whole contract is
 * `SECUREGIT_PASSPHRASE` as a *non-interactive* filter-time source
 * (`ctx.interactive: false` throughout). `yubikey-piv`/`yubikey-fido2`
 * would always self-reject in that context anyway (both check
 * `ctx.interactive` before touching hardware), so including them here
 * would add real subprocess calls for zero possible benefit. `providersFor()`
 * below is the hardware-aware version, used only by genuinely interactive
 * commands.
 */
function passphraseProvidersFor(file: KeyringFile, passphrase: string): KeyProvider[] {
  const ids = new Set<string>();
  for (const gen of file.generations) {
    for (const slot of gen.wrapped) {
      if (slot.provider === 'passphrase-file' || slot.provider.startsWith('passphrase-file:')) {
        ids.add(slot.provider);
      }
    }
  }
  if (ids.size === 0) ids.add('passphrase-file');
  return [...ids].map((id) => new PassphraseFileProvider(() => passphrase, undefined, id));
}

/**
 * Every provider actually configured on `file`'s keyring, one instance per
 * distinct provider id found across every generation's wrapped slots.
 * `unlockKeyring()` tries every slot against every provider given here and
 * keeps whichever succeed (06-key-provider-port.md), so a caller never has
 * to say in advance which one will actually work.
 *
 * Every passphrase-file-shaped id (the unlabeled default `init` always
 * creates, plus any `key add-provider --label` slots) gets a
 * `PassphraseFileProvider` sharing the same already-resolved `passphrase`
 * — harmless even against a hardware-only keyring, since one that never
 * matches any slot just fails its own attempts and `unlockKeyring()`
 * continues past it. `yubikey-piv`'s PIN and `yubikey-fido2`'s touch
 * prompt are genuinely lazy instead, unlike the passphrase: `resolvePin()`
 * (or the real hardware call) only happens if `unlockKeyring()` actually
 * reaches that provider's `unwrap()`, never merely because this function
 * ran. `loadProvider()` failing (the companion package genuinely not
 * installed) degrades to a warning and that one provider being skipped,
 * not a thrown error — a keyring that also has a working passphrase or
 * other provider must still be unlockable.
 */
async function providersFor(file: KeyringFile, io: CliIO, passphrase: string): Promise<KeyProvider[]> {
  const passphraseIds = new Set<string>();
  let hasPiv = false;
  let hasFido2 = false;
  for (const gen of file.generations) {
    for (const slot of gen.wrapped) {
      if (slot.provider === 'passphrase-file' || slot.provider.startsWith('passphrase-file:')) {
        passphraseIds.add(slot.provider);
      } else if (slot.provider === 'yubikey-piv') {
        hasPiv = true;
      } else if (slot.provider === 'yubikey-fido2') {
        hasFido2 = true;
      }
    }
  }
  if (passphraseIds.size === 0) passphraseIds.add('passphrase-file');

  const providers: KeyProvider[] = [...passphraseIds].map(
    (id) => new PassphraseFileProvider(() => passphrase, undefined, id),
  );

  if (hasPiv) {
    // `slot` only matters for init()/wrap() (creating a *new* generation);
    // unwrap() against an existing one reads the slot from the keyring's
    // own persisted state, never this constructor argument.
    try {
      providers.push(await loadProvider('yubikey-piv', { slot: '9d', pin: () => resolvePin(io) }));
    } catch (e) {
      io.stderr((e as Error).message);
    }
  }
  if (hasFido2) {
    try {
      providers.push(await loadProvider('yubikey-fido2', {}));
    } catch (e) {
      io.stderr((e as Error).message);
    }
  }
  return providers;
}

async function keySourceFromPassphraseEnv(
  passphrase: string,
  config: RepoConfig,
  io: { home: string; stderr: (message: string) => void },
): Promise<KeySource> {
  let file;
  try {
    file = await readKeyringFile(resolveKeyringPath(config.repoId, io.home));
  } catch {
    return lockedKeySource(); // no local keyring: this source has nothing to offer
  }
  try {
    return await unlockKeyring(file, passphraseProvidersFor(file, passphrase), {
      expectedRepoId: config.repoId,
      warn: io.stderr,
    });
  } catch {
    return lockedKeySource(); // e.g. a keyring for a different repoId — fail closed, not a throw
  }
}

/**
 * `SECUREGIT_IDENTITY_FILE` (third precedence) names *which* identity to
 * join with, but carries no secret of its own — `SECUREGIT_PASSPHRASE`
 * unlocks it, the same env var `keySourceFromPassphraseEnv` otherwise uses
 * for the *local keyring*. So this isn't really a fourth independent
 * check: when both are set, `SECUREGIT_IDENTITY_FILE` changes what
 * `SECUREGIT_PASSPHRASE` is applied *to* (this identity, not the local
 * keyring) rather than sitting behind it in the precedence order. Mirrors
 * `cmdUnlockViaRecipient`'s core logic exactly, minus the session write —
 * this never touches disk. Fails closed on every step: a missing or
 * unreadable identity file, a wrong passphrase, no matching recipient
 * file, or a recipient file that doesn't cover any generation this
 * identity can decrypt.
 */
async function keySourceFromIdentityFileEnv(
  identityFilePath: string,
  passphrase: string,
  config: RepoConfig,
  io: { cwd: string },
): Promise<KeySource> {
  let identity;
  try {
    identity = await readIdentityFile(identityFilePath);
  } catch {
    return lockedKeySource();
  }
  const provider = new PassphraseFileProvider(() => passphrase);
  let privateKey: Buffer | null;
  try {
    privateKey = await unlockIdentity(identity, [provider]);
  } catch {
    return lockedKeySource();
  }
  if (privateKey === null) return lockedKeySource();
  const identityKeyPair: X25519KeyPair = { publicKey: decodePublicKey(identity.publicKey), privateKey };

  let recipient: RecipientFile;
  try {
    recipient = await readRecipientFile(recipientPath(io.cwd, identity.fingerprint));
  } catch {
    return lockedKeySource();
  }

  return unlockFromRecipientFile(recipient, identityKeyPair, config.repoId);
}

/**
 * The read side shared by clean/smudge/textconv/encrypt/decrypt: config,
 * then whichever key source applies (07-unlock-session.md's "Non-interactive
 * unlock" precedence) — `SECUREGIT_SESSION_KEY`, then `SECUREGIT_PASSPHRASE`
 * (itself branching on whether `SECUREGIT_IDENTITY_FILE` is also set — see
 * `keySourceFromIdentityFileEnv`'s doc comment for why that's a branch, not
 * a fourth independent tier), then the session file. The first one present
 * wins outright; it is not merely tried first and fallen back from — a
 * `SECUREGIT_SESSION_KEY` that fails to decode never falls through to
 * `SECUREGIT_PASSPHRASE`, and a `SECUREGIT_PASSPHRASE` that unwraps to
 * nothing (local keyring or identity, whichever applies) never falls
 * through to the session file, matching `keySourceFromSessionKey()`'s own
 * "replaces, does not supplement" behavior.
 */
async function loadKeys(io: CliIO): Promise<Loaded> {
  let config: RepoConfig;
  try {
    config = await readConfig(io.cwd);
  } catch (e) {
    io.stderr((e as Error).message);
    return { ok: false, code: EXIT_MISCONFIGURED };
  }
  const sessionKeyEnv = io.env.SECUREGIT_SESSION_KEY;
  const passphraseEnv = io.env.SECUREGIT_PASSPHRASE;
  const identityFileEnv = io.env.SECUREGIT_IDENTITY_FILE;
  let keys: KeySource;
  if (sessionKeyEnv !== undefined && sessionKeyEnv.length > 0) {
    keys = keySourceFromSessionKey(sessionKeyEnv, {
      repoId: config.repoId,
      ...(io.now !== undefined ? { now: io.now } : {}),
    });
  } else if (passphraseEnv !== undefined && passphraseEnv.length > 0) {
    keys =
      identityFileEnv !== undefined && identityFileEnv.length > 0
        ? await keySourceFromIdentityFileEnv(identityFileEnv, passphraseEnv, config, io)
        : await keySourceFromPassphraseEnv(passphraseEnv, config, io);
  } else {
    keys = await readSession({
      repoId: config.repoId,
      path: sessionPathFor(config, io),
      warn: io.stderr,
      ...(io.now !== undefined ? { now: io.now } : {}),
    });
  }
  return { ok: true, config, keys };
}

// ---------------------------------------------------------------------------
// repository lifecycle
// ---------------------------------------------------------------------------

/**
 * `initConfig()` itself (`@trinoris/securelib`) no longer checks this —
 * docs/securegit/01-architecture.md's Phase 2: a git-agnostic library has no business
 * assuming its caller is a git repository. `securegit` is the consumer
 * that actually requires one, so the check lives here instead.
 */
async function isGitRepo(repoDir: string): Promise<boolean> {
  try {
    // A worktree's `.git` is a file (`gitdir: …`), not a directory — either
    // counts, since both mean "this is a real Git checkout".
    await stat(join(repoDir, '.git'));
    return true;
  } catch {
    return false;
  }
}

async function cmdInit(args: string[], io: CliIO): Promise<number> {
  if (!(await isGitRepo(io.cwd))) {
    io.stderr(`securegit: ${io.cwd} is not a Git repository (no .git found)`);
    return EXIT_USAGE;
  }

  const bindPath = args.includes('--bind-path');

  const padToIdx = args.indexOf('--pad-to');
  const padToArg = padToIdx !== -1 ? args[padToIdx + 1] : undefined;
  let padTo: number | undefined;
  if (padToArg !== undefined) {
    padTo = Number(padToArg);
    if (!Number.isInteger(padTo) || padTo < 0) {
      io.stderr(`securegit: --pad-to must be a non-negative integer, got '${padToArg}'`);
      return EXIT_USAGE;
    }
  }

  let config: RepoConfig;
  try {
    config = await initConfig(io.cwd, { bindPath, home: io.home, ...(padTo !== undefined ? { padTo } : {}) });
  } catch (e) {
    let message = (e as Error).message;
    // "Already initialised" only means config.json exists — that file is
    // inside the repo (cwd-relative), so it's found identically from any
    // environment touching this same physical repo. It says nothing about
    // whether *this* home directory has a usable local keyring (home-
    // relative, never shared the same way) — check separately, so this
    // error and `key list`'s "no keyring found" give consistent guidance
    // instead of looking like two unrelated problems.
    if (e instanceof ConfigError && message.includes('already initialised')) {
      try {
        const existing = await readConfig(io.cwd);
        await readKeyringFile(resolveKeyringPath(existing.repoId, io.home));
      } catch {
        const existing = await readConfig(io.cwd).catch(() => null);
        const candidate = existing !== null ? await findLikelyWindowsHome(existing.repoId).catch(() => null) : null;
        message +=
          '\n  note:   this home directory has no local keyring for that repository — if it was set\n' +
          '          up from a different environment (WSL vs. native Windows, for example), set\n' +
          '          SECUREGIT_HOME to point at it; otherwise `securegit key import-recovery`, or\n' +
          '          ask an existing member to run `securegit key add-recipient` for you' +
          (candidate !== null
            ? `\n  found:  a keyring for this exact repository exists at ${candidate} — if that's yours:\n` +
              `          export SECUREGIT_HOME=${candidate}`
            : '');
      }
    }
    io.stderr(message);
    return EXIT_USAGE;
  }

  const passphrase = resolvePassphrase(io);
  const provider = new PassphraseFileProvider(() => passphrase);

  let created;
  try {
    created = await createKeyring(config.repoId, [provider]);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_USAGE;
  }

  const keyringPath = resolveKeyringPath(config.repoId, io.home);
  await writeKeyringFile(keyringPath, created.file);

  io.info(
    `securegit: initialized repository ${config.repoId}\n` +
      `  keyring: ${keyringPath}\n` +
      `  next:    securegit protect <pattern>, then securegit unlock`,
  );
  return EXIT_OK;
}

async function cmdInstall(args: string[], io: CliIO): Promise<number> {
  const useProcess = args.includes('--process');
  const force = args.includes('--force');
  const required = !args.includes('--no-required');
  const binIdx = args.indexOf('--bin');
  const bin = binIdx !== -1 ? args[binIdx + 1] : undefined;

  try {
    await install({
      repoDir: io.cwd,
      process: useProcess,
      required,
      force,
      ...(bin !== undefined ? { bin } : {}),
    });
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_MISCONFIGURED;
  }
  io.info(`securegit: filter configuration installed${useProcess ? ' (process form)' : ''}`);
  return EXIT_OK;
}

async function cmdProtect(args: string[], io: CliIO): Promise<number> {
  const given = args.filter((a) => !a.startsWith('--'));
  const usingDefaults = given.length === 0;
  const patterns = usingDefaults ? DEFAULT_PROTECT_PATTERNS : given;
  const residuePatterns = !args.includes('--no-residue');
  try {
    await protect(io.cwd, patterns, { residuePatterns });
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_USAGE;
  }
  io.info(
    usingDefaults
      ? `securegit: no pattern given — protecting common secret-shaped defaults:\n` +
          `  ${patterns.join(', ')}\n` +
          `  action: \`securegit unprotect <pattern>\` removes one that doesn't fit;\n` +
          `          \`securegit protect <pattern>\` adds more`
      : `securegit: protecting ${patterns.join(', ')}`,
  );
  return EXIT_OK;
}

async function cmdUnprotect(args: string[], io: CliIO): Promise<number> {
  const patterns = args.filter((a) => !a.startsWith('--'));
  if (patterns.length === 0) {
    io.stderr('securegit: unprotect requires at least one pattern');
    return EXIT_USAGE;
  }
  try {
    await unprotect(io.cwd, patterns);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_USAGE;
  }
  io.info(
    `securegit: no longer protecting ${patterns.join(', ')}\n` +
      '  warning: blobs already committed under this pattern stay encrypted — this only\n' +
      '           changes what happens the next time the file is edited and re-added\n' +
      '  action: git add .gitattributes && git commit',
  );
  return EXIT_OK;
}

// ---------------------------------------------------------------------------
// keys and session
// ---------------------------------------------------------------------------

/** The tail shared by every path that ends in "write a session for this KeySource". */
async function writeUnlockSession(
  config: RepoConfig,
  io: CliIO,
  keys: KeySource,
  args: string[],
): Promise<number> {
  const current = keys.current();
  if (current === null) return EXIT_LOCKED;

  const ttlIdx = args.indexOf('--ttl');
  const ttlArg = ttlIdx !== -1 ? args[ttlIdx + 1] : undefined;
  const ttlSeconds = ttlArg !== undefined ? Number(ttlArg) : undefined;

  const entries = keys.available().map((keyId) => ({ keyId, rmk: keys.find(keyId)! }));
  await writeSession({
    repoId: config.repoId,
    path: sessionPathFor(config, io),
    entries,
    current: current.keyId,
    ...(ttlSeconds !== undefined ? { ttlSeconds } : {}),
    ...(io.now !== undefined ? { now: io.now } : {}),
  });
  return EXIT_OK;
}

/**
 * The join flow: a machine with no local keyring but its own identity and a
 * `.securegit/recipients/<its fingerprint>.json` file bootstraps a session
 * straight from that file — no local keyring.json is written. Persisting one
 * would mean wrapping every recovered generation for a fresh local provider,
 * which `keyring.ts` has no primitive for yet (only fresh-generation-1
 * creation and single-new-generation rotation); a session is enough for the
 * common case, and re-running `unlock` each session is a small cost until
 * that primitive exists. See specs/securegit/08-multi-recipient.md.
 */
async function cmdUnlockViaRecipient(config: RepoConfig, args: string[], io: CliIO): Promise<number> {
  let identity;
  try {
    identity = await readIdentityFile(identityPath(io.home));
  } catch {
    io.stderr(
      `securegit: no keyring found for this repository\n` +
        `  action: run \`securegit init\`, or run \`securegit identity init\` and ask an existing ` +
        `member to \`securegit key add-recipient\` your public key`,
    );
    return EXIT_MISCONFIGURED;
  }

  const passphrase = resolvePassphrase(io);
  const provider = new PassphraseFileProvider(() => passphrase);
  const privateKey = await unlockIdentity(identity, [provider]);
  if (privateKey === null) {
    io.stderr('securegit: could not unlock your identity — wrong passphrase');
    return EXIT_LOCKED;
  }
  const identityKeyPair: X25519KeyPair = { publicKey: decodePublicKey(identity.publicKey), privateKey };

  let recipient: RecipientFile;
  try {
    recipient = await readRecipientFile(recipientPath(io.cwd, identity.fingerprint));
  } catch {
    io.stderr(
      `securegit: no recipient file for this identity (${identity.fingerprint})\n` +
        `  action: ask a member with access to run \`securegit key add-recipient ${identity.publicKey}\``,
    );
    return EXIT_MISCONFIGURED;
  }

  const keys = unlockFromRecipientFile(recipient, identityKeyPair, config.repoId);
  if (keys.current() === null) {
    io.stderr(
      'securegit: could not unlock — the recipient file does not cover any generation this identity can decrypt',
    );
    return EXIT_LOCKED;
  }

  const code = await writeUnlockSession(config, io, keys, args);
  if (code === EXIT_OK) {
    io.info(`securegit: unlocked via recipient (generation ${keys.current()!.keyId})`);
  }
  return code;
}

async function cmdUnlock(args: string[], io: CliIO): Promise<number> {
  let config: RepoConfig;
  try {
    config = await readConfig(io.cwd);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_MISCONFIGURED;
  }

  const keyringPath = resolveKeyringPath(config.repoId, io.home);
  let file;
  try {
    file = await readKeyringFile(keyringPath);
  } catch {
    return await cmdUnlockViaRecipient(config, args, io);
  }

  const passphrase = resolvePassphrase(io);
  const candidates = await providersFor(file, io, passphrase);
  let keys;
  try {
    keys = await unlockKeyring(file, candidates, {
      warn: io.stderr,
      expectedRepoId: config.repoId,
    });
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_MISCONFIGURED;
  }

  const current = keys.current();
  if (current === null) {
    io.stderr(
      "securegit: could not unlock — wrong passphrase, or this keyring holds none of the repository's generations",
    );
    return EXIT_LOCKED;
  }

  // 06-key-provider-port.md: a keyring wrapped at an old scrypt cost is
  // re-wrapped at the current one on the next successful unlock. Never
  // blocks the unlock itself — this is hygiene, not a precondition for it.
  try {
    const { file: rewrapped, changed } = await rewrapOutdatedGenerations(
      file,
      passphraseProvidersFor(file, passphrase),
      keys,
    );
    if (changed) {
      await writeKeyringFile(keyringPath, rewrapped);
      io.info('securegit: keyring re-wrapped at the current scrypt cost');
    }
  } catch {
    // best-effort — a re-wrap failure here must not fail the unlock
  }

  const code = await writeUnlockSession(config, io, keys, args);
  io.info(`securegit: unlocked (generation ${current.keyId})`);
  return code;
}

async function cmdLock(_args: string[], io: CliIO): Promise<number> {
  let config: RepoConfig;
  try {
    config = await readConfig(io.cwd);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_MISCONFIGURED;
  }
  await lockSession({ repoId: config.repoId, path: sessionPathFor(config, io) });
  io.info('securegit: locked');
  return EXIT_OK;
}

async function cmdStatus(args: string[], io: CliIO): Promise<number> {
  const loaded = await loadKeys(io);
  if (!loaded.ok) return loaded.code;
  const current = loaded.keys.current();
  const recovery = await recoveryPathStatus({ repoDir: io.cwd, home: io.home });

  if (args.includes('--json')) {
    const metadata = await metadataReport({ repoDir: io.cwd });
    writeJson(io, {
      repository: io.cwd,
      repoId: loaded.config.repoId,
      bindPath: loaded.config.bindPath,
      padTo: loaded.config.padTo,
      locked: current === null,
      generation: current ? current.keyId : null,
      metadata,
      recoveryPaths: recovery,
    });
    return current ? EXIT_OK : EXIT_LOCKED;
  }

  io.stderr(
    `repository   ${io.cwd}\n` +
      `repoId       ${loaded.config.repoId}\n` +
      `bindPath     ${loaded.config.bindPath}\n` +
      `padTo        ${loaded.config.padTo}\n` +
      `session      ${current ? `unlocked, generation ${current.keyId}` : 'locked'}\n` +
      `metadata     M1–M12 (14-metadata-leakage.md): securegit status --json` +
      (recovery?.warn
        ? `\nrecovery     ⚠ only ${recovery.paths} recovery path${recovery.paths === 1 ? '' : 's'}, no export on record — see 09-rotation-recovery.md`
        : ''),
  );
  return current ? EXIT_OK : EXIT_LOCKED;
}

// ---------------------------------------------------------------------------
// identity and recipients — see 08-multi-recipient.md
// ---------------------------------------------------------------------------

async function cmdIdentityInit(args: string[], io: CliIO): Promise<number> {
  const labelIdx = args.indexOf('--label');
  const label = labelIdx !== -1 ? (args[labelIdx + 1] ?? '') : '';
  const generateSigningKeyFlag = args.includes('--generate-signing-key');
  const path = identityPath(io.home);

  try {
    await readIdentityFile(path);
    io.stderr(`securegit: an identity already exists at ${path}`);
    return EXIT_USAGE;
  } catch {
    // ENOENT is the expected case — fall through and create one.
  }

  const passphrase = resolvePassphrase(io);
  const provider = new PassphraseFileProvider(() => passphrase);
  let created;
  try {
    created = await createIdentity(label, provider);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_USAGE;
  }

  // Commit signing (specs/securegit/08-multi-recipient.md, "Commit
  // signing"): detecting an existing key is unconditional — read-only,
  // nothing new comes into being, so it needs no flag and no confirmation.
  // Generating one is opt-in, and only when detection found nothing to
  // use instead — matches "never silently create new key material"
  // everywhere else this CLI touches key state (`init`, `install`).
  let signingKeyNote: string;
  const detectedSigningKey = await detectLocalSigningKey(io.cwd, io.home);
  if (detectedSigningKey) {
    created.file.signingKey = detectedSigningKey;
    signingKeyNote = `\n  signing key: detected (${signingKeyFingerprint(detectedSigningKey)})`;
  } else if (generateSigningKeyFlag) {
    const genPath = signingKeyPath(io.home);
    const generated = await generateSigningKeyPair(genPath);
    created.file.signingKey = generated.publicKey;
    signingKeyNote = `\n  signing key: generated at ${genPath} (${signingKeyFingerprint(generated.publicKey)})`;
  } else {
    signingKeyNote =
      '\n  signing key: none found — run `securegit identity init --generate-signing-key`,' +
      '\n               or `git config user.signingkey <path>` and re-run';
  }

  await writeIdentityFile(path, created.file);

  io.info(
    `securegit: identity created\n` +
      `  fingerprint: ${created.file.fingerprint}\n` +
      `  public key:  ${created.file.publicKey}${signingKeyNote}\n` +
      `  next:        share the public key above with someone who already has access`,
  );
  return EXIT_OK;
}

async function cmdIdentityShow(_args: string[], io: CliIO): Promise<number> {
  let file;
  try {
    file = await readIdentityFile(identityPath(io.home));
  } catch {
    io.stderr(`securegit: no identity found\n  action: run \`securegit identity init\``);
    return EXIT_MISCONFIGURED;
  }
  io.stderr(`fingerprint  ${file.fingerprint}\n` + `label        ${file.label}\n` + `public key   ${file.publicKey}`);
  return EXIT_OK;
}

async function cmdIdentity(args: string[], io: CliIO): Promise<number> {
  const [sub, ...rest] = args;
  switch (sub) {
    case 'init':
      return await cmdIdentityInit(rest, io);
    case 'show':
      return await cmdIdentityShow(rest, io);
    default:
      io.stderr(
        sub ? `securegit: unknown identity subcommand '${sub}'` : 'usage: securegit identity <init|show>',
      );
      return EXIT_USAGE;
  }
}

async function cmdKeyAddRecipient(args: string[], io: CliIO): Promise<number> {
  const pubkeyArg = args.find((a) => !a.startsWith('--'));
  if (!pubkeyArg) {
    io.stderr('usage: securegit key add-recipient <pubkey> [--label <label>] [--signing-key <ssh-public-key>]');
    return EXIT_USAGE;
  }
  const labelIdx = args.indexOf('--label');
  const label = labelIdx !== -1 ? (args[labelIdx + 1] ?? '') : '';
  const signingKeyIdx = args.indexOf('--signing-key');
  const signingKeyArg = signingKeyIdx !== -1 ? args[signingKeyIdx + 1] : undefined;

  let recipientPublicKey: Buffer;
  try {
    recipientPublicKey = decodePublicKey(pubkeyArg);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_USAGE;
  }

  // Optional — specs/securegit/08-multi-recipient.md, "Commit signing".
  // Validated up front (before ever touching keys/disk) the same way the
  // primary pubkey is above: a malformed value refuses cleanly rather than
  // writing a recipient file with a signing key nothing could ever match
  // against.
  let signingKeyFp = '';
  if (signingKeyArg !== undefined) {
    try {
      signingKeyFp = signingKeyFingerprint(signingKeyArg);
    } catch (e) {
      io.stderr((e as Error).message);
      return EXIT_USAGE;
    }
  }

  const loaded = await loadKeys(io);
  if (!loaded.ok) return loaded.code;
  if (loaded.keys.current() === null) {
    io.stderr('securegit: repository is locked; run `securegit unlock`');
    return EXIT_LOCKED;
  }

  const wrapped = wrapAllGenerations(
    loaded.keys,
    loaded.keys.available(),
    recipientPublicKey,
    loaded.config.repoId,
  );
  const fingerprint = identityFingerprint(recipientPublicKey);

  // Not an error if absent: the person adding a recipient may only have
  // direct keyring access themselves, having never run `identity init`.
  let addedBy = '';
  try {
    addedBy = (await readIdentityFile(identityPath(io.home))).fingerprint;
  } catch {
    // no local identity
  }

  const file: RecipientFile = {
    version: 1,
    fingerprint,
    publicKey: pubkeyArg,
    label,
    addedAt: (io.now ? io.now() : new Date()).toISOString(),
    addedBy,
    ...(signingKeyArg !== undefined ? { signingKey: signingKeyArg } : {}),
    keys: wrapped,
  };
  await writeRecipientFile(recipientPath(io.cwd, fingerprint), file);

  io.info(
    `securegit: added recipient ${fingerprint}${label ? ` (${label})` : ''}` +
      (signingKeyArg !== undefined ? `\n  signing key: ${signingKeyFp}` : '') +
      `\n  action: git add .securegit/recipients && git commit && git push`,
  );
  return EXIT_OK;
}

async function cmdKeyRemoveRecipient(args: string[], io: CliIO): Promise<number> {
  const fingerprint = args.find((a) => !a.startsWith('--'));
  if (!fingerprint) {
    io.stderr('usage: securegit key remove-recipient <fingerprint>');
    return EXIT_USAGE;
  }
  const path = recipientPath(io.cwd, fingerprint);
  // Read before deleting: the file itself is the only record of which
  // generations this recipient held, and once it's gone there is no way to
  // reconstruct that for the removed-recipients log below.
  let removed: RecipientFile;
  try {
    removed = await readRecipientFile(path);
  } catch {
    io.stderr(`securegit: no recipient file for ${fingerprint}`);
    return EXIT_USAGE;
  }
  await unlink(path);

  let removedBy = '';
  try {
    removedBy = (await readIdentityFile(identityPath(io.home))).fingerprint;
  } catch {
    // no local identity — not an error, same as add-recipient's addedBy
  }
  const generations = Object.keys(removed.keys)
    .map(Number)
    .filter((n) => Number.isInteger(n))
    .sort((a, b) => a - b);
  await appendRemovedRecipientLogEntry(removedRecipientsLogPath(io.cwd), {
    fingerprint,
    label: removed.label,
    removedAt: (io.now ? io.now() : new Date()).toISOString(),
    removedBy,
    generations,
  });

  io.info(
    `securegit: removed recipient ${fingerprint}\n` +
      `  warning: they can still read every blob committed under generations they already held\n` +
      `  action: \`securegit key rotate\` then \`securegit reencrypt\` to stop them receiving new ones\n` +
      `  action: git add .securegit/recipients .securegit/removed-recipients.json && git commit && git push`,
  );
  return EXIT_OK;
}

/**
 * See specs/securegit/09-rotation-recovery.md. Refuses a dirty working tree
 * (so the recipient-rewrap side effect is reviewable, not a surprise) and a
 * locked repository, generates generation `current + 1`, wraps it for every
 * configured provider (v1: just `passphrase-file`) and every existing
 * recipient, and invalidates the session so the next operation re-reads the
 * keyring.
 */
async function cmdKeyRotate(args: string[], io: CliIO): Promise<number> {
  const bindPath = args.includes('--bind-path');

  // Locked has to be checked before the git-status dirty check, not after:
  // `git status` needs to run `clean` to compare a plaintext worktree
  // against a ciphertext index correctly, and `clean` fails closed when
  // locked (F1) — so on a locked repository, checking status first would
  // surface a confusing "could not check git status" instead of the actual,
  // more specific reason.
  const loaded = await loadKeys(io);
  if (!loaded.ok) return loaded.code;
  if (loaded.keys.current() === null) {
    io.stderr('securegit: repository is locked; run `securegit unlock`');
    return EXIT_LOCKED;
  }

  // Load recipients once, here — reused both for the confirmation gate and
  // (once confirmed) the rewrap loop below, so a recipient someone forgot
  // was added or removed since they last checked is caught before anything
  // is actually rotated, not discovered afterward in the rewrap count.
  let recipientEntries: { path: string; recipient: RecipientFile }[] = [];
  try {
    const files = (await readdir(recipientsDir(io.cwd))).filter((f) => f.endsWith('.json'));
    for (const entry of files) {
      const path = recipientPath(io.cwd, entry.replace(/\.json$/, ''));
      recipientEntries.push({ path, recipient: await readRecipientFile(path) });
    }
  } catch {
    // no recipients directory — nothing to confirm or rewrap
  }

  const confirmIdx = args.indexOf('--confirm-recipients');
  const confirmArg = confirmIdx !== -1 ? args[confirmIdx + 1] : undefined;
  const confirmed = confirmArg !== undefined ? Number(confirmArg) : undefined;
  if (confirmed === undefined || !Number.isInteger(confirmed) || confirmed !== recipientEntries.length) {
    const list =
      recipientEntries.length > 0
        ? recipientEntries
            .map(({ recipient: r }) => `  ${r.fingerprint}${r.label ? ` (${r.label})` : ''}`)
            .join('\n')
        : '  (none)';
    io.stderr(
      `securegit: rotate will rewrap the new generation for ${recipientEntries.length} ` +
        `recipient${recipientEntries.length === 1 ? '' : 's'}\n${list}\n` +
        `  action: re-run with --confirm-recipients ${recipientEntries.length} to proceed`,
    );
    return EXIT_USAGE;
  }

  let statusOutput: string;
  try {
    // The spawned `git` needs to see this CliIO's own `home`, explicitly,
    // not whatever HOME the calling process happens to have. In the real
    // binary these already coincide (`io.env` is `process.env`); explicit
    // here mainly for tests that inject a different `home`.
    //
    // `git status`'s dirty-check has to actually run our `clean` filter, as
    // a real nested subprocess, to compare the worktree's plaintext against
    // the staged ciphertext — so whatever env this spawn gets, that filter
    // sees too. `SECUREGIT_SESSION_KEY`/`SECUREGIT_PASSPHRASE`/
    // `SECUREGIT_IDENTITY_FILE` authenticate *this* `runCli()` invocation
    // (07-unlock-session.md); they were never meant to cascade into a
    // subprocess this invocation merely spawns, which already has its own
    // valid session to read from `unlock` moments earlier. Left in, they'd
    // make every dirty-check pay a real scrypt cost it has no reason to pay
    // — slow enough, nested inside a real subprocess, to destabilize CI
    // under load, not just wasteful locally.
    const { SECUREGIT_SESSION_KEY: _sk, SECUREGIT_PASSPHRASE: _pp, SECUREGIT_IDENTITY_FILE: _idf, ...rest } =
      io.env;
    // `rest` (an injected CliIO's env in tests) is not guaranteed to carry
    // `PATH` at all — it exists to inject specific variables for a test,
    // not to simulate a full realistic environment. Without it, git can
    // still be found (the OS falls back to a default search path that
    // usually includes it), but the *filter* git then spawns as part of
    // this very check often can't be: a version-managed or CI-installed
    // `node` typically lives somewhere that default fallback path doesn't
    // reach. Falls back to this process's own PATH, exactly like the real
    // binary already gets for free since its `io.env` *is* `process.env`.
    const env: NodeJS.ProcessEnv = { ...rest, HOME: io.home };
    if (env.PATH === undefined) env.PATH = process.env.PATH;
    const { stdout } = await execFile('git', ['status', '--porcelain'], { cwd: io.cwd, env });
    statusOutput = stdout;
  } catch (e) {
    io.stderr(`securegit: could not check git status: ${(e as Error).message}`);
    return EXIT_USAGE;
  }
  if (statusOutput.trim().length > 0) {
    io.stderr(
      'securegit: refusing to rotate with uncommitted changes\n' +
        '  action: commit or stash first, then retry',
    );
    return EXIT_USAGE;
  }

  const keyringPath = resolveKeyringPath(loaded.config.repoId, io.home);
  let file;
  try {
    file = await readKeyringFile(keyringPath);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_MISCONFIGURED;
  }

  const passphrase = resolvePassphrase(io);
  const provider = new PassphraseFileProvider(() => passphrase);
  const rotated = await rotateKeyring(file, [provider]);
  const newGeneration = rotated.file.current;
  const newFingerprint = keyFingerprint(rotated.rmk);

  let rewrapped = 0;
  for (const { path, recipient } of recipientEntries) {
    const recipientPublicKey = decodePublicKey(recipient.publicKey);
    recipient.keys[String(newGeneration)] = wrapForRecipient({
      recipientPublicKey,
      repoId: loaded.config.repoId,
      generation: newGeneration,
      fingerprint: newFingerprint,
      rmk: rotated.rmk,
    });
    await writeRecipientFile(path, recipient);
    rewrapped += 1;
  }

  await writeKeyringFile(keyringPath, rotated.file);
  // Config, not the keyring: bindPath is a repository-wide encryption
  // policy, not something recorded per generation — 05-key-hierarchy.md.
  // Written after the keyring succeeds, so a failure here never leaves a
  // rotated-but-not-yet-persisted keyring silently unrecorded.
  if (bindPath) await setBindPath(io.cwd, true);
  await lockSession({ repoId: loaded.config.repoId, path: sessionPathFor(loaded.config, io) });

  io.info(
    `securegit: rotated to generation ${newGeneration}` +
      (bindPath ? ' with bindPath enabled' : '') +
      `\n  recipients rewrapped: ${rewrapped}\n` +
      `  action: securegit unlock` +
      (rewrapped > 0 ? '; git add .securegit/recipients && git commit && git push' : ''),
  );
  return EXIT_OK;
}

/**
 * Exports every generation this session already holds — no separate secret
 * needed, since an unlocked session already has the RMKs in hand. See
 * specs/securegit/09-rotation-recovery.md.
 */
async function cmdKeyExportRecovery(args: string[], io: CliIO): Promise<number> {
  const outIdx = args.indexOf('--out');
  const outFile = outIdx !== -1 ? args[outIdx + 1] : undefined;
  if (!outFile) {
    io.stderr('usage: securegit key export-recovery --out <file>');
    return EXIT_USAGE;
  }

  const loaded = await loadKeys(io);
  if (!loaded.ok) return loaded.code;
  if (loaded.keys.current() === null) {
    io.stderr('securegit: repository is locked; run `securegit unlock`');
    return EXIT_LOCKED;
  }

  const generations = loaded.keys
    .available()
    .map((keyId) => {
      const parsed = parseKeyId(keyId);
      return parsed ? { generation: parsed.generation, rmk: loaded.keys.find(keyId)! } : null;
    })
    .filter((g): g is { generation: number; rmk: Buffer } => g !== null)
    .sort((a, b) => a.generation - b.generation);

  const { code, file } = exportRecovery({ repoId: loaded.config.repoId, generations });
  const outPath = recoveryFilePath(io.cwd, outFile);
  await writeRecoveryFile(outPath, file);

  // Not an error if absent: exporting only requires an unlocked session, not
  // a local identity.
  let exportedBy = '';
  try {
    exportedBy = (await readIdentityFile(identityPath(io.home))).fingerprint;
  } catch {
    // no local identity
  }
  await appendRecoveryLogEntry(recoveryLogPath(io.cwd), {
    exportId: generateExportId(),
    timestamp: (io.now ? io.now() : new Date()).toISOString(),
    exportedBy,
    generations: generations.map((g) => g.generation),
  });

  io.stderr(
    `securegit: exported recovery file to ${outPath}\n` +
      `  generations: ${generations.map((g) => g.generation).join(', ')}\n` +
      `  recovery code — write this down somewhere offline, then discard this output:\n` +
      `  ${formatRecoveryCode(code)}\n` +
      `  this code decrypts every generation above, permanently and irrevocably\n` +
      `  action: git add ${outFile} .securegit/recovery-log.json && git commit && git push`,
  );
  return EXIT_OK;
}

/**
 * import-recovery needs two secrets: the recovery code (to open the file)
 * and a fresh passphrase (for the new local provider this machine becomes a
 * holder under). Each has its own env var; when either falls back to stdin,
 * the code takes line 1 and the passphrase line 2 — the order a human would
 * be asked for them.
 */
function resolveImportRecoverySecrets(io: CliIO): { code: string; passphrase: string } {
  const codeFromEnv = io.env.SECUREGIT_RECOVERY_CODE;
  const passphraseFromEnv = io.env.SECUREGIT_PASSPHRASE;
  const lines = io.stdin.toString('utf8').split(/\r?\n/);
  let next = 0;
  const code = codeFromEnv !== undefined && codeFromEnv.length > 0 ? codeFromEnv : (lines[next++] ?? '');
  const passphrase =
    passphraseFromEnv !== undefined && passphraseFromEnv.length > 0
      ? passphraseFromEnv
      : (lines[next++] ?? '');
  return { code, passphrase };
}

/**
 * Rebuilds a full local keyring from a recovery file plus its code, wrapped
 * by a newly chosen passphrase. See specs/securegit/09-rotation-recovery.md
 * and `keyringFromRecoveredGenerations` in keyring.ts.
 */
async function cmdKeyImportRecovery(args: string[], io: CliIO): Promise<number> {
  const inIdx = args.indexOf('--in');
  const inFile = inIdx !== -1 ? args[inIdx + 1] : undefined;
  if (!inFile) {
    io.stderr('usage: securegit key import-recovery --in <file>');
    return EXIT_USAGE;
  }

  let config: RepoConfig;
  try {
    config = await readConfig(io.cwd);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_MISCONFIGURED;
  }

  let recoveryFile;
  const inPath = recoveryFilePath(io.cwd, inFile);
  try {
    recoveryFile = await readRecoveryFile(inPath);
  } catch (e) {
    io.stderr(`securegit: could not read recovery file at ${inPath}: ${(e as Error).message}`);
    return EXIT_USAGE;
  }

  // Checked here, ahead of decryption, so a wrong-repo file (misconfigured)
  // and a wrong code (locked) get the exit codes 10-cli-contract.md assigns
  // them, rather than one error class collapsing the distinction.
  if (recoveryFile.repoId !== config.repoId) {
    io.stderr(
      `securegit: this recovery file belongs to repository ${recoveryFile.repoId}\n` +
        `  this repository is ${config.repoId}`,
    );
    return EXIT_MISCONFIGURED;
  }

  const { code: rawCode, passphrase } = resolveImportRecoverySecrets(io);
  let code: Buffer;
  try {
    code = parseRecoveryCode(rawCode);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_USAGE;
  }

  let recovered;
  try {
    recovered = importRecovery(recoveryFile, code, config.repoId);
  } catch (e) {
    io.stderr((e as Error).message);
    return e instanceof RecoveryError ? EXIT_LOCKED : EXIT_USAGE;
  }

  const provider = new PassphraseFileProvider(() => passphrase);
  let file;
  try {
    file = await keyringFromRecoveredGenerations(config.repoId, recovered, [provider]);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_USAGE;
  }

  const keyringPath = resolveKeyringPath(config.repoId, io.home);
  await writeKeyringFile(keyringPath, file);
  await lockSession({ repoId: config.repoId, path: sessionPathFor(config, io) });

  const generationList = recovered
    .map((g) => g.generation)
    .sort((a, b) => a - b)
    .join(', ');
  io.info(
    `securegit: imported recovery file — local keyring now holds generation${recovered.length === 1 ? '' : 's'} ${generationList}\n` +
      `  keyring: ${keyringPath}\n` +
      `  action: securegit unlock`,
  );
  return EXIT_OK;
}

/**
 * `key add-provider <type> [options]` (06-key-provider-port.md).
 *
 * `passphrase-file [--label <label>]` — a *second, independent* passphrase
 * secret. `--label` becomes part of the new provider's id
 * (`passphrase-file:<label>`); omitted, it collides with the unlabeled
 * `passphrase-file` id `init` always creates, and `addProvider()` refuses
 * that collision with a clear message rather than this command
 * pre-checking it separately.
 *
 * `yubikey-piv --slot <slot>` / `yubikey-fido2 [--device <path>]` — the
 * two real hardware providers, resolved via `@trinoris/securelib`'s
 * `loadProvider()` (a dynamic `import()` of the companion package by
 * naming convention — `npm install @trinoris/securelib-piv`/`-fido2` if
 * it isn't already, surfaced as this command's own error if not). Neither
 * takes `--label`: this command can add at most one of each today,
 * matching the port's own id scheme (`yubikey-piv`/`yubikey-fido2`, no
 * per-device suffix yet) — multiple hardware keys on one repository is a
 * real, separate feature, not built here.
 */
async function cmdKeyAddProvider(args: string[], io: CliIO): Promise<number> {
  const type = args.find((a) => !a.startsWith('--'));
  if (!type) {
    io.stderr('usage: securegit key add-provider <passphrase-file|yubikey-piv|yubikey-fido2> [options]');
    return EXIT_USAGE;
  }

  const loaded = await loadKeys(io);
  if (!loaded.ok) return loaded.code;
  if (loaded.keys.current() === null) {
    io.stderr('securegit: repository is locked; run `securegit unlock`');
    return EXIT_LOCKED;
  }

  const keyringPath = resolveKeyringPath(loaded.config.repoId, io.home);
  let file;
  try {
    file = await readKeyringFile(keyringPath);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_MISCONFIGURED;
  }

  let provider: KeyProvider;
  let id: string;
  let successAction: string;

  if (type === 'passphrase-file') {
    const labelIdx = args.indexOf('--label');
    const label = labelIdx !== -1 ? args[labelIdx + 1] : undefined;
    id = label ? `passphrase-file:${label}` : 'passphrase-file';
    const passphrase = resolvePassphrase(io);
    provider = new PassphraseFileProvider(() => passphrase, undefined, id);
    successAction = 'share the new passphrase with whoever should hold it';
  } else if (type === 'yubikey-piv') {
    const slotIdx = args.indexOf('--slot');
    const slot = slotIdx !== -1 ? args[slotIdx + 1] : undefined;
    if (!slot) {
      io.stderr('usage: securegit key add-provider yubikey-piv --slot <slot>');
      return EXIT_USAGE;
    }
    id = 'yubikey-piv';
    try {
      provider = await loadProvider('yubikey-piv', { slot, pin: () => resolvePin(io) });
    } catch (e) {
      io.stderr((e as Error).message);
      return EXIT_MISCONFIGURED;
    }
    successAction = 'this YubiKey can now unlock the repository — run `securegit unlock` to try it';
  } else if (type === 'yubikey-fido2') {
    const deviceIdx = args.indexOf('--device');
    const device = deviceIdx !== -1 ? args[deviceIdx + 1] : undefined;
    id = 'yubikey-fido2';
    try {
      provider = await loadProvider('yubikey-fido2', device !== undefined ? { device } : {});
    } catch (e) {
      io.stderr((e as Error).message);
      return EXIT_MISCONFIGURED;
    }
    successAction = 'this authenticator can now unlock the repository — run `securegit unlock` to try it';
  } else {
    io.stderr(
      `securegit: unknown provider type '${type}'\n  supported: passphrase-file, yubikey-piv, yubikey-fido2`,
    );
    return EXIT_USAGE;
  }

  let updated;
  try {
    updated = await addProvider(file, provider, loaded.keys);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_USAGE;
  }

  await writeKeyringFile(keyringPath, updated);
  io.info(`securegit: added provider '${id}'\n  action: ${successAction}`);
  return EXIT_OK;
}

/** `key remove-provider <id>` (06-key-provider-port.md). Needs no unlock — it only ever deletes a slot, never re-wraps. */
async function cmdKeyRemoveProvider(args: string[], io: CliIO): Promise<number> {
  const id = args.find((a) => !a.startsWith('--'));
  if (!id) {
    io.stderr('usage: securegit key remove-provider <id>');
    return EXIT_USAGE;
  }

  let config: RepoConfig;
  try {
    config = await readConfig(io.cwd);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_MISCONFIGURED;
  }

  const keyringPath = resolveKeyringPath(config.repoId, io.home);
  let file;
  try {
    file = await readKeyringFile(keyringPath);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_MISCONFIGURED;
  }

  let updated;
  try {
    updated = removeProvider(file, id);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_USAGE;
  }

  await writeKeyringFile(keyringPath, updated);
  io.info(`securegit: removed provider '${id}'`);
  return EXIT_OK;
}

/**
 * `key list` (06-key-provider-port.md/10-cli-contract.md): generations,
 * fingerprints, dates, current marker, and which provider ids can unlock
 * each. No key required — everything here is keyring metadata, not
 * anything that needs decrypting, the same reasoning `verify` and `key
 * export-recovery`'s read side already follow.
 */
async function cmdKeyList(args: string[], io: CliIO): Promise<number> {
  let config: RepoConfig;
  try {
    config = await readConfig(io.cwd);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_MISCONFIGURED;
  }

  let file;
  try {
    file = await readKeyringFile(resolveKeyringPath(config.repoId, io.home));
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_MISCONFIGURED;
  }

  if (args.includes('--json')) {
    writeJson(io, {
      current: file.current,
      generations: file.generations.map((g) => ({
        generation: g.generation,
        fingerprint: g.fingerprint,
        createdAt: g.createdAt,
        providers: g.wrapped.map((w) => w.provider),
      })),
    });
    return EXIT_OK;
  }

  const lines = file.generations.map((g) => {
    const marker = g.generation === file.current ? '*' : ' ';
    const providers = g.wrapped.map((w) => w.provider).join(', ');
    return `${marker} gen ${g.generation}  ${g.fingerprint}  ${g.createdAt}  providers: ${providers}`;
  });
  io.stderr(lines.join('\n'));
  return EXIT_OK;
}

/**
 * `key list-recipients` (10-cli-contract.md): fingerprint, label, added-at,
 * added-by, generations covered — for every `.securegit/recipients/*.json`
 * file. No key required, same as `key list`. Deliberately built on
 * `accessReport()` (13-verify.md) rather than its own enumeration: that
 * report already computes exactly this per recipient, including the
 * `git log`-derived `addedCommit` `verify --access` shows; re-deriving it
 * here would just be a second, easier-to-drift copy of the same walk.
 */
async function cmdKeyListRecipients(args: string[], io: CliIO): Promise<number> {
  try {
    await readConfig(io.cwd);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_MISCONFIGURED;
  }

  const report = await accessReport({ repoDir: io.cwd, home: io.home, env: io.env });

  if (args.includes('--json')) {
    writeJson(io, report.recipients);
    return EXIT_OK;
  }

  if (report.recipients.length === 0) {
    io.stderr('  (none)');
    return EXIT_OK;
  }

  const lines = report.recipients.map(
    (r) =>
      `  ${r.fingerprint}  ${r.label}  added ${r.addedAt.slice(0, 10)} by ${r.addedBy || '(unknown)'}  ` +
      `gen ${r.generations.join(',')}`,
  );
  io.stderr(lines.join('\n'));
  return EXIT_OK;
}

async function cmdKey(args: string[], io: CliIO): Promise<number> {
  const [sub, ...rest] = args;
  switch (sub) {
    case 'add-recipient':
      return await cmdKeyAddRecipient(rest, io);
    case 'remove-recipient':
      return await cmdKeyRemoveRecipient(rest, io);
    case 'rotate':
      return await cmdKeyRotate(rest, io);
    case 'export-recovery':
      return await cmdKeyExportRecovery(rest, io);
    case 'import-recovery':
      return await cmdKeyImportRecovery(rest, io);
    case 'add-provider':
      return await cmdKeyAddProvider(rest, io);
    case 'remove-provider':
      return await cmdKeyRemoveProvider(rest, io);
    case 'list':
      return await cmdKeyList(rest, io);
    case 'list-recipients':
      return await cmdKeyListRecipients(rest, io);
    default:
      io.stderr(
        sub
          ? `securegit: unknown key subcommand '${sub}'`
          : 'usage: securegit key <add-recipient|remove-recipient|rotate|export-recovery|import-recovery|add-provider|remove-provider|list|list-recipients>',
      );
      return EXIT_USAGE;
  }
}

function agentTargetsFrom(args: string[]): string[] {
  return args.filter((a) => !a.startsWith('--'));
}

async function cmdAgentInstall(args: string[], io: CliIO): Promise<number> {
  const force = args.includes('--force');
  let results;
  try {
    results = await installAgentTargets(io.cwd, agentTargetsFrom(args), { force });
  } catch (e) {
    if (e instanceof AgentInstallError) {
      io.stderr(e.message);
      return e.kind === 'unknown-target' ? EXIT_USAGE : EXIT_MISCONFIGURED;
    }
    throw e;
  }
  const lines = results.map((r) => `  ${r.path} (${r.action})`);
  io.info(`securegit: agent instructions installed\n${lines.join('\n')}`);
  return EXIT_OK;
}

async function cmdAgentList(args: string[], io: CliIO): Promise<number> {
  let entries;
  try {
    entries = listAgentTargets(agentTargetsFrom(args));
  } catch (e) {
    if (e instanceof AgentInstallError) {
      io.stderr(e.message);
      return EXIT_USAGE;
    }
    throw e;
  }
  if (args.includes('--json')) {
    writeJson(io, entries);
    return EXIT_OK;
  }
  io.stderr(entries.map((e) => `${e.target.padEnd(8)} ${e.path}`).join('\n'));
  return EXIT_OK;
}

async function cmdAgent(args: string[], io: CliIO): Promise<number> {
  const [sub, ...rest] = args;
  switch (sub) {
    case 'install':
      return await cmdAgentInstall(rest, io);
    case 'list':
      return await cmdAgentList(rest, io);
    default:
      io.stderr(sub ? `securegit: unknown agent subcommand '${sub}'` : 'usage: securegit agent <install|list>');
      return EXIT_USAGE;
  }
}

/**
 * Re-runs `clean` over every protected tracked file's *working-tree*
 * plaintext and stages the result via `hash-object`/`update-index` plumbing
 * — never through the worktree file itself, which must keep showing
 * plaintext throughout. `clean` is deterministic, so a file already on the
 * current generation re-encrypts to byte-identical ciphertext and is
 * correctly a no-op; only files still on an older generation actually
 * change. History is never touched — only the index. See
 * specs/securegit/09-rotation-recovery.md.
 */
async function cmdReencrypt(args: string[], io: CliIO): Promise<number> {
  const dryRun = args.includes('--dry-run');
  const pathsIdx = args.indexOf('--paths');
  const pathspec = pathsIdx !== -1 ? args[pathsIdx + 1] : undefined;

  const loaded = await loadKeys(io);
  if (!loaded.ok) return loaded.code;
  if (loaded.keys.current() === null) {
    io.stderr('securegit: repository is locked; run `securegit unlock`');
    return EXIT_LOCKED;
  }

  let tracked: string[];
  try {
    tracked = await listTrackedPaths(io.cwd);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_USAGE;
  }

  const candidates: string[] = [];
  for (const path of tracked) {
    if (pathspec !== undefined && path !== pathspec && !path.startsWith(pathspec)) continue;
    const attrs = await checkAttr(io.cwd, path);
    if (attrs.filter === 'securegit') candidates.push(path);
  }

  const lines: string[] = [];
  let changed = 0;
  for (const path of candidates) {
    const plaintext = await readFile(join(io.cwd, path));
    const reencrypted = clean(plaintext, {
      keys: loaded.keys,
      path,
      bindPath: loaded.config.bindPath,
      padTo: loaded.config.padTo,
    });

    let current: Buffer;
    try {
      current = await readIndexBlob(io.cwd, path);
    } catch {
      current = Buffer.alloc(0);
    }
    const willChange = !current.equals(reencrypted);
    lines.push(`  ${path}  ${willChange ? 'would change' : 'already current'}`);

    if (willChange) {
      changed += 1;
      if (!dryRun) await stageBlob(io.cwd, path, reencrypted);
    }
  }

  lines.push(
    `${candidates.length} protected file${candidates.length === 1 ? '' : 's'}, ` +
      `${changed} ${dryRun ? 'would change' : 'changed'}`,
  );
  io.stderr(lines.join('\n'));
  return EXIT_OK;
}

/** Stages `content` as `path`'s new blob via plumbing — the worktree file itself is never written. */
async function stageBlob(repoDir: string, path: string, content: Buffer): Promise<void> {
  const tmp = join(tmpdir(), `securegit-reencrypt-${randomBytes(4).toString('hex')}`);
  await writeFile(tmp, content);
  let sha: string;
  try {
    const { stdout } = await execFile('git', ['hash-object', '-w', tmp], { cwd: repoDir });
    sha = stdout.trim();
  } finally {
    await unlink(tmp).catch(() => {});
  }
  await execFile('git', ['update-index', '--cacheinfo', `100644,${sha},${path}`], { cwd: repoDir });
}

/**
 * "gen 1–3" for a contiguous run, "gen 4" for one generation, "gen 1,3" for
 * a genuine gap (not expected in practice — `key rotate` rewraps every
 * existing recipient unconditionally — but not assumed away either).
 */
function formatGenerationRange(generations: number[]): string {
  if (generations.length === 0) return 'none';
  const sorted = [...generations].sort((a, b) => a - b);
  const min = sorted[0]!;
  const max = sorted[sorted.length - 1]!;
  if (max - min + 1 === sorted.length) return min === max ? `gen ${min}` : `gen ${min}–${max}`;
  return `gen ${sorted.join(',')}`;
}

function isoDate(timestamp: string): string {
  return timestamp.slice(0, 10);
}

/**
 * `--json`'s one writer: the report object itself, exactly as the module
 * that built it returned it — no separate JSON-specific shape to keep in
 * sync with the human-readable rendering. stdout, since `--json` is the
 * documented escape hatch for a script that wants a normally-stderr report
 * as data instead (10-cli-contract.md).
 */
function writeJson(io: CliIO, value: unknown): void {
  io.stdout(Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8'));
}

/** "Who can read this repository" — 13-verify.md. No key required, same as the base `verify()` form. */
async function cmdVerifyAccess(args: string[], io: CliIO): Promise<number> {
  const report = await accessReport({ repoDir: io.cwd, home: io.home, env: io.env });

  if (args.includes('--json')) {
    writeJson(io, report);
    return EXIT_OK;
  }

  const lines: string[] = [];

  lines.push('recipients');
  if (report.recipients.length === 0) {
    lines.push('  (none)');
  }
  for (const r of report.recipients) {
    lines.push(
      `  ${r.fingerprint}  ${r.label}  added ${isoDate(r.addedAt)} by ${r.addedBy || '(unknown)'}  ` +
        `commit ${r.addedCommit ?? '(uncommitted)'}  ${formatGenerationRange(r.generations)}`,
    );
  }

  lines.push('providers');
  if (report.providers.length === 0) {
    lines.push('  (none)');
  }
  for (const p of report.providers) {
    lines.push(`  ${p.id}  ${formatGenerationRange(p.generations)}`);
  }

  lines.push('recovery exports');
  if (report.recoveryExports.length === 0) {
    lines.push('  (none)');
  } else {
    for (const e of report.recoveryExports) {
      lines.push(
        `  ${isoDate(e.timestamp)}  by ${e.exportedBy || '(unknown)'}  export ${e.exportId}  ` +
          `covers ${formatGenerationRange(e.generations)}`,
      );
    }
    lines.push(
      '  ⚠  a recovery export is a full, non-revocable read path that leaves no recipient entry.',
      '     This list cannot tell you who holds it.',
    );
  }

  lines.push('removed recipients');
  if (report.removedRecipients.length === 0) {
    lines.push('  (none)');
  }
  for (const r of report.removedRecipients) {
    lines.push(
      `  ${r.fingerprint}  ${r.label}  removed ${isoDate(r.removedAt)}, ${formatGenerationRange(r.generations)}`,
    );
    lines.push(`     can still read every blob committed under generations ${formatGenerationRange(r.generations)}`);
  }

  io.stderr(lines.join('\n'));
  return EXIT_OK;
}

/**
 * `verify --history` — a real commit walk, CI-tier speed. Exits leaked (5)
 * on the same condition the base form does: plaintext actually found,
 * whether in the index (base form) or reachable history (this one).
 */
async function cmdVerifyHistory(args: string[], io: CliIO): Promise<number> {
  const report = await historyReport({ repoDir: io.cwd });
  const leaked = report.findings.length > 0 || report.textconvNotesRef.present;

  if (args.includes('--json')) {
    writeJson(io, report);
    return leaked ? EXIT_LEAK : EXIT_OK;
  }

  const lines: string[] = [`scanning ${report.commitsWalked} commits …`];

  for (const f of report.findings) {
    lines.push(`  ✗  plaintext at ${f.path}`);
    lines.push(`     first: ${f.firstSha}  ${f.firstDate}  "${f.firstSubject}"`);
    lines.push(`     last:  ${f.lastSha}  ${f.lastDate}  "${f.lastSubject}"`);
    const reachable = f.reachableFrom.length > 0 ? `, still reachable from ${f.reachableFrom.join(', ')}` : '';
    lines.push(`     ${f.commitCount} commit${f.commitCount === 1 ? '' : 's'}${reachable}`);
  }

  if (report.textconvNotesRef.present) {
    lines.push('  ✗  textconv cache notes ref present');
    lines.push(`     ${TEXTCONV_NOTES_REF} — ${report.textconvNotesRef.count} blobs of plaintext`);
  }

  if (!leaked) {
    lines.push('  ✓  no plaintext found in history');
  } else {
    lines.push(
      '',
      '  A secret committed in plaintext and pushed is exposed. Rewriting history',
      '  removes it from the repository; it does not remove it from the mirrors,',
      '  backups, CI caches and clones that already have it. Rotate the secret.',
    );
  }

  io.stderr(lines.join('\n'));
  return leaked ? EXIT_LEAK : EXIT_OK;
}

/** No key required — every check here works from public information. See 13-verify.md. */
async function cmdVerify(args: string[], io: CliIO): Promise<number> {
  if (args.includes('--access')) {
    return await cmdVerifyAccess(args, io);
  }
  if (args.includes('--history')) {
    return await cmdVerifyHistory(args, io);
  }

  // Only `describe()` is ever called on this — verify() unwraps nothing, so
  // it never needs a real passphrase.
  const provider = new PassphraseFileProvider(() => '');

  let report;
  try {
    report = await verify({ repoDir: io.cwd, home: io.home, env: io.env, providers: [provider] });
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_MISCONFIGURED;
  }

  if (args.includes('--json')) {
    writeJson(io, report);
    return verifyExitCode(report);
  }

  const lines: string[] = [];
  for (const check of report.checks) {
    const mark = check.ok ? '✓' : '✗';
    lines.push(check.detail ? `  ${mark}  ${check.label} — ${check.detail}` : `  ${mark}  ${check.label}`);
  }
  for (const finding of report.findings) {
    const mark = finding.kind === 'leak' ? '✗' : '⚠';
    lines.push(`  ${mark}  ${finding.kind}: ${finding.path} — ${finding.detail}`);
  }
  io.stderr(lines.join('\n'));
  return verifyExitCode(report);
}

// ---------------------------------------------------------------------------
// Git filters — stdin/stdout are content channels here, not diagnostics
// ---------------------------------------------------------------------------

interface ParsedPathArg {
  path: string;
  flags: Set<string>;
}

function parsePathArg(args: string[]): ParsedPathArg | null {
  const sepIdx = args.indexOf('--');
  if (sepIdx === -1) return null;
  const rest = args.slice(sepIdx + 1);
  const path = rest[0];
  if (!path) return null;
  return { path, flags: new Set(args.slice(0, sepIdx)) };
}

async function cmdClean(args: string[], io: CliIO): Promise<number> {
  const parsed = parsePathArg(args);
  if (!parsed) {
    io.stderr('usage: securegit clean -- <path>');
    return EXIT_USAGE;
  }
  const loaded = await loadKeys(io);
  if (!loaded.ok) return loaded.code;

  const verbose = parsed.flags.has('-v') || parsed.flags.has('--verbose');
  try {
    const out = clean(io.stdin, {
      keys: loaded.keys,
      path: parsed.path,
      bindPath: loaded.config.bindPath,
      padTo: loaded.config.padTo,
      ...(verbose ? { trace: io.stderr } : {}),
    });
    io.stdout(out);
    return EXIT_OK;
  } catch (e) {
    io.stderr((e as Error).message);
    return e instanceof LockedError ? EXIT_LOCKED : EXIT_CRYPTO;
  }
}

async function cmdSmudge(args: string[], io: CliIO): Promise<number> {
  const parsed = parsePathArg(args);
  if (!parsed) {
    io.stderr('usage: securegit smudge -- <path>');
    return EXIT_USAGE;
  }
  const loaded = await loadKeys(io);
  if (!loaded.ok) return loaded.code;

  const verbose = parsed.flags.has('-v') || parsed.flags.has('--verbose');
  try {
    const out = smudge(io.stdin, {
      keys: loaded.keys,
      path: parsed.path,
      bindPath: loaded.config.bindPath,
      strict: parsed.flags.has('--strict'),
      warn: io.stderr,
      ...(verbose ? { trace: io.stderr } : {}),
    });
    io.stdout(out);
    return EXIT_OK;
  } catch (e) {
    io.stderr((e as Error).message);
    return e instanceof LockedError ? EXIT_LOCKED : EXIT_CRYPTO;
  }
}

async function cmdTextconv(args: string[], io: CliIO): Promise<number> {
  const parsed = parsePathArg(args);
  if (!parsed) {
    io.stderr('usage: securegit textconv -- <file>');
    return EXIT_USAGE;
  }
  const loaded = await loadKeys(io);
  if (!loaded.ok) return loaded.code;

  // Git gives textconv a real file path (a temp copy of the blob), not stdin.
  const content = await readFile(parsed.path);
  const out = textconv(content, {
    keys: loaded.keys,
    path: parsed.path,
    bindPath: loaded.config.bindPath,
  });
  io.stdout(out);
  return EXIT_OK;
}

interface ParsedMergeArgs {
  basePath: string;
  oursPath: string;
  theirsPath: string;
  markerSize: number;
  path: string;
  flags: Set<string>;
}

/** `securegit merge -- %O %A %B %L %P` — base, ours, theirs, marker size, path. */
function parseMergeArgs(args: string[]): ParsedMergeArgs | null {
  const sepIdx = args.indexOf('--');
  if (sepIdx === -1) return null;
  const [basePath, oursPath, theirsPath, markerSizeArg, path] = args.slice(sepIdx + 1);
  if (!basePath || !oursPath || !theirsPath || !markerSizeArg || !path) return null;
  const markerSize = Number(markerSizeArg);
  if (!Number.isInteger(markerSize)) return null;
  return { basePath, oursPath, theirsPath, markerSize, path, flags: new Set(args.slice(0, sepIdx)) };
}

async function cmdMerge(args: string[], io: CliIO): Promise<number> {
  const parsed = parseMergeArgs(args);
  if (!parsed) {
    io.stderr('usage: securegit merge -- <base> <ours> <theirs> <markerSize> <path>');
    return EXIT_USAGE;
  }
  const loaded = await loadKeys(io);
  if (!loaded.ok) return loaded.code;

  const [base, ours, theirs] = await Promise.all([
    readFile(parsed.basePath),
    readFile(parsed.oursPath),
    readFile(parsed.theirsPath),
  ]);

  const verbose = parsed.flags.has('-v') || parsed.flags.has('--verbose');
  try {
    const result = await merge({
      keys: loaded.keys,
      path: parsed.path,
      bindPath: loaded.config.bindPath,
      padTo: loaded.config.padTo,
      markerSize: parsed.markerSize,
      base,
      ours,
      theirs,
      ...(verbose ? { trace: io.stderr } : {}),
    });
    // %A must always be overwritten, clean or not — that's how Git knows what
    // to show in the worktree, and `smudge` decrypts it either way.
    await writeFile(parsed.oursPath, result.output);
    // 1 here means "conflict", mirroring `git merge-file` — the same numeric
    // code the catch block below returns for `LockedError`. Deliberately not
    // disambiguated: Git's merge-driver protocol only distinguishes zero from
    // nonzero, and a caller that needs to tell them apart still can — a
    // locked failure always writes a diagnostic to stderr; a conflict (not a
    // failure — Git shows it on its own) never does. See 10-cli-contract.md.
    return result.clean ? EXIT_OK : 1;
  } catch (e) {
    io.stderr((e as Error).message);
    return e instanceof LockedError ? EXIT_LOCKED : EXIT_CRYPTO;
  }
}

// ---------------------------------------------------------------------------
// ad hoc — exist so the cryptography is testable without a repository
// ---------------------------------------------------------------------------

async function readInput(path: string, io: CliIO): Promise<Buffer> {
  return path === '-' ? io.stdin : readFile(path);
}

async function writeOutput(path: string, data: Buffer, io: CliIO): Promise<void> {
  if (path === '-') {
    io.stdout(data);
    return;
  }
  await writeFile(path, data);
}

function outArg(args: string[]): string {
  const idx = args.indexOf('--out');
  return idx !== -1 ? (args[idx + 1] ?? '-') : '-';
}

async function cmdEncrypt(args: string[], io: CliIO): Promise<number> {
  const input = args.find((a) => !a.startsWith('--'));
  if (!input) {
    io.stderr('usage: securegit encrypt <file|-> [--out <file|->]');
    return EXIT_USAGE;
  }
  const loaded = await loadKeys(io);
  if (!loaded.ok) return loaded.code;

  const current = loaded.keys.current();
  if (!current) {
    io.stderr('securegit: repository is locked; run `securegit unlock`');
    return EXIT_LOCKED;
  }

  const data = await readInput(input, io);
  const out = seal(data, {
    rmk: current.rmk,
    keyId: current.keyId,
    path: input === '-' ? 'stdin' : input,
    bindPath: loaded.config.bindPath,
    padTo: loaded.config.padTo,
  });
  await writeOutput(outArg(args), out, io);
  return EXIT_OK;
}

async function cmdDecrypt(args: string[], io: CliIO): Promise<number> {
  const input = args.find((a) => !a.startsWith('--'));
  if (!input) {
    io.stderr('usage: securegit decrypt <file|-> [--out <file|->]');
    return EXIT_USAGE;
  }
  const loaded = await loadKeys(io);
  if (!loaded.ok) return loaded.code;

  const data = await readInput(input, io);
  let header;
  try {
    header = parseEnvelope(data);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_CRYPTO;
  }

  const rmk = loaded.keys.find(header.keyId);
  if (!rmk) {
    io.stderr(`securegit: this keyring does not hold generation ${header.keyId}`);
    return EXIT_LOCKED;
  }

  try {
    const out = unseal(data, { rmk, path: input === '-' ? 'stdin' : input });
    await writeOutput(outArg(args), out, io);
    return EXIT_OK;
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_CRYPTO;
  }
}

async function cmdInspect(args: string[], io: CliIO): Promise<number> {
  const input = args.find((a) => !a.startsWith('--'));
  if (!input) {
    io.stderr('usage: securegit inspect <file|->');
    return EXIT_USAGE;
  }
  const data = await readInput(input, io);
  let header;
  try {
    header = parseEnvelope(data);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_CRYPTO;
  }

  if (args.includes('--json')) {
    writeJson(io, {
      format: header.format,
      algorithm: header.algorithm,
      bindPath: header.bindPath,
      padded: header.padded,
      keyId: header.keyId,
      ciphertextLength: header.ciphertext.length,
    });
    return EXIT_OK;
  }

  io.stderr(
    `format      ${header.format}\n` +
      `algorithm   ${header.algorithm}\n` +
      `flags       bindPath=${header.bindPath}, padded=${header.padded}\n` +
      `keyId       ${header.keyId}\n` +
      `ciphertext  ${header.ciphertext.length} bytes`,
  );
  return EXIT_OK;
}

// ---------------------------------------------------------------------------
// filter-process — see 11-filter-process.md
// ---------------------------------------------------------------------------

/**
 * `filter-process`'s IO is shaped for a long-running stream, not the
 * single-shot request/response every other command uses (`CliIO`'s `stdin`
 * is a whole already-read `Buffer`, and `runCli` returns exactly once) — so
 * it gets its own entrypoint rather than a case in `runCli`'s switch. Real
 * wiring is in `bin/securegit.ts`, which intercepts `filter-process` before
 * ever calling `runCli`.
 */
export interface FilterProcessIO {
  cwd: string;
  env: NodeJS.ProcessEnv;
  home: string;
  /**
   * Registers the handler that receives each raw chunk read from stdin. May
   * return a promise — a real Node stream ignores it, but `runFilterProcess`
   * chains on it internally to serialize chunk processing (below), and a
   * test harness can await it too.
   */
  onData: (handler: (chunk: Buffer) => void | Promise<void>) => void;
  /** Registers the handler invoked once stdin ends (Git closed the pipe). */
  onEnd: (handler: () => void) => void;
  /** Already guarded — see `installStdoutGuard` in `process.ts`. */
  write: (chunk: Buffer) => void;
  stderr: (message: string) => void;
  // The `| undefined` (beyond plain optionality) is deliberate under this
  // project's `exactOptionalPropertyTypes` — tests assign `now: undefined`
  // explicitly to assert the real, no-injected-clock fallback path, as
  // distinct from simply omitting the key.
  now?: (() => Date) | undefined;
}

export async function runFilterProcess(io: FilterProcessIO): Promise<number> {
  let config: RepoConfig;
  try {
    config = await readConfig(io.cwd);
  } catch (e) {
    io.stderr((e as Error).message);
    return EXIT_MISCONFIGURED;
  }

  const sessionPath = resolveSessionPath(config.repoId, io.env, io.home);
  const sessionKeyEnv = io.env.SECUREGIT_SESSION_KEY;
  const passphraseEnv = io.env.SECUREGIT_PASSPHRASE;
  const identityFileEnv = io.env.SECUREGIT_IDENTITY_FILE;
  // Unlike `loadKeys()`'s one-shot form, a single `filter-process` server
  // lives for the whole git operation — so unless a real session is behind
  // it, SECUREGIT_PASSPHRASE's (or SECUREGIT_IDENTITY_FILE's) scrypt unwrap
  // only has to happen once here, not once per blob. Computed lazily (only
  // if the env var is actually set and SECUREGIT_SESSION_KEY didn't already
  // win) and cached for the rest of this process's lifetime.
  let cachedPassphraseKeys: Promise<KeySource> | undefined;
  const server = new FilterProcessServer({
    bindPath: config.bindPath,
    padTo: config.padTo,
    write: io.write,
    warn: io.stderr,
    // Re-read per blob, deliberately — see FilterProcessContext.keys in
    // process.ts for why this is how session expiry gets re-checked without
    // the server needing its own polling. Same precedence as loadKeys():
    // SECUREGIT_SESSION_KEY, then SECUREGIT_PASSPHRASE (itself branching on
    // SECUREGIT_IDENTITY_FILE, cached either way — see above), then the
    // session file — the first one present replaces the rest.
    keys: () => {
      if (sessionKeyEnv !== undefined && sessionKeyEnv.length > 0) {
        return Promise.resolve(
          keySourceFromSessionKey(sessionKeyEnv, {
            repoId: config.repoId,
            ...(io.now !== undefined ? { now: io.now } : {}),
          }),
        );
      }
      if (passphraseEnv !== undefined && passphraseEnv.length > 0) {
        cachedPassphraseKeys ??=
          identityFileEnv !== undefined && identityFileEnv.length > 0
            ? keySourceFromIdentityFileEnv(identityFileEnv, passphraseEnv, config, io)
            : keySourceFromPassphraseEnv(passphraseEnv, config, io);
        return cachedPassphraseKeys;
      }
      return readSession({
        repoId: config.repoId,
        path: sessionPath,
        warn: io.stderr,
        ...(io.now !== undefined ? { now: io.now } : {}),
      });
    },
  });

  return await new Promise<number>((resolve) => {
    let settled = false;
    const finish = (code: number): void => {
      if (settled) return;
      settled = true;
      resolve(code);
    };

    // Chunks are chained rather than pushed independently: `server.push()`
    // does real async work per command (`keys()` re-reads the session), and
    // two chunks processed concurrently would interleave against the
    // server's shared mutable state (its parse position, the pending
    // command header) — a real race, not just a testability concern. Once
    // aborted, further chunks are still drained off the chain (so it keeps
    // resolving) but never handed to a server that already failed.
    let chain: Promise<void> = Promise.resolve();
    let aborted = false;
    io.onData((chunk) => {
      chain = chain
        .then(() => {
          if (aborted) return;
          return server.push(chunk);
        })
        .catch((e: unknown) => {
          aborted = true;
          io.stderr((e as Error).message);
          finish(EXIT_USAGE);
        });
      return chain;
    });
    io.onEnd(() => {
      chain.then(() => finish(EXIT_OK)).catch(() => {});
    });
  });
}

// ---------------------------------------------------------------------------

export async function runCli(io: CliIO): Promise<number> {
  // `--repo <path>` is global — it can appear anywhere in argv, before or
  // after the command name — so it's parsed and stripped here, once,
  // before dispatch, rather than threaded through every one of the ~30
  // places in this file that read `io.cwd` individually. Reassigning `io`
  // (not introducing a second variable) means every existing case below
  // picks up the resolved path for free.
  const repoIdx = io.argv.indexOf('--repo');
  if (repoIdx !== -1) {
    const repoArg = io.argv[repoIdx + 1];
    if (repoArg === undefined) {
      io.stderr('securegit: --repo requires a path argument');
      return EXIT_USAGE;
    }
    io = {
      ...io,
      cwd: resolve(io.cwd, repoArg),
      argv: [...io.argv.slice(0, repoIdx), ...io.argv.slice(repoIdx + 2)],
    };
  }

  // `--quiet` is global too, but unlike `--repo` it takes no value and no
  // command does positional (index-based) argv parsing that a stray
  // `--quiet` token could be mistaken for — every command either checks a
  // specific named flag or filters out anything starting with `--`. So
  // nothing needs to be stripped: just swap in a no-op `info` and leave the
  // rest of argv untouched.
  if (io.argv.includes('--quiet')) {
    io = { ...io, info: () => {} };
  }

  const [cmd, ...rest] = io.argv;
  const showHelp = (text: string): number => {
    io.stderr(text);
    return EXIT_OK;
  };
  try {
    switch (cmd) {
      case 'init':
        if (wantsHelp(rest)) return showHelp(renderCommandHelp('init', HELP.init!));
        return await cmdInit(rest, io);
      case 'install':
        if (wantsHelp(rest)) return showHelp(renderCommandHelp('install', HELP.install!));
        return await cmdInstall(rest, io);
      case 'protect':
        if (wantsHelp(rest)) return showHelp(renderCommandHelp('protect', HELP.protect!));
        return await cmdProtect(rest, io);
      case 'unprotect':
        if (wantsHelp(rest)) return showHelp(renderCommandHelp('unprotect', HELP.unprotect!));
        return await cmdUnprotect(rest, io);
      case 'unlock':
        if (wantsHelp(rest)) return showHelp(renderCommandHelp('unlock', HELP.unlock!));
        return await cmdUnlock(rest, io);
      case 'lock':
        if (wantsHelp(rest)) return showHelp(renderCommandHelp('lock', HELP.lock!));
        return await cmdLock(rest, io);
      case 'status':
        if (wantsHelp(rest)) return showHelp(renderCommandHelp('status', HELP.status!));
        return await cmdStatus(rest, io);
      case 'identity':
        if (wantsHelp(rest)) return showHelp(groupHelp('identity', rest));
        return await cmdIdentity(rest, io);
      case 'key':
        if (wantsHelp(rest)) return showHelp(groupHelp('key', rest));
        return await cmdKey(rest, io);
      case 'agent':
        if (wantsHelp(rest)) return showHelp(groupHelp('agent', rest));
        return await cmdAgent(rest, io);
      case 'reencrypt':
        if (wantsHelp(rest)) return showHelp(renderCommandHelp('reencrypt', HELP.reencrypt!));
        return await cmdReencrypt(rest, io);
      case 'verify':
        if (wantsHelp(rest)) return showHelp(renderCommandHelp('verify', HELP.verify!));
        return await cmdVerify(rest, io);
      case 'clean':
        if (wantsHelp(rest)) return showHelp(renderCommandHelp('clean', HELP.clean!));
        return await cmdClean(rest, io);
      case 'smudge':
        if (wantsHelp(rest)) return showHelp(renderCommandHelp('smudge', HELP.smudge!));
        return await cmdSmudge(rest, io);
      case 'textconv':
        if (wantsHelp(rest)) return showHelp(renderCommandHelp('textconv', HELP.textconv!));
        return await cmdTextconv(rest, io);
      case 'merge':
        if (wantsHelp(rest)) return showHelp(renderCommandHelp('merge', HELP.merge!));
        return await cmdMerge(rest, io);
      case 'encrypt':
        if (wantsHelp(rest)) return showHelp(renderCommandHelp('encrypt', HELP.encrypt!));
        return await cmdEncrypt(rest, io);
      case 'decrypt':
        if (wantsHelp(rest)) return showHelp(renderCommandHelp('decrypt', HELP.decrypt!));
        return await cmdDecrypt(rest, io);
      case 'inspect':
        if (wantsHelp(rest)) return showHelp(renderCommandHelp('inspect', HELP.inspect!));
        return await cmdInspect(rest, io);
      case 'help':
      case '--help':
      case '-h': {
        const topic = cmd === 'help' ? rest.find((a) => !a.startsWith('-')) : undefined;
        if (io.argv.includes('--json')) {
          io.stdout(Buffer.from(JSON.stringify(helpManifest())));
          return EXIT_OK;
        }
        if (topic === undefined) {
          return showHelp(renderTopLevelHelp(io.argv.includes('--quiet')));
        }
        if (!HELP[topic]) {
          io.stderr(`securegit: unknown help topic '${topic}'\n${USAGE}`);
          return EXIT_USAGE;
        }
        if (topic === 'key' || topic === 'identity' || topic === 'agent') {
          return showHelp(groupHelp(topic, rest.slice(rest.indexOf(topic) + 1)));
        }
        return showHelp(renderCommandHelp(topic, HELP[topic]!));
      }
      default:
        io.stderr(cmd ? `securegit: unknown command '${cmd}'\n${USAGE}` : USAGE);
        return EXIT_USAGE;
    }
  } catch (e) {
    if (
      e instanceof KeyringError ||
      e instanceof ProviderError ||
      e instanceof InstallError ||
      e instanceof IdentityError ||
      e instanceof RecipientError ||
      e instanceof RecoveryError
    ) {
      io.stderr((e as Error).message);
      return EXIT_USAGE;
    }
    if (e instanceof EnvelopeError) {
      io.stderr((e as Error).message);
      return EXIT_CRYPTO;
    }
    io.stderr(`securegit: unexpected error: ${(e as Error).message}`);
    return EXIT_USAGE;
  }
}
