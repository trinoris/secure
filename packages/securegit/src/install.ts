// Writes local (never committed) Git filter/diff configuration, and manages
// the tracked `.gitattributes` / `.gitignore` entries that route paths
// through it.
// See specs/securegit/02-git-integration.md and 16-adversarial-integrity.md (T10, T12).

import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const execFile = promisify(execFileCb);

export class InstallError extends Error {
  readonly code = 'INSTALL';

  constructor(message: string) {
    super(message);
    this.name = 'InstallError';
  }
}

// ---------------------------------------------------------------------------
// git config
// ---------------------------------------------------------------------------

async function gitConfigGet(repoDir: string, key: string): Promise<string | null> {
  try {
    const { stdout } = await execFile('git', ['config', '--local', '--get', key], {
      cwd: repoDir,
    });
    return stdout.replace(/\n$/, '');
  } catch (e) {
    const err = e as { code?: number };
    if (err.code === 1) return null; // unset
    throw new InstallError(
      `could not read git config in ${repoDir}: ${(e as Error).message}`,
    );
  }
}

async function gitConfigSet(repoDir: string, key: string, value: string): Promise<void> {
  await execFile('git', ['config', '--local', '--replace-all', key, value], { cwd: repoDir });
}

async function gitConfigUnset(repoDir: string, key: string): Promise<void> {
  try {
    await execFile('git', ['config', '--local', '--unset-all', key], { cwd: repoDir });
  } catch (e) {
    const err = e as { code?: number };
    if (err.code !== 5) throw e; // 5 = key was already unset
  }
}

export interface InstallOptions {
  repoDir: string;
  /** Command used in the filter lines. Defaults to "securegit". */
  bin?: string;
  /** Use the long-running `filter.securegit.process` form instead of clean/smudge. */
  process?: boolean;
  required?: boolean;
  /** Overwrite pre-existing filter/diff config this tool did not write. */
  force?: boolean;
}

const IDENTITY_KEYS = [
  'filter.securegit.clean',
  'filter.securegit.smudge',
  'filter.securegit.process',
  'diff.securegit.textconv',
  'merge.securegit.driver',
] as const;

/** Every value securegit itself would ever write to an identity key, for any form. */
function recognizedValues(bin: string): Set<string> {
  return new Set([
    `${bin} clean -- %f`,
    `${bin} smudge -- %f`,
    `${bin} filter-process`,
    `${bin} textconv --`,
    `${bin} merge -- %O %A %B %L %P`,
  ]);
}

/**
 * Writes the filter and diff configuration. Refuses to overwrite an existing
 * identity key (clean/smudge/process/textconv) whose value does not look like
 * something securegit itself would have written — for any bin path this call
 * uses — because that value names an executable, and silently replacing it is
 * exactly the risk in specs/securegit/16-adversarial-integrity.md, T10.
 */
export async function install(opts: InstallOptions): Promise<void> {
  const bin = opts.bin ?? 'securegit';
  const useProcess = opts.process ?? false;
  const required = opts.required ?? true;

  const existing: Record<string, string | null> = {};
  for (const key of IDENTITY_KEYS) {
    existing[key] = await gitConfigGet(opts.repoDir, key);
  }

  if (!opts.force) {
    const recognized = recognizedValues(bin);
    const foreign = IDENTITY_KEYS.filter(
      (key) => existing[key] !== null && !recognized.has(existing[key] as string),
    );
    if (foreign.length > 0) {
      const detail = foreign.map((key) => `  ${key} = ${existing[key]}`).join('\n');
      throw new InstallError(
        `securegit: refusing to overwrite existing filter configuration it did not write\n${detail}\n` +
          `  action: remove it manually, or pass force: true to overwrite it`,
      );
    }
  }

  if (useProcess) {
    await gitConfigUnset(opts.repoDir, 'filter.securegit.clean');
    await gitConfigUnset(opts.repoDir, 'filter.securegit.smudge');
    await gitConfigSet(opts.repoDir, 'filter.securegit.process', `${bin} filter-process`);
  } else {
    await gitConfigUnset(opts.repoDir, 'filter.securegit.process');
    await gitConfigSet(opts.repoDir, 'filter.securegit.clean', `${bin} clean -- %f`);
    await gitConfigSet(opts.repoDir, 'filter.securegit.smudge', `${bin} smudge -- %f`);
  }

  await gitConfigSet(opts.repoDir, 'filter.securegit.required', required ? 'true' : 'false');
  await gitConfigSet(opts.repoDir, 'diff.securegit.textconv', `${bin} textconv --`);
  await gitConfigSet(opts.repoDir, 'diff.securegit.cachetextconv', 'false');
  await gitConfigSet(opts.repoDir, 'merge.securegit.name', 'securegit encrypted three-way merge');
  await gitConfigSet(opts.repoDir, 'merge.securegit.driver', `${bin} merge -- %O %A %B %L %P`);
}

// ---------------------------------------------------------------------------
// .gitattributes
// ---------------------------------------------------------------------------

export const EXCLUSION_LINE = '.securegit/** -filter -diff -text';

/**
 * Git does not exempt `.gitattributes` from its own filter rules the way you
 * might expect — a broad enough protect pattern (`**`, now the default; or
 * any repository that manually protects something that wide) would otherwise
 * encrypt the very file Git needs to read, unfiltered, to know how to filter
 * anything else at all. Confirmed empirically against real `git check-attr`,
 * not assumed. Always kept present and always second-to-last, immediately
 * before EXCLUSION_LINE, regardless of which patterns are protected — this
 * is a structural requirement of the tool, not something tied to any one
 * default.
 */
export const GITATTRIBUTES_EXCLUSION_LINE = '.gitattributes -filter -diff -text';

/** Always written last, in this order, by every `.gitattributes` update. */
const TRAILING_LINES = [GITATTRIBUTES_EXCLUSION_LINE, EXCLUSION_LINE];

function attributeLine(pattern: string): string {
  return `${pattern} filter=securegit diff=securegit merge=securegit -text`;
}

function exclusionLine(pattern: string): string {
  return `${pattern} -filter -diff -text`;
}

async function readLines(path: string): Promise<string[]> {
  try {
    const content = await readFile(path, 'utf8');
    return content.split('\n').filter((_, i, arr) => !(i === arr.length - 1 && arr[i] === ''));
  } catch (e) {
    if ((e as { code?: string }).code === 'ENOENT') return [];
    throw e;
  }
}

async function writeLines(path: string, lines: string[]): Promise<void> {
  await writeFile(path, lines.length > 0 ? `${lines.join('\n')}\n` : '', 'utf8');
}

function stripTrailingLines(lines: string[]): string[] {
  const trailingSet = new Set<string>(TRAILING_LINES);
  return lines.filter((line) => !trailingSet.has(line));
}

async function updateGitattributes(repoDir: string, patterns: string[]): Promise<void> {
  const path = join(repoDir, '.gitattributes');
  const existing = stripTrailingLines(await readLines(path));

  const present = new Set(existing.map((line) => line.split(/\s+/)[0]));
  const additions = patterns.filter((p) => !present.has(p)).map(attributeLine);

  await writeLines(path, [...existing, ...additions, ...TRAILING_LINES]);
}

// ---------------------------------------------------------------------------
// .gitignore residue entries (T12)
// ---------------------------------------------------------------------------

/** Exported so `verify.ts` (T12) can check for the same shapes on disk. */
export const RESIDUE_SUFFIXES = ['~', '.orig', '.rej', '.bak', '.save'];

/** The path vim actually gives a swap file: dot-prefixed basename, `.sw?`. */
export function swapPattern(pattern: string): string {
  const idx = pattern.lastIndexOf('/');
  const dir = idx === -1 ? '' : pattern.slice(0, idx + 1);
  const base = idx === -1 ? pattern : pattern.slice(idx + 1);
  return `${dir}.${base}.sw?`;
}

function residueLines(pattern: string): string[] {
  return [...RESIDUE_SUFFIXES.map((suffix) => `${pattern}${suffix}`), swapPattern(pattern)];
}

async function updateGitignore(repoDir: string, patterns: string[]): Promise<void> {
  const path = join(repoDir, '.gitignore');
  const existing = await readLines(path);
  const present = new Set(existing);
  const additions = patterns.flatMap(residueLines).filter((line) => !present.has(line));
  await writeLines(path, [...existing, ...additions]);
}

// ---------------------------------------------------------------------------

export interface ProtectOptions {
  /** Also write `.gitignore` entries for editor/merge residue. Default true. */
  residuePatterns?: boolean;
}

/**
 * `securegit protect` with no pattern given falls back to this: encrypt
 * everything, secure by default. A curated allowlist of secret-shaped
 * filenames (the old default) only ever protects what someone thought to
 * name in advance — a new sensitive file added later, under an unlisted
 * name, ships as plaintext until someone remembers to `protect` it. `**`
 * has no such blind spot: nothing new can slip through unnoticed.
 *
 * Deliberately errs broad, not narrow: encrypting a file that turns out not
 * to be sensitive costs nothing but an extra decrypt on read (still plain
 * Git otherwise); missing one that *was* sensitive costs a real leak.
 * `securegit exclude <pattern>` is the escape hatch for anything a given
 * repository wants to keep plaintext on purpose (a README for GitHub's own
 * preview, say) — durable and explicit, unlike silently never protecting it.
 */
export const DEFAULT_PROTECT_PATTERNS = ['**'];

/**
 * Paths `securegit protect` (no args) excludes automatically alongside the
 * `**` default, via `excludePattern` — not because they're safe to read (no
 * claim either way), but because encrypting them breaks something outright:
 * GitHub Actions' own servers parse `.github/workflows/**` directly with no
 * way to decrypt it first, so an encrypted workflow file simply stops being
 * recognized as a workflow at all. `securegit protect <pattern>...` (with
 * an explicit list) skips this — it's specific to the zero-arg fast path.
 */
export const DEFAULT_PROTECT_EXCLUSIONS = ['.github/workflows/**'];

/**
 * Protects one or more path patterns: writes them into `.gitattributes` with
 * the filter, diff driver and `-text`, keeping the `.securegit/**` exclusion
 * last, and (by default) adds `.gitignore` entries for the plaintext residue
 * ordinary tooling leaves beside a protected file.
 */
export async function protect(
  repoDir: string,
  patterns: string[],
  opts: ProtectOptions = {},
): Promise<void> {
  if (patterns.length === 0) {
    throw new InstallError('protect requires at least one pattern');
  }
  await updateGitattributes(repoDir, patterns);
  if (opts.residuePatterns ?? true) {
    await updateGitignore(repoDir, patterns);
  }
}

/**
 * Removes patterns previously added by `protect` — the `.gitattributes`
 * line only. `.gitignore`'s residue entries are left alone: harmless once
 * a pattern is unprotected, and removing them could unhide files a user
 * still wants ignored for reasons that have nothing to do with this tool.
 *
 * This changes what happens to the *next* commit under the pattern, not
 * anything already committed — the same forward-only shape as key rotation
 * (09-rotation-recovery.md). A blob already committed as ciphertext stays
 * ciphertext, in history and in the current index, until something
 * actually re-stages the file; `clean` only ever runs when Git decides a
 * path needs re-verifying (02-git-integration.md), and removing an
 * attribute alone doesn't trigger that.
 *
 * A pattern that was never protected, or a call before `.gitattributes`
 * exists at all, is a silent no-op — the file is left exactly as it was
 * (not touched, not created empty) rather than written unconditionally.
 */
export async function unprotect(repoDir: string, patterns: string[]): Promise<void> {
  if (patterns.length === 0) {
    throw new InstallError('unprotect requires at least one pattern');
  }
  const path = join(repoDir, '.gitattributes');
  const existing = await readLines(path);
  const toRemove = new Set(patterns);
  const remaining = existing.filter((line) => !toRemove.has(line.split(/\s+/)[0]!));
  if (remaining.length === existing.length) return; // nothing matched
  await writeLines(path, remaining);
}

/**
 * Carves an explicit, durable plaintext exception out of whatever else
 * protects this repository — the counterpart `unprotect` can't be, now that
 * the default is `**` rather than a short discrete list. `unprotect` undoes
 * one specific earlier `protect <pattern>` call and is a no-op against
 * anything it didn't itself add; `exclude` instead guarantees the given
 * pattern is never filtered going forward, regardless of what else in
 * `.gitattributes` would otherwise have matched it, by writing an explicit
 * `-filter -diff -text` line that (kept before the two permanent trailing
 * lines, per Git's own last-match-wins attribute resolution) always outranks
 * a broader positive pattern written earlier in the file.
 *
 * Idempotent — excluding the same pattern twice does not duplicate the line.
 * Like `protect`, does not touch anything already committed: a file that was
 * ciphertext before stays ciphertext until it's next edited and re-added (or
 * `reencrypt` is run).
 */
export async function excludePattern(repoDir: string, patterns: string[]): Promise<void> {
  if (patterns.length === 0) {
    throw new InstallError('exclude requires at least one pattern');
  }
  const path = join(repoDir, '.gitattributes');
  const existing = stripTrailingLines(await readLines(path));

  const present = new Set(existing);
  const additions = patterns.map(exclusionLine).filter((line) => !present.has(line));

  await writeLines(path, [...existing, ...additions, ...TRAILING_LINES]);
}
