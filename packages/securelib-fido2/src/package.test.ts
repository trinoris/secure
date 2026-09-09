import { describe, it, expect } from 'vitest';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';

// Static checks for specs/securegit/16-adversarial-integrity.md T11 (supply
// chain: zero runtime dependencies), same discipline as every other
// package.test.ts in this repo. Like @trinoris/securelib-piv, this
// package's story is the strongest: no npm dependency at all — it shells
// out to system tools (libfido2's `fido2-token`/`fido2-cred`/`fido2-assert`)
// rather than linking a native CTAP2/HID addon.

const REPO_ROOT = join(import.meta.dirname, '..');

interface PackageJson {
  dependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  files?: string[];
}

async function readPackageJson(): Promise<PackageJson> {
  return JSON.parse(await readFile(join(REPO_ROOT, 'package.json'), 'utf8')) as PackageJson;
}

async function listProductionSourceFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await listProductionSourceFiles(full)));
    } else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts')) {
      files.push(full);
    }
  }
  return files;
}

describe('package.json (T11: supply chain)', () => {
  it('declares zero runtime dependencies — @trinoris/securelib is a peerDependency, not a dependency', async () => {
    const pkg = await readPackageJson();
    expect(pkg.dependencies).toBeUndefined();
    expect(Object.keys(pkg.peerDependencies ?? {})).toEqual(['@trinoris/securelib']);
  });

  it('publishes only dist/, src/, README.md and LICENSE', async () => {
    const pkg = await readPackageJson();
    expect(pkg.files).toEqual(['dist', 'src', 'README.md', 'LICENSE']);
  });

  it('development dependencies are exactly the expected build/test tooling plus the peer it tests against', async () => {
    const pkg = await readPackageJson();
    expect(Object.keys(pkg.devDependencies ?? {}).sort()).toEqual(
      ['@trinoris/securelib', '@types/node', '@vitest/coverage-v8', 'typescript', 'vitest'].sort(),
    );
  });
});

const IMPORT_RE = /(?:import|export)\s+(?:type\s+)?[^'"]*from\s+['"]([^'"]+)['"]/g;

describe('src/ import hygiene (T11)', () => {
  it('every import in production source is relative, a node: builtin, or @trinoris/securelib', async () => {
    const files = await listProductionSourceFiles(join(REPO_ROOT, 'src'));
    expect(files.length).toBeGreaterThan(0); // sanity: the scan actually found the package

    const offenders: string[] = [];
    for (const file of files) {
      const content = await readFile(file, 'utf8');
      for (const match of content.matchAll(IMPORT_RE)) {
        const specifier = match[1]!;
        if (specifier.startsWith('.') || specifier.startsWith('node:')) continue;
        if (specifier === '@trinoris/securelib' || specifier.startsWith('@trinoris/securelib/')) continue;
        offenders.push(`${file}: ${specifier}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('never shells out to anything but fido2-token/fido2-cred/fido2-assert — no arbitrary command execution', async () => {
    // Matches both a direct execFile('cmd', ...) call and this.runner('cmd',
    // ...) — see securelib-piv's own version of this check for why the
    // literal command names must appear at call sites, never inside
    // defaultRunner's own generic execFile(command, args).
    const files = await listProductionSourceFiles(join(REPO_ROOT, 'src'));
    const allowedCommands = new Set(['fido2-token', 'fido2-cred', 'fido2-assert']);
    const offenders: string[] = [];
    let matchCount = 0;
    for (const file of files) {
      const content = await readFile(file, 'utf8');
      for (const match of content.matchAll(/(?:execFile|this\.runner)\(\s*'([^']+)'/g)) {
        matchCount++;
        if (!allowedCommands.has(match[1]!)) offenders.push(`${file}: ${match[1]}`);
      }
    }
    expect(matchCount).toBeGreaterThan(0); // sanity: the scan actually found the runner call sites
    expect(offenders).toEqual([]);
  });
});
