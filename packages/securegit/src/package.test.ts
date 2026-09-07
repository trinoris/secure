import { describe, it, expect } from 'vitest';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';

// Static checks for specs/securegit/16-adversarial-integrity.md T11 (supply
// chain: zero runtime dependencies) and the timing-safe-comparison
// requirement under "Non-goals, restated". These are properties of the
// published package and the source tree, not of any one module's behaviour,
// so they belong in their own file rather than beside filter.ts or cli.ts.
//
// Since the extraction into @trinoris/securelib (ARCHITECTURE.md), T11's
// "zero runtime dependencies" is checked per package, not once for a single
// monolith. This file covers @trinoris/securegit's own footprint: exactly
// one internal dependency (@trinoris/securelib — the same repo, same CI,
// same review process; not a third-party supply-chain risk in the sense T11
// exists to catch) and nothing else. @trinoris/securelib's own
// package.test.ts holds it to zero dependencies of any kind, with no
// exception — it's the package that actually holds key material.

const REPO_ROOT = join(import.meta.dirname, '..');

interface PackageJson {
  dependencies?: Record<string, string>;
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
  it('declares exactly one dependency: the internal, same-repo @trinoris/securelib', async () => {
    const pkg = await readPackageJson();
    expect(Object.keys(pkg.dependencies ?? {})).toEqual(['@trinoris/securelib']);
  });

  it('publishes only dist/, src/, README.md and LICENSE', async () => {
    const pkg = await readPackageJson();
    expect(pkg.files).toEqual(['dist', 'src', 'README.md', 'LICENSE']);
  });

  it('development dependencies are exactly the expected build/test tooling', async () => {
    const pkg = await readPackageJson();
    expect(Object.keys(pkg.devDependencies ?? {}).sort()).toEqual(
      ['@types/node', '@vitest/coverage-v8', 'typescript', 'vitest'].sort(),
    );
  });
});

// A specifier is either relative (`./x.js`, `../x.js`), a `node:` builtin,
// or the one internal workspace dependency this package deliberately takes
// (`@trinoris/securelib`, any subpath). Anything else — a bare third-party
// package name — is a runtime dependency this test exists to catch before
// it ever reaches package.json.
const IMPORT_RE = /(?:import|export)\s+(?:type\s+)?[^'"]*from\s+['"]([^'"]+)['"]/g;

describe('src/ import hygiene (T11)', () => {
  it('every import in production source is relative, a node: builtin, or @trinoris/securelib', async () => {
    const files = await listProductionSourceFiles(join(REPO_ROOT, 'src'));
    expect(files.length).toBeGreaterThan(5); // sanity: the scan actually found the package

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
});

describe('non-AEAD comparisons use timingSafeEqual', () => {
  // crypto.ts (equalCt's own definition), envelope.ts, identity.ts, and
  // recovery.ts all moved to @trinoris/securelib — their own equivalent of
  // this check now lives in that package's package.test.ts. `cli.ts` is the
  // one file that stayed here and was already exempted (see the reasoning
  // below), so it's the only remaining exemption on this side of the split.
  it('no production file outside cli.ts calls Buffer#equals()', async () => {
    // cli.ts's one use is `reencrypt` deciding whether a re-encrypted blob
    // differs from what's already staged — both sides are ciphertext that
    // either already is, or is about to become, public repository content,
    // never secret material. Anywhere else, a raw `.equals()` on a Buffer is
    // exactly the mistake `equalCt` (@trinoris/securelib/crypto) exists to
    // prevent.
    const allowedBasenames = new Set(['cli.ts']);
    const files = await listProductionSourceFiles(join(REPO_ROOT, 'src'));
    const offenders: string[] = [];
    for (const file of files) {
      if (allowedBasenames.has(file.split('/').pop()!)) continue;
      const content = await readFile(file, 'utf8');
      if (/\.equals\(/.test(content)) offenders.push(file);
    }
    expect(offenders).toEqual([]);
  });

  it('no production file compares a fingerprint with a raw === or !==', async () => {
    const files = await listProductionSourceFiles(join(REPO_ROOT, 'src'));
    const offenders: string[] = [];
    for (const file of files) {
      const content = await readFile(file, 'utf8');
      if (/fingerprint\w*\s*[!=]==|[!=]==\s*\w*[fF]ingerprint/.test(content)) {
        offenders.push(file);
      }
    }
    expect(offenders).toEqual([]);
  });
});
