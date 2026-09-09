// Turns each package's own vitest coverage-summary.json (branches only —
// that's the dimension every package's vitest.config.ts actually gates
// on, see the coverage.thresholds comment in each) into shields.io
// "endpoint badge" JSON files (https://shields.io/badges/endpoint-badge):
// one per package, plus one aggregate across all four. Published to
// GitHub Pages by the `coverage-badge` job in
// .github/workflows/build-ci.yml. The README's badges point at those
// published files, not at this script directly.
//
// Run after `npm run test:coverage` has produced a coverage-summary.json
// in every package below (that script builds each package's dependencies
// first, same as `npm test` does — coverage-summary.json won't exist yet
// on a bare checkout).

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';

const PACKAGES = ['securelib', 'securelib-piv', 'securelib-fido2', 'securegit'];

const outDir = process.argv[2];
if (!outDir) {
  console.error('usage: node scripts/generate-coverage-badge.mjs <output-dir>');
  process.exit(1);
}
await mkdir(outDir, { recursive: true });

// shields.io's own coverage-badge color scale.
function colorFor(p) {
  if (p >= 90) return 'brightgreen';
  if (p >= 80) return 'green';
  if (p >= 70) return 'yellowgreen';
  if (p >= 60) return 'yellow';
  if (p >= 50) return 'orange';
  return 'red';
}

function badgeFor(covered, total) {
  const pct = (covered / total) * 100;
  return {
    schemaVersion: 1,
    label: 'coverage',
    message: `${pct.toFixed(1)}% branches`,
    color: colorFor(pct),
  };
}

async function writeBadge(name, covered, total) {
  const badge = badgeFor(covered, total);
  const path = join(outDir, `${name}.json`);
  await writeFile(path, JSON.stringify(badge));
  console.log(`wrote ${path}: ${badge.message} (${covered}/${total} branches, ${badge.color})`);
}

let coveredTotal = 0;
let branchesTotal = 0;

for (const pkg of PACKAGES) {
  const summaryPath = join('packages', pkg, 'coverage', 'coverage-summary.json');
  let summary;
  try {
    summary = JSON.parse(await readFile(summaryPath, 'utf8'));
  } catch (e) {
    console.error(`could not read ${summaryPath} — did \`npm run test:coverage\` run first?`);
    throw e;
  }
  const { covered, total } = summary.total.branches;
  coveredTotal += covered;
  branchesTotal += total;
  await writeBadge(`coverage-badge-${pkg}`, covered, total);
}

await writeBadge('coverage-badge', coveredTotal, branchesTotal);
