// Runs `npm audit --json` scoped to each individual workspace package and
// turns the result into shields.io "endpoint badge" JSON files
// (https://shields.io/badges/endpoint-badge): one per package, plus one
// aggregate across all four. Published to GitHub Pages by the
// `metrics-badges` job in .github/workflows/build-ci.yml, alongside the
// coverage badges (see generate-coverage-badge.mjs, which this
// deliberately mirrors). The README's badges point at those published
// files, not at this script.
//
// This is a *reporting* badge, not the gate — `npm audit --audit-level=high`
// in the `audit` job's own step (run against the whole workspace) is what
// actually fails a push/PR on a real high/critical finding. Scoping per
// package here is purely for the per-package badge: `npm audit` itself
// resolves against the one shared root package-lock.json either way, so
// this can run standalone with no prior step (just `npm ci` first, same
// as any other command in this repo).

import { writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';

const execFile = promisify(execFileCb);

const PACKAGES = ['securelib', 'securelib-piv', 'securelib-fido2', 'securegit'];

const outDir = process.argv[2];
if (!outDir) {
  console.error('usage: node scripts/generate-audit-badge.mjs <output-dir>');
  process.exit(1);
}
await mkdir(outDir, { recursive: true });

// Worst severity actually present decides the message and color — a
// single critical finding shouldn't hide behind a "12 low" summary.
const SEVERITIES = ['critical', 'high', 'moderate', 'low', 'info'];
const COLOR_FOR_SEVERITY = {
  critical: 'red',
  high: 'red',
  moderate: 'orange',
  low: 'yellow',
  info: 'yellow',
  none: 'brightgreen',
};

function badgeFor(counts) {
  const worst = SEVERITIES.find((s) => counts[s] > 0);
  if (!worst) {
    return { schemaVersion: 1, label: 'audit', message: 'no known vulns', color: COLOR_FOR_SEVERITY.none };
  }
  return {
    schemaVersion: 1,
    label: 'audit',
    message: `${counts.total} vuln${counts.total === 1 ? '' : 's'} (${worst})`,
    color: COLOR_FOR_SEVERITY[worst],
  };
}

const aggregate = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 };

for (const pkg of PACKAGES) {
  // `npm audit` exits nonzero the moment it finds anything — that's the
  // real gate's job (the `audit` job's own unscoped `npm audit
  // --audit-level=high` step), not this script's. `execFile` rejects on a
  // nonzero exit, but `--json` output still lands on the rejected error's
  // own `.stdout`, exactly like a zero-exit success — so both cases parse
  // identically here.
  let stdout;
  try {
    ({ stdout } = await execFile('npm', ['audit', '--workspace', `packages/${pkg}`, '--json']));
  } catch (e) {
    if (typeof e.stdout !== 'string' || e.stdout.length === 0) throw e;
    stdout = e.stdout;
  }
  const counts = JSON.parse(stdout).metadata.vulnerabilities;
  for (const s of [...SEVERITIES, 'total']) aggregate[s] += counts[s];

  const badge = badgeFor(counts);
  const path = join(outDir, `audit-badge-${pkg}.json`);
  await writeFile(path, JSON.stringify(badge));
  console.log(`wrote ${path}: ${badge.message} (${badge.color})`);
}

const aggregateBadge = badgeFor(aggregate);
const aggregatePath = join(outDir, 'audit-badge.json');
await writeFile(aggregatePath, JSON.stringify(aggregateBadge));
console.log(`wrote ${aggregatePath}: ${aggregateBadge.message} (${aggregateBadge.color})`);
