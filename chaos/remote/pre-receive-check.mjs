#!/usr/bin/env node
// The full `pre-receive` hook, installed unconditionally for every
// SANDBOX_WORKFLOW (specs/chaotests/03-orchestrator.md, "Enforcing 'only
// the orchestrator writes master'" and its signing-check extension). Two
// independent checks, each driven by its own env var, both unconditional
// for every network pusher — there is still no pusher *identity* here
// (git:// has none to check), only ref names and the commits' own
// embedded signatures:
//
//   1. From SANDBOX_WORKFLOW: for working-branch/pr-gated, refuse any
//      *update* (not creation) of the protected branch, always —
//      unchanged from the original hook. The orchestrator lands its own
//      reviewed merges through a different, privileged filesystem path
//      (`update-ref`, driver.mjs's landReviewedMerge()) that never
//      invokes receive-pack and so never runs this hook at all.
//      direct-master (either signing tier) deliberately does *not* apply
//      this rule at all — see REFUSES_PROTECTED_REF_OUTRIGHT below.
//   2. From SANDBOX_SIGNING: "basic" (the default) runs no signing check
//      at all, on any ref — the original, pre-signing behavior. "advance"
//      requires every commit a push introduces, on every ref this hook
//      doesn't already refuse outright, to be signed by a fingerprint
//      already on the protected branch's own recipient list, or the
//      whole push is refused. This closes the exact gap that let
//      chaos-5's T1 attribute-downgrade attack sit on `working`, unsigned
//      and undetected, for the rest of a run under working-branch+basic
//      (see that spec's "Since then" note) — and needs no pusher identity
//      either: `%GF` resolves a commit's real signer straight from its
//      own embedded signature, independent of how it arrived, so a
//      hostile pusher can't opt out of it by pushing "as" anyone — they
//      simply can't produce a valid signature under a key that was never
//      registered.
//
// These two checks are genuinely independent — direct-master+advance has
// no ref refused outright but every commit signing-checked; working-
// branch+basic refuses `master` updates but signing-checks nothing.
//
// Reuses this project's own real code directly — /app/dist is baked into
// this same shared image (chaos/Dockerfile), exactly like
// chaos/lib/paths.mjs's re-exports — rather than reimplementing
// fingerprint hashing or constant-time comparison a second time here.

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { signingKeyFingerprint } from '/app/dist/identity.js';
import { equalCt } from '/app/dist/crypto.js';

const REPO_PATH = process.env.REPO_PATH ?? '/repos/repo.git';
const BRANCH = process.env.BRANCH ?? 'main';
const SANDBOX_WORKFLOW = process.env.SANDBOX_WORKFLOW ?? 'direct-master';
const SANDBOX_SIGNING = process.env.SANDBOX_SIGNING ?? 'basic';
const PROTECTED_REF = `refs/heads/${BRANCH}`;
const ZERO_SHA = '0'.repeat(40);

function git(args) {
  return execFileSync('git', ['--git-dir', REPO_PATH, ...args], { encoding: 'utf8' });
}

/**
 * Registered signing fingerprints, read from the protected branch's own
 * committed tree — never the incoming ref's own claims, the same T1
 * precision 16-adversarial-integrity.md's own note insists on ("evaluate
 * against the state *before* the push, not the incoming one"). Two
 * no-op-tier reasons this can come back empty, mirroring
 * verify.ts's commit-signed-by-recipient exactly: fewer than 2 recipients
 * (no one to impersonate), or none of them has adopted signing yet.
 */
function registeredFingerprints() {
  let entries;
  try {
    // `-r` is required: without it, `.securegit/recipients` being a tree
    // itself makes `ls-tree` return exactly one bogus "entry" — the
    // directory name — never its contents. Confirmed the hard way: that
    // bug made `entries.length` always 1, permanently tripping the
    // "fewer than 2 recipients" no-op tier below regardless of how many
    // real recipients existed, so this check silently never enforced
    // anything at all.
    entries = git(['ls-tree', '-r', '--name-only', BRANCH, '--', '.securegit/recipients'])
      .trim()
      .split('\n')
      .filter(Boolean);
  } catch {
    return { recipientCount: 0, registered: [] };
  }
  const registered = [];
  for (const path of entries) {
    let file;
    try {
      file = JSON.parse(git(['show', `${BRANCH}:${path}`]));
    } catch {
      continue; // unreadable or malformed — can't match, same as absent
    }
    if (!file.signingKey) continue;
    try {
      registered.push(signingKeyFingerprint(file.signingKey));
    } catch {
      // malformed signingKey already committed — same as absent
    }
  }
  return { recipientCount: entries.length, registered };
}

/** The commit's real signer fingerprint, or `null` if it isn't signed at all. */
function commitFingerprint(sha) {
  try {
    const out = execFileSync(
      'git',
      ['--git-dir', REPO_PATH, '-c', 'gpg.ssh.allowedSignersFile=/dev/null', 'log', '-1', '--format=%GF', sha],
      { encoding: 'utf8' },
    ).trim();
    return out.length > 0 ? out : null;
  } catch {
    return null;
  }
}

/**
 * Every commit this specific push introduces — not the ref's whole
 * history. `--no-merges`: a merge commit doesn't introduce new *content*
 * of its own — that came from its parents, which are checked on their own
 * merits (either already signed themselves, or already on the protected
 * branch) — so requiring the merge commit itself to *also* carry a
 * signature would mean the orchestrator's own landing commits
 * (chaos/actors/driver.mjs's `landReviewedMerge()`, which pushes a
 * genuine merge commit to a scratch ref as part of transferring its
 * objects) permanently fail this check, since the operator was never
 * given a signing identity of its own — deliberately, since it never
 * contributes content commits (see driver.mjs's own comment on that).
 */
function newCommits(oldSha, newSha) {
  if (newSha === ZERO_SHA) return []; // a deletion — nothing to check
  const range = oldSha === ZERO_SHA ? [newSha, '--not', '--all'] : [`${oldSha}..${newSha}`];
  try {
    return git(['rev-list', '--no-merges', ...range]).trim().split('\n').filter(Boolean);
  } catch {
    return [];
  }
}

// direct-master (either signing tier) deliberately never refuses updates
// to PROTECTED_REF at all — it has no promotion step, no orchestrator, by
// definition. working-branch/pr-gated always refuse any direct update to
// PROTECTED_REF unconditionally, regardless of SANDBOX_SIGNING.
const REFUSES_PROTECTED_REF_OUTRIGHT = SANDBOX_WORKFLOW !== 'direct-master';
// "basic" (the default) never runs the signing check at all, on any ref —
// the original, pre-signing behavior, preserved exactly as an explicit
// opt-out rather than something only direct-master could ever have.
const SIGNING_CHECK_ENABLED = SANDBOX_SIGNING === 'advance';

const lines = readFileSync(0, 'utf8').trim().split('\n').filter(Boolean);
let status = 0;
let signingTier = null; // computed lazily, once, only if some ref actually needs it

for (const line of lines) {
  const [oldSha, newSha, ref] = line.split(' ');

  if (ref === PROTECTED_REF && REFUSES_PROTECTED_REF_OUTRIGHT) {
    if (oldSha !== ZERO_SHA) {
      console.error(
        `remote: refusing direct push to ${PROTECTED_REF} — this workflow (${SANDBOX_WORKFLOW}) only accepts reviewed merges`,
      );
      status = 1;
    }
    continue;
  }

  if (!SIGNING_CHECK_ENABLED) continue; // "basic" tier — no signing check on any ref

  if (signingTier === null) signingTier = registeredFingerprints();
  if (signingTier.recipientCount < 2 || signingTier.registered.length === 0) continue; // not yet adopted

  for (const sha of newCommits(oldSha, newSha)) {
    const fingerprint = commitFingerprint(sha);
    if (fingerprint === null) {
      console.error(`remote: refusing push to ${ref} — commit ${sha.slice(0, 8)} is not signed`);
      status = 1;
      continue;
    }
    const fingerprintBuf = Buffer.from(fingerprint, 'utf8');
    const isRegistered = signingTier.registered.some((r) => equalCt(Buffer.from(r, 'utf8'), fingerprintBuf));
    if (!isRegistered) {
      console.error(`remote: refusing push to ${ref} — commit ${sha.slice(0, 8)} is signed by an unrecognized key (${fingerprint})`);
      status = 1;
    }
  }
}

process.exit(status);
