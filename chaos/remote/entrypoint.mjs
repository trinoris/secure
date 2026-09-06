// The `remote` service: an anonymous `git daemon` serving one bare repo.
// No auth — this is a Docker Compose-internal network, not exposed outside
// the sandbox, and the repo holds only ciphertext regardless
// (01-threat-model.md's whole point). `-b main` pins the bare repo's HEAD
// symref up front so every actor's later `git checkout main` is an
// ordinary, unambiguous operation — see chaos/actors/driver.mjs's
// bootstrap comments for why that matters.
//
// Always installs the same `pre-receive` hook (pre-receive-check.mjs),
// regardless of SANDBOX_WORKFLOW/SANDBOX_SIGNING — it reads both env vars
// itself and derives two independent booleans from them
// (specs/chaotests/03-orchestrator.md):
//
//   - REFUSES_PROTECTED_REF_OUTRIGHT (from SANDBOX_WORKFLOW): true for
//     working-branch/pr-gated, false for direct-master. When true, any
//     *update* (not creation) of `refs/heads/<BRANCH>` over the ordinary
//     git protocol is refused unconditionally, for every pusher, since
//     `git://` has no identity to exempt the orchestrator by — it lands
//     its own reviewed merges by a different, privileged path instead: a
//     direct `update-ref` against this same bare repo over a shared
//     filesystem volume (REMOTE_REPO_PATH in docker-compose.yml), which
//     never invokes `receive-pack` and so never runs this hook at all.
//   - SIGNING_CHECK_ENABLED (from SANDBOX_SIGNING): true for "advance",
//     false for "basic". When true, every ref this hook doesn't already
//     refuse outright must have every commit a push introduces signed by
//     a fingerprint on the protected branch's own recipient list, or the
//     whole push is refused.
//
// The four combinations that matter for direct-master/working-branch/
// pr-gated crossed with basic/advance all fall out of these two booleans
// without any workflow-specific branching in the hook itself — including
// direct-master+advance (REFUSES=false, SIGNING=true: nothing refused
// outright, but master itself is signing-checked) and direct-master+basic
// (both false: a true no-op, identical to no hook at all). See
// 03-orchestrator.md's "Enforcing 'only the orchestrator writes master'"
// for the real-world server-side equivalents (self-hosted `pre-receive`,
// or github.com's required status checks) and its honest limits.

import { existsSync, writeFileSync, chmodSync } from 'node:fs';
import { spawn, execFileSync } from 'node:child_process';

const REPO_PATH = process.env.REPO_PATH ?? '/repos/repo.git';
const BRANCH = process.env.BRANCH ?? 'main';
const SANDBOX_WORKFLOW = process.env.SANDBOX_WORKFLOW ?? 'direct-master';
const SANDBOX_SIGNING = process.env.SANDBOX_SIGNING ?? 'basic';

if (!existsSync(REPO_PATH)) {
  execFileSync('git', ['init', '--bare', '-b', 'main', REPO_PATH], { stdio: 'inherit' });
  execFileSync('git', ['config', '--file', `${REPO_PATH}/config`, 'daemon.uploadpack', 'true'], { stdio: 'inherit' });
  execFileSync('git', ['config', '--file', `${REPO_PATH}/config`, 'daemon.receivepack', 'true'], { stdio: 'inherit' });
}

const PROTECTED_REF = `refs/heads/${BRANCH}`;
const hookPath = `${REPO_PATH}/hooks/pre-receive`;
// `exec` (not a plain call) so the node process inherits this shell's
// stdin unconsumed — pre-receive-check.mjs reads the "<old> <new> <ref>"
// lines itself, git delivers no other input.
writeFileSync(hookPath, '#!/bin/sh\nexec node /chaos/remote/pre-receive-check.mjs\n');
chmodSync(hookPath, 0o755);

const refusesOutright = SANDBOX_WORKFLOW !== 'direct-master';
const signingEnabled = SANDBOX_SIGNING === 'advance';
const hookDescription = !refusesOutright && !signingEnabled
  ? 'is a no-op'
  : refusesOutright && !signingEnabled
    ? `protects ${PROTECTED_REF} outright, no signing check`
    : !refusesOutright && signingEnabled
      ? `enforces signing on every ref including ${PROTECTED_REF}, refuses nothing outright`
      : `protects ${PROTECTED_REF} outright, enforces signing on every other ref`;
process.stdout.write(`[remote] SANDBOX_WORKFLOW=${SANDBOX_WORKFLOW}, SANDBOX_SIGNING=${SANDBOX_SIGNING}, pre-receive hook ${hookDescription}\n`);

process.stdout.write(`[remote] serving ${REPO_PATH} on :9418\n`);

const child = spawn(
  'git',
  ['daemon', '--verbose', '--export-all', '--reuseaddr', '--enable=receive-pack', '--base-path=/repos', '/repos'],
  { stdio: 'inherit' },
);
child.on('exit', (code) => process.exit(code ?? 1));
