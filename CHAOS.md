# Chaos Sandbox

`securegit`'s guarantees aren't just asserted by unit tests against
hand-picked inputs — they're measured against a live, adversarial
simulation: real Docker containers, a real `git` daemon, real collaborators
pushing and pulling for minutes at a stretch, a real hostile pusher
attempting the exact attack catalogue in
[specs/securegit/16-adversarial-integrity.md](specs/securegit/16-adversarial-integrity.md),
and an unprivileged verifier auditing the result the same way a real
repository auditor would: a fresh clone, no key, no access to any actor's
workstation.

## What it proves

Three hard invariants, checked by the verifier after every run, regardless
of what chaos happened during it:

1. **No plaintext ever crossed the boundary** — every protected file, in
   every commit that ever existed, everywhere in reachable history, not
   just the latest one.
2. **The repository's object graph stayed intact** (`git fsck`),
   independent of confidentiality.
3. **Zero data loss** — every commit a run confirmed as pushed is still
   reachable, and every protected blob still decrypts to its original
   content, across every key rotation the run performed.

See [specs/chaotests/01-sandbox.md](specs/chaotests/01-sandbox.md) for the
full design and exactly how each invariant is audited.

## Three real-world git workflows, compared

The same attack traffic, run against three different ways teams actually
structure write access to a repository:

| | Workflow | Real-world shape | Who can move `master` |
|---|---|---|---|
| **W1** | Direct push to `master` | No review, no CI gate — common on small teams, early-stage repos, or any self-hosted server nobody has configured protection on | Anyone with push access, unconditionally |
| **W2** | Shared working branch, gated promotion | GitFlow's `develop`, a team's `staging` branch — fast collaboration upstream, a reviewed release step onto `master` | Anyone, on the working branch; only the promotion step, on `master` |
| **W3** | Pull request against a protected `master` | GitHub/GitLab/Bitbucket's standard model — every change reviewed before it can merge | Only the merge action itself, never a direct push |

Full design, including exactly what the automated reviewer checks and its
honestly-documented limits, in
[specs/chaotests/03-orchestrator.md](specs/chaotests/03-orchestrator.md).

### Two independent axes, not four workflows

Review workflow (W1/W2/W3 above) and commit-signing enforcement are two
genuinely separate mechanisms, easy to conflate as one — so the sandbox
models them as two independent flags, `SANDBOX_WORKFLOW` and
`SANDBOX_SIGNING` (`basic` — off, the default — or `advance`), crossed
together: 3 workflows × 2 signing tiers = **6 real, distinct modes**, not
three workflows plus a bolted-on fourth. `advance` requires every push —
to every ref the workflow doesn't already refuse outright — to be signed
by a fingerprint already on the repository's own recipient list.

| | Push-time signing gate (the hook) | Content review at promotion | `verify`'s own check |
|---|---|---|---|
| **W1** direct-master, basic | ❌ none | ❌ none (no promotion step exists) | runs, but a no-op (nobody's registered as a signer) |
| **W1** direct-master, advance | ✅ yes, on `master` itself | ❌ none — no promotion step, same as basic | enforces (signers registered) |
| **W2** working-branch, basic | ❌ none | ✅ only at promotion (`working` → `master`) | runs, but a no-op |
| **W2** working-branch, advance | ✅ yes, every ref | ✅ only at promotion (`working` → `master`) | enforces |
| **W3** pr-gated, basic | ❌ none | ✅ at every merge, per branch, finer-grained | runs, but a no-op |
| **W3** pr-gated, advance | ✅ yes, every ref | ✅ at every merge, per branch, finer-grained | enforces |

Signing is an *identity* check — is this commit from someone already
trusted with this repository's secrets — enforced independently of
whichever review workflow (or lack of one) a team runs on top of it.
direct-master+advance isolates that question on its own: does signing
alone stop an attacker with zero review process at all? **Confirmed, on
real GitHub Actions infrastructure: yes** — every attacker attempt
refused directly on `master` itself, 0 violations. Try it:
`SANDBOX_WORKFLOW=direct-master SANDBOX_SIGNING=advance npm run chaos:sandbox`.

## What real runs actually found

Not a projection — this is what happened, repeatedly, on real GitHub
Actions infrastructure. The full six-mode matrix was confirmed together
in one run
([34022273040](https://github.com/trinoris/securegit/actions/runs/34022273040)):

- **W3 (pr-gated) holds clean in both signing tiers.** `basic`: 0
  violations — branch isolation and content review already do the whole
  job, no signing needed. `advance`: also 0 violations, defense-in-depth
  on top. The attacker's downgrade/rollback/hostile-recipient attempts
  landed on its own isolated branch and either got explicitly rejected by
  the review or simply had no shared state to poison in the first place.
- **W1 (direct push) and W2 (shared working branch) both leak under
  `basic`** — direct-master: 12 violations, 3 hostile recipients;
  working-branch: 157 violations, matching this project's own earlier
  150-violation finding almost exactly. A gated *promotion* to `master`
  (W2) was never enough on its own: the shared branch everyone reads and
  writes is already visible to anyone with ordinary read access the
  moment anything lands on it, long before a promotion review ever runs.
- **Both close to zero under `advance`.** direct-master+advance and
  working-branch+advance: 0 violations, 0 hostile recipients, in the same
  run. Once every push — not just the promotion — requires a signature
  from a registered recipient, the attacker's attribute-downgrade attempts
  get refused directly (on `master` itself for W1, on `working` for W2),
  before any content ever lands.
- The live comparison — the actual current numbers, not last session's —
  is published every night: see "Watch it live" below.

## Watch it live

[![Chaos Match Viewer](https://img.shields.io/badge/chaos%20sandbox-live%20replay-3ecf8e)](https://trinoris.github.io/securegit/)

`.github/workflows/build-ci.yml`'s `chaos` job runs all six modes (three
workflows × two signing tiers) as a real, several-minute campaign every
night (and on demand via `workflow_dispatch`), and publishes the result
as a GitHub Pages site: a side-by-side verdict grouped by workflow, each
with a Basic/Advance pair, and a full match replay — friendly
collaborators, hostile contacts, a live commit log, three invariant gauges
resolving at the end — for whichever one you pick.

## Run it yourself

```sh
npm run chaos:sandbox
```

Runs `direct-master` + `basic` by default. Compare a different combination:

```sh
SANDBOX_WORKFLOW=working-branch npm run chaos:sandbox
SANDBOX_WORKFLOW=pr-gated npm run chaos:sandbox
SANDBOX_WORKFLOW=direct-master SANDBOX_SIGNING=advance npm run chaos:sandbox
SANDBOX_WORKFLOW=working-branch SANDBOX_SIGNING=advance npm run chaos:sandbox
```

See [chaos/README.md](chaos/README.md) for prerequisites, the exact
commands, and troubleshooting.

## The cast

| | Role | Behaviour |
|---|---|---|
| collaborator-a / collaborator-b | Legitimate collaborators | Clone, protect a file set, edit/commit/push on a loop, unlock as needed — ordinary daily use |
| code-agent | Legitimate collaborator (AI) | Identical loop to collaborator-a/b, no special-casing anywhere in the driver — models an AI coding agent committing like any human collaborator, same protections and signing requirements |
| operator / orchestrator | Maintenance & review | `direct-master`: key rotation, `verify`, status checks, and post-hoc attribute recovery. `working-branch`/`pr-gated`: reviews every proposed change before `master` ever moves |
| chaos-4 "virus" | Local corruption | Tampers with a collaborator's own session/keyring/identity files — the shape of commodity ransomware or a crashing backup tool |
| chaos-5 "attacker" | Hostile collaborator | Ordinary push access, nothing more — attempts attribute downgrades, blob relocation/rollback, and hostile recipients, exactly matching a real collaborator who turns hostile |
| bad-agent | Hostile collaborator (AI) | code-agent's adversarial counterpart — a second, independent instance of chaos-5's exact attack catalogue, modeling a compromised or malicious AI agent, never coordinated with chaos-5 |
| chaos-6 "infra" | Infrastructure faults | Kills processes mid-operation, fills disk, drops network links — impersonal fault injection, not attacker-shaped |
| verifier | Auditor | No key, fresh clone only — exactly the access a real outside auditor would have |

## Deep dives

- [specs/chaotests/00-test-plan.md](specs/chaotests/00-test-plan.md) — the
  deterministic, one-fault-at-a-time chaos categories this sandbox
  complements
- [specs/chaotests/01-sandbox.md](specs/chaotests/01-sandbox.md) — full
  sandbox design, topology, and exactly how each invariant is verified
- [specs/chaotests/02-viewer.md](specs/chaotests/02-viewer.md) — the
  replay viewer's own design
- [specs/chaotests/03-orchestrator.md](specs/chaotests/03-orchestrator.md)
  — the three-workflow comparison: reasoning, real-world precedent, the
  review's exact accept/reject criteria, and its honestly-documented gaps
- [specs/securegit/16-adversarial-integrity.md](specs/securegit/16-adversarial-integrity.md)
  — the attack catalogue chaos-5 automates, and why each one is or isn't
  fully solvable client-side
