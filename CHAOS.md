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

**These numbers predate `bad-agent`'s redefinition** (below) — at the
time of run 34022273040, `bad-agent` still ran chaos-5's own outsider
attack catalogue, doubling attack pressure rather than adding a distinct
threat shape. The findings above (in particular "both close to zero under
`advance`") describe the signing check's effect on an *unregistered*
attacker only.

### A signed attacker changes the picture — the trusted-agent-hijack finding

`bad-agent` now models something the numbers above don't cover at all: a
genuinely registered, genuinely signing collaborator, hijacked into a
prompt-injection-shaped attack on a fraction of its rounds
([specs/chaotests/04-agent-threat-model.md](specs/chaotests/04-agent-threat-model.md)).
Confirmed locally, then on real GitHub Actions infrastructure
([run 34041479353](https://github.com/trinoris/securegit/actions/runs/34041479353)),
where the longer run surfaced a real mechanism the shorter local runs
missed:

- **`direct-master`+`advance`:** signing alone stops nothing here — W1 has
  no content-review step at all, at any signing tier. Locally: 399
  plaintext violations (the attribute-downgrade cascading into every
  subsequent `secrets/*.json` commit from *any* role, not just
  bad-agent's own) and 4 hostile recipient files. On CI: 3 hostile
  recipients landed in the shorter window; the downgrade itself hadn't
  fired yet when the run ended — same underlying finding, different
  dice roll.
- **`pr-gated` (both signing tiers) — real plaintext still reaches the
  remote, just never `master`.** The review gate keeps `master` itself
  completely clean in every run (`.gitattributes` intact, 0 hostile
  recipients) — but on real CI (180s runs, long enough for bad-agent to
  downgrade its own branch *and then keep committing to it*), 22–28
  plaintext violations landed, every single one `secrets/bad-agent.json`
  on bad-agent's own now-unfiltered branch. Branch isolation stops an
  attack from reaching *other* collaborators; it was never a guarantee
  against an attacker poisoning its own branch's own future commits —
  no prior attacker-shaped role ever also did ongoing legitimate work on
  the branch it attacked. Full mechanism in
  [specs/chaotests/04-agent-threat-model.md](specs/chaotests/04-agent-threat-model.md)'s
  "self-poisoning correction". Plaintext exfiltration to an unprotected
  path (`debug.log`) also got through in every `pr-gated` run (11–38
  occurrences) — honestly reported by the verifier as observed, not
  prevented, and correctly not counted as a violation of any hard
  invariant, since no mechanism in this project claims to stop it.

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
| chaos-5 "attacker" | Hostile outsider | Ordinary push access, no registered identity — attempts attribute downgrades, blob relocation/rollback, and hostile recipients, exactly matching a real collaborator-shaped attacker who was never a recipient |
| bad-agent | Hijacked trusted agent (AI) | A genuine, registered, signing collaborator — same identity and decrypt access as code-agent — that on ~30% of rounds is hijacked into one of four *signed* prompt-injection attacks (attribute downgrade, blob relocation, plaintext exfiltration, hostile recipient) instead of an ordinary commit; see [specs/chaotests/04-agent-threat-model.md](specs/chaotests/04-agent-threat-model.md) |
| chaos-6 "infra" | Infrastructure faults | Kills processes mid-operation, fills disk, drops network links — impersonal fault injection, not attacker-shaped |
| verifier | Auditor | No key, fresh clone only — exactly the access a real outside auditor would have |

### Reading run length as simulated time

`CHAOS_DURATION_SECONDS` is just wall-clock seconds — nothing in the code
tracks "day" or "hour," and no actor behaves differently at simulated
2am vs. simulated 2pm (every actor's round loop runs at the same jittered
pace — `chaos/lib/proc.mjs`'s `jitter()` — for the whole duration,
uniformly). The table below is a human-readable *scale* for interpreting
how much real-world activity a given run length stands in for, not a
mechanic the sandbox itself implements:

| Real time | Simulated time (T) |
|---|---|
| 1 workday (~9–10h of active collaboration) | T0:00 → T2:00 |
| Day 2 | T2:00 → T4:00 |
| Day 3 | T4:00 → T6:00 |
| Day 4 | T6:00 → T8:00 |
| Day 5 | T8:00 → T10:00 |
| Day 6 (weekend, lighter activity) | T10:00 → T12:00 |
| Day 7 (weekend, lighter activity) | T12:00 → T14:00 |

...i.e. one real workday ≈ 2 simulated minutes, so a full simulated week
is 14 minutes end to end. Mapped onto the actual durations this project
runs:

| Run | `CHAOS_DURATION_SECONDS` | Simulated span |
|---|---|---|
| `npm run chaos:sandbox` default | 300 (5 min) | ~T0:00–T5:00 — about 2½ simulated workdays |
| `build-ci.yml`'s own matrix legs | 180 (3 min) | ~T0:00–T3:00 — about 1½ simulated workdays |
| A full simulated week | 840 (14 min) | T0:00–T14:00 — all 7 days |

```sh
CHAOS_DURATION_SECONDS=840 npm run chaos:sandbox
```

Longer runs matter for more than flavor: the pr-gated self-poisoning
finding above ([specs/chaotests/04-agent-threat-model.md](specs/chaotests/04-agent-threat-model.md))
only ever showed up on real CI's 180s/T3:00 legs — the 90s/T1:30 local
runs used while building it were simply too short for bad-agent to both
fire PI1 and then get another ordinary round in afterward. A run that
looks clean at T1:30 isn't necessarily clean at T3:00 or T14:00 — the
same actor-timing randomness that makes every run genuinely different
(see "Run it yourself") also means a longer simulated span is strictly
more likely to surface a low-probability interaction, never less.

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
