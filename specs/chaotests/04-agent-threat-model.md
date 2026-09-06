# 04. A Trusted Agent, Hijacked — Prompt Injection Against a Real Recipient

## Overview

`bad-agent` (`01-sandbox.md`, `chaos/agents/attacker.mjs`) and `chaos-5`
model one specific threat: an *outsider* with ordinary push access but no
registered identity — matching threat model A6/A7
([../securegit/01-threat-model.md](../securegit/01-threat-model.md)).
Commit signing (`08-multi-recipient.md`'s "Commit signing",
`03-orchestrator.md`'s signing axis) closes exactly that gap: a signer
who was never added as a recipient can't produce a valid signature under
any registered key.

That is a different, narrower question from the one this document is
about: **what happens when the attacker isn't an outsider at all, but a
legitimate, already-registered AI coding agent (IDE or CLI) whose output
gets hijacked by a prompt injection?** Its signing key is real. Its
recipient registration is real. Every commit it produces is validly
signed by a fingerprint this repository's own recipient list already
trusts — because it genuinely is that recipient. Signing was never built
to answer "did this trusted party actually intend this," only "is this
party one we already trust." This document works out precisely which of
this project's existing mechanisms still hold against that gap, and
which one honestly doesn't.

**Status: BUILT and empirically confirmed.** `bad-agent`
([01-sandbox.md](01-sandbox.md)) now runs this document's own model, not
the outsider/A6-A7 case — a genuine `COLLABORATOR_ROLES` member
(`chaos/actors/driver.mjs`), registered and signing exactly like any
other collaborator, running the ordinary collaborator loop on ~70% of
rounds and one of the four PI1–PI4 attacks below
(`hijackedAgentRound()`) on the rest. Two real local Docker runs confirm
the predicted table exactly (see "Which existing mechanisms actually
protect against each" below for the numbers).

## Why this is a different attacker shape, precisely

| | chaos-5 / today's `bad-agent` | A hijacked trusted agent (this document) |
|---|---|---|
| Recipient status | Never registered, can't sign | **Registered — a real, valid recipient** |
| Signing key | None | **Real, its own, correctly enrolled** |
| Decrypt access | None (never touches an actor's HOME) | **Real — can smudge/decrypt protected content like any legitimate collaborator** |
| What stops it | The signing check itself (`commit-signed-by-recipient`, `pre-receive-check.mjs`) | **Not the signing check — everything else this section is about** |
| Real-world analogue | A stranger who found `git push` access | A developer's own IDE/CLI agent, correctly provisioned, fed a poisoned instruction (a malicious file it read, a compromised MCP tool response, an injected PR/issue comment) |

## A prompt-injection attack catalogue for a trusted agent

Four shapes, each signed with the hijacked agent's own valid, registered
key — the identity is never in question, only the intent behind the
commit:

- **PI1 — Plausible attribute "fix".** Downgrades `.gitattributes` under
  a benign-sounding pretext ("fix the overly broad pattern that's
  slowing down CI"). Structurally identical to T1
  ([16-adversarial-integrity.md](../securegit/16-adversarial-integrity.md)),
  just signed.
- **PI2 — Blob relocation as "refactor".** Moves a protected blob to an
  unprotected path under a plausible reorganization pretext. Structurally
  identical to T3, just signed.
- **PI3 — Direct plaintext exfiltration.** The agent has real decrypt
  access — it can legitimately `smudge` a protected file. A hijacked
  agent writes that *decrypted* content somewhere this project has never
  protected: an unprotected file, a commit message, a log line, an
  external tool call. No existing attack (T1/T3/T4/T5) models this
  because none of them assume the attacker can actually read plaintext in
  the first place.
- **PI4 — Hostile recipient, from a trusted signer.** Adds a new
  "helper" recipient under a plausible pretext ("onboard the new
  contractor"). Structurally identical to T5, just signed by someone
  already on the list rather than an unknown pusher.

## Which existing mechanisms actually protect against each

| | Signing check | Content review (orchestrator, W2/W3 promotion) | Recipient-change floor (unconditional) |
|---|---|---|---|
| PI1 (attribute downgrade) | ❌ no — validly signed | ✅ yes — `attributes-present` inspects the resulting tree, not who signed it | — |
| PI2 (blob relocation) | ❌ no | ⚠️ partial — same detector, but T3's own ceiling still holds: a relocated blob is still valid ciphertext, only caught if the pattern protecting the original path doesn't also cover the new one | — |
| PI3 (plaintext exfiltration) | ❌ no | ❌ **no hard check** — `verify`'s heuristic scan (AWS-key-shaped strings, etc., [13-verify.md](../securegit/13-verify.md)) is advice-tier only on unprotected paths, never a block | — |
| PI4 (hostile recipient) | ❌ no | — | ✅ **yes, unconditionally** — the orchestrator refuses *any* change under `.securegit/recipients/**` regardless of who signed it ([16](../securegit/16-adversarial-integrity.md)'s T5 section: signing narrows this, never retires it) |

**The honest finding, stated precisely:** signing contributes nothing to
PI1, PI2, or PI4 — each is already caught (fully or partially) by a
mechanism that was never identity-based in the first place. PI3 is
genuinely new and genuinely unmitigated: a legitimately-signed agent with
real decrypt access, exfiltrating plaintext through any channel that
isn't a protected repository path, has no hard stop anywhere in this
project today.

**Confirmed on two real local Docker runs** (`direct-master`+`advance`
vs. `pr-gated`+`advance`, both `CHAOS_DURATION_SECONDS=90`):

- **`direct-master`+`advance` (no content-review step exists at all under
  W1):** PI1/PI2/PI4 land completely unopposed — 399 plaintext violations,
  4 hostile recipient files, `.gitattributes` left not protecting the
  pattern. The PI1 attribute downgrade is what cascades into the 399: once
  the filter is gone, every subsequent `secrets/*.json` commit from any
  role lands as genuine plaintext, not just bad-agent's own. This is the
  concrete demonstration of the table's own point — the signing check
  that fully stops chaos-5 under this exact mode (`CHAOS.md`'s "0
  violations" finding) has nothing to say about a signer it already
  trusts.
- **`pr-gated`+`advance` (W3, content review + the unconditional
  recipient floor both apply):** 0 plaintext violations, 0 hostile
  recipients, `.gitattributes` still protects the pattern — PI1/PI2/PI4
  fully caught, exactly as predicted. PI3 still landed unopposed (38
  exfiltration occurrences, correctly reported by
  `checkAgentExfiltration()` as observed-not-prevented, correctly *not*
  counted against `hardInvariantsHeld` — see "What building this would
  actually require" below).

## This is not a sandbox bug — it's an existing, named boundary

[../securegit/01-threat-model.md](../securegit/01-threat-model.md)
already states this limit for a human: **"An attacker with code
execution on an unlocked workstation. They have the plaintext working
tree. Nothing here helps."** A hijacked agent with real decrypt access is
the same boundary, restated for an agent rather than a person at a
compromised terminal — this document doesn't discover a new gap, it
demonstrates an already-acknowledged one concretely enough to put in the
chaos sandbox next to everything else it already proves.

## How this was actually built

- `bad-agent` was added to `COLLABORATOR_ROLES` in
  `chaos/actors/driver.mjs`, going through the *same*
  `registerSigningRecipients()` flow every legitimate collaborator uses —
  its key is genuinely registered, not `chaos-5`'s "never a recipient"
  shape. `chaos/docker-compose.yml`'s `bad-agent` service now mirrors
  `code-agent`'s (real `HOME`/keyring volumes, `driver.mjs`, not
  `attacker.mjs`) rather than `chaos-5-attacker`'s.
- Four new attack functions in `driver.mjs` —
  `hijackedAttributeDowngrade`, `hijackedBlobRelocation`,
  `hijackedPlaintextExfiltration`, `hijackedRecipientAddition` — each
  producing one real, validly signed commit under a plausible pretext,
  dispatched by `hijackedAgentRound()` on ~30% of bad-agent's rounds (the
  rest are an ordinary collaborator round — modeling a hijack as an
  occasional event during otherwise-legitimate agent use, not a
  permanently hostile actor).
- PI3 has its own honest handling: `chaos/verifier/verify.mjs`'s
  `checkAgentExfiltration()` scans history for the `debug.log` path PI3
  writes to and reports `{ observed, occurrences }` as its own top-level
  `agentExfiltration` field — deliberately never folded into
  `noPlaintextLeaked` (which stays scoped to protected paths under
  `secrets/`) and never a CI failure condition. The correct outcome for a
  PI3 attempt is "observed, not prevented," and that's exactly what gets
  reported, not silently absent or mistaken for a passing check.
- `chaos/viewer/index.html`'s `classifyRealEvent()` matches
  `/^PI[1-4] hijacked/` on message text (not on role) before the
  role-based branches, so bad-agent's ordinary unlock/pull/push rounds
  render through the same path every collaborator's do, and only its
  PI1-4 rounds render as hostile events; the demo generator was updated
  to match (bad-agent joins the friendly push loop, then independently
  rolls a ~30% chance per round of one of the four PI events, rather than
  running chaos-5's own T1/T3/T4/T5 catalogue).
- Confirmed on two real local Docker runs, not asserted from the analysis
  alone — see the numbers above.

## Relationship to other specs

- [../securegit/01-threat-model.md](../securegit/01-threat-model.md) —
  the "code execution on an unlocked workstation" boundary this document
  restates for an agent
- [../securegit/16-adversarial-integrity.md](../securegit/16-adversarial-integrity.md)
  — T1/T3/T4/T5, the attack shapes PI1/PI2/PI4 are signed variants of
- [03-orchestrator.md](03-orchestrator.md) — the signing axis and the
  content-review mechanisms this document evaluates PI1/PI2/PI3/PI4
  against
- [01-sandbox.md](01-sandbox.md) — `bad-agent` as it exists today (the
  outsider/A6-A7 case), unchanged by this document
