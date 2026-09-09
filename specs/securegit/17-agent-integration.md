# 17. Agent Integration

## Overview

An AI coding agent (Claude Code, Cursor, GitHub Copilot, Kiro, and others)
operating inside a `securegit`-protected repository needs to know a handful
of things no amount of reading source code reliably teaches it in time: that
`securegit install` is a separate, easy-to-forget step from `init`; that a
locked repository should be unlocked with `securegit unlock`, never worked
around; that `--json` and specific environment variables exist for
non-interactive use; and what each exit code means before deciding whether a
failure is safe to retry. Getting this wrong is not hypothetical — the
person who wrote this exact spec [independently forgot the `install` step
in this project's own README quickstart](05-cli-guide.md) and only caught it
while writing the CLI guide.

`securegit agent install` writes this knowledge directly into the
repository, in whatever file shape each tool already knows how to load
automatically — a Claude Code Skill, a Cursor Rule, a GitHub Copilot
instructions file, a Kiro steering document — so an agent never has to
infer `securegit`'s workflow from source, and never has to be told the same
five things in every new conversation.

## Design principles

1. **One body of instructions, several frontmatter wrappers.** The actual
   guidance (what to run, in what order, what never to do) is identical
   across every target — only the YAML frontmatter each tool requires to
   discover and load the file differs. Written once, in
   `src/agent-content.ts`, and wrapped per target at install time. This is
   the same reasoning [10](10-cli-contract.md) applies to `--json`: one
   underlying object, rendered differently for different consumers.
2. **Minimal, copy-pasteable examples over prose.** An agent that has to
   infer a flag's exact spelling from a paragraph is an agent that
   occasionally invents one that doesn't exist. Every instruction that
   names a command pairs it with the exact, runnable invocation — the same
   discipline [05-cli-guide.md](../../docs/securegit/05-cli-guide.md) and
   every `--help` entry in [10](10-cli-contract.md) already follow, and for
   the same reason.
3. **Idempotent, never silently overwrites foreign content.** Same rule
   `install()` already enforces for `.git/config` ([02](02-git-integration.md)):
   a file this command didn't originally write is left alone unless
   `--force` is passed. Every generated file opens with a marker
   (`managed by: securegit agent install (v1)`, `src/agent-install.ts`'s
   `MARKER`) that a re-run checks for before overwriting — as a `#` YAML
   comment for a frontmatter target, or an HTML comment for a plain-Markdown
   one (a bare `# ...` line there would render as a real, wrong heading).
4. **No network calls, no new runtime dependency.** Every target's file
   format is plain text this process constructs directly — consistent with
   the zero-runtime-dependency property [16](16-adversarial-integrity.md)
   (T11) already holds for the rest of `securegit`.

## Targets

| Target | File written | Discovery mechanism |
|---|---|---|
| `claude` | `.claude/skills/securegit/SKILL.md` | Claude Code scans every skill's `description` frontmatter field at startup; the body loads only once a prompt matches it (progressive disclosure) |
| `cursor` | `.cursor/rules/securegit.mdc` | Cursor's Agent-Requested rule type: matched against the `description` frontmatter field, no `globs`/`alwaysApply: true` needed since this is workflow guidance, not file-type-scoped |
| `copilot` | `.github/instructions/securegit.instructions.md` | GitHub Copilot loads any `.github/instructions/*.instructions.md` file whose `applyTo` glob matches the files in play; this one uses `applyTo: "**"` since the guidance is repository-wide, not path-scoped |
| `kiro` | `.kiro/steering/securegit.md` | Kiro loads every steering file with `inclusion: always` into every session automatically |
| `codex` | `AGENTS.md` (repo root) | OpenAI Codex CLI's own convention — plain Markdown, no frontmatter, loaded automatically from the repo root. Also the emerging cross-tool `agents.md` standard a growing number of other agents read as a fallback, so this file benefits more than Codex alone |
| `gemini` | `GEMINI.md` (repo root) | Gemini CLI's hierarchical context file — plain Markdown, no frontmatter, concatenated into every prompt automatically |
| `antigravity` | `.agents/rules/securegit.md` | Antigravity reads root `AGENTS.md` too, but its more specific convention for splitting guidance by topic is a `.agents/rules/` folder of plain Markdown files — used here so this target writes a file of its own rather than silently duplicating `codex`'s `AGENTS.md` |

`securegit agent install` with no target installs all seven. Each target is
independent — installing `claude` never touches `.cursor/`, `.github/`,
`.kiro/`, or any other target's file, and a target whose parent directory
doesn't exist yet gets one created, the same way `init` creates
`.securegit/`.

None of these formats were guessed — each was verified against that tool's
own current documentation before this spec was written: Claude Code's
skills docs (`name`, `description`, `.claude/skills/<name>/SKILL.md`),
Cursor's rules docs (`description`/`globs`/`alwaysApply` in `.mdc`
frontmatter), GitHub's custom-instructions docs (`applyTo` glob frontmatter
in `.github/instructions/*.instructions.md`), Kiro's steering docs
(`inclusion`/`fileMatchPattern`/`name`/`description` frontmatter in
`.kiro/steering/*.md`), Codex CLI's and Gemini CLI's own `AGENTS.md`/
`GEMINI.md` docs (plain Markdown, no frontmatter, root-level), and
Antigravity's rules docs (`.agents/rules/` folder, plain Markdown, no
frontmatter). Two distinct marker styles follow from this split — see
"Design principles" above. Another target is a small, mechanical addition
later if a further tool converges on its own file-based convention —
nothing about the shared body content is target-specific.

## The shared instruction body

Kept intentionally short — this is a trigger and a cheat sheet an agent
consults at the start of a task, not a copy of
[05-cli-guide.md](../../docs/securegit/05-cli-guide.md). It covers, in this
order:

1. **What this repository is**: files matching certain patterns are
   transparently encrypted at rest; `git add`/`commit`/`push`/`diff` behave
   normally from a machine that holds the key.
2. **Before touching a file that might hold a secret**: check whether it's
   already covered by `.gitattributes` (`git check-attr filter -- <path>`);
   if not, `securegit protect <pattern>` (or `securegit protect` alone for
   the fast-setup defaults) before adding real secret content, never after.
3. **Setup, verbatim**, for a fresh repository:
   ```sh
   securegit init
   securegit install
   securegit protect
   ```
4. **Before finishing any task that touched a protected path**:
   ```sh
   securegit verify
   ```
   Exit code 5 means a protected path's committed content is not real
   ciphertext — stop and investigate, never commit past this.
5. **If a command exits locked (1)**: run `securegit unlock`, don't attempt
   to work around it by reading the raw ciphertext or disabling the filter.
6. **Non-interactive / scripted use**: `SECUREGIT_PASSPHRASE` (env var) in
   place of an interactive passphrase prompt; `--json` on `status`,
   `verify`, `inspect`, `key list`, `key list-recipients` for parseable
   output; check the process exit code, not stdout text, to decide success.
7. **Never**: print, log, or commit a passphrase, recovery code, or the
   contents of `~/.securegit/`; disable `filter.securegit.required`; encrypt
   or decrypt a file by any path other than `securegit`'s own commands.
8. **Full reference**: a pointer to
   `docs/securegit/05-cli-guide.md`, `specs/securegit/10-cli-contract.md`,
   and `securegit help`/`securegit <command> --help` for anything this
   summary doesn't cover.

## CLI contract

| Command | Effect |
|---|---|
| `securegit agent install [<target>...] [--force]` | Writes the skill/rule/instructions files for the given targets (`claude`, `cursor`, `copilot`, `kiro`, `codex`, `gemini`, `antigravity`), or all seven with none given. `--force` overwrites a file this command did not originally write (identified by its marker); without it, a foreign file at the same path is refused, matching `install()`'s own rule. |
| `securegit agent list` | Prints the targets and the exact path each would write, without writing anything — useful for an agent (or a human) to check what's already there first. |

Exit codes follow the existing convention: `0` on success (including "every
target already up to date, nothing changed"); `4` (usage) for an unknown
target name; `2` (misconfigured) if a target's file exists and was not
written by this command, without `--force`.

No repository unlock is needed for either command — like `install`, this
only ever writes local instructional files, never touches keys.

## Test Cases

| Test | Test File | Fixture | Status |
|---|---|---|---|
| `agent install` with no target writes every target's file | `src/agent-install.test.ts` | — | ✅ |
| `agent install claude` writes only `.claude/skills/securegit/SKILL.md` | `src/agent-install.test.ts` | — | ✅ |
| Every frontmatter target (`claude`/`cursor`/`copilot`/`kiro`) parses as valid `---`-delimited YAML frontmatter + Markdown body | `src/agent-install.test.ts` | — | ✅ |
| Every plain-Markdown target (`codex`/`gemini`/`antigravity`) has no frontmatter, only the HTML-comment marker and the shared body | `src/agent-install.test.ts` | — | ✅ |
| `codex` and `gemini` write distinct root files (`AGENTS.md`, `GEMINI.md`), not the same path | `src/agent-install.test.ts` | — | ✅ |
| Re-running `agent install` is idempotent (no diff on a second run) | `src/agent-install.test.ts` | — | ✅ |
| A hand-edited file (marker missing) is refused without `--force` | `src/agent-install.test.ts` | — | ✅ |
| `--force` overwrites a foreign file | `src/agent-install.test.ts` | — | ✅ |
| `agent install bogus-target` exits usage (4) | `src/agent-install.test.ts`, `src/cli.test.ts` | — | ✅ |
| `agent list` / `agent list --json` prints targets and paths, writes nothing | `src/cli.test.ts` | — | ✅ |
| `securegit agent --help`, `agent install --help`, `agent list --help` render from the same `HELP` table `10-cli-contract.md`'s help system uses | `src/cli.test.ts` | — | ✅ |
| The shared instruction body names no command or flag absent from `HELP` in `src/cli.ts` | `src/agent-install.test.ts` | — | ✅ |

## Relationship to Other Specs

- [02](02-git-integration.md) — `install()`'s own foreign-content refusal
  rule, reused here for the same reason
- [10](10-cli-contract.md) — the `HELP` data this spec's shared body must
  never drift from; also where `--help`'s own agent-friendly manifest
  (`securegit help --json`) is documented
- [05-cli-guide.md](../../docs/securegit/05-cli-guide.md) — the full
  human-oriented reference this spec's shared body points to rather than
  duplicates
