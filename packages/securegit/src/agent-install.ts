// Writes AI-coding-agent instruction files (Claude Code Skill, Cursor Rule,
// GitHub Copilot instructions, Kiro steering) so an agent operating in this
// repository knows securegit's workflow without inferring it from source.
// One shared instruction body, wrapped per target's own frontmatter format.
// See specs/securegit/17-agent-integration.md.

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

export class AgentInstallError extends Error {
  readonly code = 'AGENT_INSTALL';
  /** Lets the CLI pick the right exit code without parsing the message. */
  readonly kind: 'unknown-target' | 'foreign-file';

  constructor(message: string, kind: 'unknown-target' | 'foreign-file') {
    super(message);
    this.name = 'AgentInstallError';
    this.kind = kind;
  }
}

/**
 * The text every generated file carries somewhere near the top — checked
 * (via plain substring) before any overwrite, so a file a person has since
 * hand-edited is never silently replaced. Two targets wrap it differently:
 * a YAML-frontmatter target gets it as a `#` comment line *inside* the
 * frontmatter block (valid YAML, invisible to the tool reading it); a
 * plain-Markdown target (no frontmatter convention at all — AGENTS.md,
 * GEMINI.md) gets it as an HTML comment instead, since a bare `# ...` line
 * there would render as a visible, wrong H1 heading.
 */
const MARKER_TEXT = 'managed by: securegit agent install (v1) — https://github.com/trinoris/secure';
export const MARKER = MARKER_TEXT;
const YAML_MARKER = `# ${MARKER_TEXT}`;
const HTML_MARKER = `<!-- ${MARKER_TEXT} -->`;

/**
 * The one body of guidance, identical across every target. Kept to what an
 * agent needs at the start of a task, not a copy of
 * docs/securegit/05-cli-guide.md — every command named here pairs with its
 * exact invocation, deliberately, so an agent reading this has something to
 * copy rather than something to guess at.
 */
export const AGENT_INSTRUCTIONS = `# securegit

This repository uses \`securegit\`: files matching certain patterns are
transparently encrypted at rest. \`git add\`, \`git commit\`, \`git push\`,
\`git diff\` all behave normally from a machine that already holds the key —
nothing about the Git workflow itself changes.

## Before adding a file that might hold a secret

Check whether it's already covered:

\`\`\`sh
git check-attr filter -- path/to/file
\`\`\`

If it isn't, protect it **before** adding real secret content, not after:

\`\`\`sh
securegit protect path/to/file
\`\`\`

With no pattern, \`securegit protect\` applies a conservative default set of
common secret-shaped filenames instead — a fast path for a repository that
isn't set up yet at all:

\`\`\`sh
securegit init
securegit install
securegit protect
\`\`\`

(\`install\` is easy to skip and easy to forget: without it, Git never
invokes the encryption filter at all, and "protected" files check out as
plain, ordinary text.)

## Before finishing any task that touched a protected path

\`\`\`sh
securegit verify
\`\`\`

Exit code 5 means a protected path's committed content is not actually
ciphertext. Stop and investigate — never commit past this.

## If a command exits locked (exit code 1)

\`\`\`sh
securegit unlock
\`\`\`

Never work around a locked repository by reading raw ciphertext directly or
disabling the filter (\`filter.securegit.required\`) to force a checkout.

## Non-interactive / scripted use

- \`SECUREGIT_PASSPHRASE=... securegit unlock\` instead of an interactive
  prompt.
- \`--json\` on \`status\`, \`verify\`, \`inspect\`, \`key list\`,
  \`key list-recipients\` for machine-readable output.
- Check the process **exit code** to decide success, not stdout text —
  \`securegit help\` lists every command; \`securegit <command> --help\` or
  \`securegit help <command>\` (works for subcommands too, e.g.
  \`securegit key rotate --help\`) gives exact flags and a runnable example
  for any of them. \`securegit help --json\` gives the same information as
  one machine-readable manifest.

## Never

- Print, log, or commit a passphrase, recovery code, or anything under
  \`~/.securegit/\`.
- Disable \`filter.securegit.required\`.
- Encrypt or decrypt a protected file by any path other than \`securegit\`'s
  own commands (\`clean\`/\`smudge\`/\`encrypt\`/\`decrypt\` — never hand-roll it).

## Full reference

\`docs/securegit/05-cli-guide.md\`, \`specs/securegit/10-cli-contract.md\`, or
\`securegit help\` / \`securegit <command> --help\` for anything not covered
above.
`;

export interface AgentTarget {
  id: string;
  /** Relative to the repository root. */
  path: string;
  render: () => string;
}

function claudeSkill(): string {
  return (
    `---\n` +
    `${YAML_MARKER}\n` +
    `name: securegit\n` +
    `description: Use when working in a repository protected by securegit — encrypting or protecting a file, running \`securegit init\`/\`protect\`/\`unlock\`/\`verify\`/\`key\`, or troubleshooting a locked or misconfigured repository.\n` +
    `---\n\n${AGENT_INSTRUCTIONS}`
  );
}

function cursorRule(): string {
  return (
    `---\n` +
    `${YAML_MARKER}\n` +
    `description: securegit workflow — protecting, unlocking, and sharing access to encrypted files in this repository\n` +
    `alwaysApply: false\n` +
    `---\n\n${AGENT_INSTRUCTIONS}`
  );
}

function copilotInstructions(): string {
  return `---\n${YAML_MARKER}\napplyTo: "**"\n---\n\n${AGENT_INSTRUCTIONS}`;
}

function kiroSteering(): string {
  return (
    `---\n` +
    `${YAML_MARKER}\n` +
    `inclusion: always\n` +
    `---\n\n${AGENT_INSTRUCTIONS}`
  );
}

/**
 * AGENTS.md, GEMINI.md and Antigravity's `.agents/rules/*.md` share the same
 * shape: plain Markdown, no frontmatter convention at all — unlike the four
 * above, a bare `# ...` marker line here isn't a comment, it's a rendered H1,
 * so these get the HTML-comment marker instead.
 */
function plainMarkdownFile(): string {
  return `${HTML_MARKER}\n\n${AGENT_INSTRUCTIONS}`;
}

export const AGENT_TARGETS: Record<string, AgentTarget> = {
  claude: { id: 'claude', path: join('.claude', 'skills', 'securegit', 'SKILL.md'), render: claudeSkill },
  cursor: { id: 'cursor', path: join('.cursor', 'rules', 'securegit.mdc'), render: cursorRule },
  copilot: {
    id: 'copilot',
    path: join('.github', 'instructions', 'securegit.instructions.md'),
    render: copilotInstructions,
  },
  kiro: { id: 'kiro', path: join('.kiro', 'steering', 'securegit.md'), render: kiroSteering },
  // OpenAI Codex CLI's own convention: a root AGENTS.md, no frontmatter.
  // Also the emerging cross-tool standard (agents.md) a growing number of
  // other agents read as a fallback — writing it benefits more than Codex.
  codex: { id: 'codex', path: 'AGENTS.md', render: plainMarkdownFile },
  // Gemini CLI's hierarchical context file, root-level, no frontmatter.
  gemini: { id: 'gemini', path: 'GEMINI.md', render: plainMarkdownFile },
  // Antigravity reads AGENTS.md too, but its more specific, splittable-by-
  // topic convention is a `.agents/rules/` folder of plain Markdown files —
  // used here instead of AGENTS.md so this target writes a distinct file
  // rather than silently duplicating `codex`'s.
  antigravity: { id: 'antigravity', path: join('.agents', 'rules', 'securegit.md'), render: plainMarkdownFile },
};

export const AGENT_TARGET_IDS = Object.keys(AGENT_TARGETS);

export interface AgentInstallOptions {
  force?: boolean;
}

export interface AgentInstallResult {
  target: string;
  path: string;
  action: 'created' | 'updated' | 'unchanged';
}

/** Only ever true for a file this command could have written itself. */
function looksManaged(content: string): boolean {
  return content.includes(MARKER);
}

export async function installAgentTargets(
  repoDir: string,
  targetIds: string[],
  opts: AgentInstallOptions = {},
): Promise<AgentInstallResult[]> {
  const ids = targetIds.length > 0 ? targetIds : AGENT_TARGET_IDS;
  const unknown = ids.filter((id) => !AGENT_TARGETS[id]);
  if (unknown.length > 0) {
    throw new AgentInstallError(
      `securegit: unknown agent target '${unknown[0]}'\n  supported: ${AGENT_TARGET_IDS.join(', ')}`,
      'unknown-target',
    );
  }

  const results: AgentInstallResult[] = [];
  for (const id of ids) {
    const target = AGENT_TARGETS[id]!;
    const fullPath = join(repoDir, target.path);
    const rendered = target.render();

    let existing: string | null = null;
    try {
      existing = await readFile(fullPath, 'utf8');
    } catch {
      existing = null;
    }

    if (existing !== null && !looksManaged(existing) && !opts.force) {
      throw new AgentInstallError(
        `securegit: refusing to overwrite ${target.path} — it was not written by this command\n` +
          `  action: remove it manually, or pass --force to overwrite it`,
        'foreign-file',
      );
    }

    if (existing === rendered) {
      results.push({ target: id, path: target.path, action: 'unchanged' });
      continue;
    }

    await mkdir(dirname(fullPath), { recursive: true });
    await writeFile(fullPath, rendered);
    results.push({ target: id, path: target.path, action: existing === null ? 'created' : 'updated' });
  }
  return results;
}

export interface AgentListEntry {
  target: string;
  path: string;
}

export function listAgentTargets(targetIds: string[] = []): AgentListEntry[] {
  const ids = targetIds.length > 0 ? targetIds : AGENT_TARGET_IDS;
  const unknown = ids.filter((id) => !AGENT_TARGETS[id]);
  if (unknown.length > 0) {
    throw new AgentInstallError(
      `securegit: unknown agent target '${unknown[0]}'\n  supported: ${AGENT_TARGET_IDS.join(', ')}`,
      'unknown-target',
    );
  }
  return ids.map((id) => ({ target: id, path: AGENT_TARGETS[id]!.path }));
}
