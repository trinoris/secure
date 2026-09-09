import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, readFile, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  AgentInstallError,
  AGENT_TARGETS,
  AGENT_TARGET_IDS,
  AGENT_INSTRUCTIONS,
  MARKER,
  installAgentTargets,
  listAgentTargets,
} from './agent-install.js';
import { HELP } from './cli.js';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'securegit-agent-install-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const FRONTMATTER_TARGETS = ['claude', 'cursor', 'copilot', 'kiro'];
const PLAIN_MARKDOWN_TARGETS = ['codex', 'gemini', 'antigravity'];

describe('installAgentTargets()', () => {
  it('with no targets, writes every target\'s file', async () => {
    const results = await installAgentTargets(dir, []);
    expect(results.map((r) => r.target).sort()).toEqual([...AGENT_TARGET_IDS].sort());
    for (const id of AGENT_TARGET_IDS) {
      await expect(readFile(join(dir, AGENT_TARGETS[id]!.path), 'utf8')).resolves.toContain(MARKER);
    }
  });

  it('with one target, writes only that file', async () => {
    const results = await installAgentTargets(dir, ['claude']);
    expect(results).toEqual([{ target: 'claude', path: AGENT_TARGETS.claude!.path, action: 'created' }]);
    await expect(readFile(join(dir, AGENT_TARGETS.cursor!.path), 'utf8')).rejects.toThrow();
  });

  it('every frontmatter target has valid --- delimited YAML frontmatter around the shared body', async () => {
    await installAgentTargets(dir, FRONTMATTER_TARGETS);
    for (const id of FRONTMATTER_TARGETS) {
      const content = await readFile(join(dir, AGENT_TARGETS[id]!.path), 'utf8');
      const parts = content.split('---\n');
      // ['', frontmatter, body...] — exactly one frontmatter block, opened and closed.
      expect(parts.length).toBeGreaterThanOrEqual(3);
      expect(content).toContain(AGENT_INSTRUCTIONS.trim());
    }
  });

  it('every plain-markdown target has no frontmatter, just an HTML comment marker and the shared body', async () => {
    await installAgentTargets(dir, PLAIN_MARKDOWN_TARGETS);
    for (const id of PLAIN_MARKDOWN_TARGETS) {
      const content = await readFile(join(dir, AGENT_TARGETS[id]!.path), 'utf8');
      expect(content.startsWith('<!--')).toBe(true);
      expect(content).not.toMatch(/^---/);
      expect(content).toContain(AGENT_INSTRUCTIONS.trim());
    }
  });

  it('codex and gemini write distinct root files (AGENTS.md, GEMINI.md), not the same path', () => {
    expect(AGENT_TARGETS.codex!.path).toBe('AGENTS.md');
    expect(AGENT_TARGETS.gemini!.path).toBe('GEMINI.md');
    expect(AGENT_TARGETS.codex!.path).not.toBe(AGENT_TARGETS.gemini!.path);
  });

  it('claude target: name and description frontmatter fields are present', async () => {
    await installAgentTargets(dir, ['claude']);
    const content = await readFile(join(dir, AGENT_TARGETS.claude!.path), 'utf8');
    expect(content).toMatch(/^name: securegit$/m);
    expect(content).toMatch(/^description: .+$/m);
  });

  it('cursor target: description and alwaysApply frontmatter fields are present', async () => {
    await installAgentTargets(dir, ['cursor']);
    const content = await readFile(join(dir, AGENT_TARGETS.cursor!.path), 'utf8');
    expect(content).toMatch(/^description: .+$/m);
    expect(content).toMatch(/^alwaysApply: false$/m);
  });

  it('copilot target: applyTo frontmatter field is present', async () => {
    await installAgentTargets(dir, ['copilot']);
    const content = await readFile(join(dir, AGENT_TARGETS.copilot!.path), 'utf8');
    expect(content).toMatch(/^applyTo: "\*\*"$/m);
  });

  it('kiro target: inclusion frontmatter field is present', async () => {
    await installAgentTargets(dir, ['kiro']);
    const content = await readFile(join(dir, AGENT_TARGETS.kiro!.path), 'utf8');
    expect(content).toMatch(/^inclusion: always$/m);
  });

  it('re-running is idempotent: second run reports every target unchanged, content identical', async () => {
    await installAgentTargets(dir, []);
    const before = await Promise.all(AGENT_TARGET_IDS.map((id) => readFile(join(dir, AGENT_TARGETS[id]!.path), 'utf8')));
    const results = await installAgentTargets(dir, []);
    expect(results.every((r) => r.action === 'unchanged')).toBe(true);
    const after = await Promise.all(AGENT_TARGET_IDS.map((id) => readFile(join(dir, AGENT_TARGETS[id]!.path), 'utf8')));
    expect(after).toEqual(before);
  });

  it('refuses to overwrite a file that exists but was not written by this command', async () => {
    await mkdir(join(dir, '.cursor', 'rules'), { recursive: true });
    await writeFile(join(dir, AGENT_TARGETS.cursor!.path), 'hand-written, no marker\n');
    await expect(installAgentTargets(dir, ['cursor'])).rejects.toThrow(AgentInstallError);
    await expect(installAgentTargets(dir, ['cursor'])).rejects.toMatchObject({ kind: 'foreign-file' });
  });

  it('--force overwrites a foreign file', async () => {
    await mkdir(join(dir, '.cursor', 'rules'), { recursive: true });
    await writeFile(join(dir, AGENT_TARGETS.cursor!.path), 'hand-written, no marker\n');
    const results = await installAgentTargets(dir, ['cursor'], { force: true });
    expect(results).toEqual([{ target: 'cursor', path: AGENT_TARGETS.cursor!.path, action: 'updated' }]);
    await expect(readFile(join(dir, AGENT_TARGETS.cursor!.path), 'utf8')).resolves.toContain(MARKER);
  });

  it('an unknown target throws AgentInstallError with kind "unknown-target"', async () => {
    await expect(installAgentTargets(dir, ['bogus'])).rejects.toMatchObject({ kind: 'unknown-target' });
  });

  it('creates the containing directory for a target whose parent does not exist yet', async () => {
    await installAgentTargets(dir, ['kiro']);
    await expect(readFile(join(dir, '.kiro', 'steering', 'securegit.md'), 'utf8')).resolves.toContain(MARKER);
  });
});

describe('listAgentTargets()', () => {
  it('lists all four targets and their paths without writing anything', async () => {
    const entries = listAgentTargets();
    expect(entries.map((e) => e.target).sort()).toEqual([...AGENT_TARGET_IDS].sort());
    for (const id of AGENT_TARGET_IDS) {
      await expect(readFile(join(dir, AGENT_TARGETS[id]!.path), 'utf8')).rejects.toThrow();
    }
  });

  it('an unknown target throws AgentInstallError with kind "unknown-target"', () => {
    expect(() => listAgentTargets(['bogus'])).toThrow(AgentInstallError);
  });
});

describe('the shared instruction body', () => {
  it('names no command or flag absent from HELP in cli.ts', () => {
    // A loose but real guard against drift: every `securegit <word>` this
    // body tells an agent to run should be a word HELP actually documents.
    const commands = [...AGENT_INSTRUCTIONS.matchAll(/securegit ([a-z-]+)/g)].map((m) => m[1]!);
    // `help` itself isn't a HELP table entry — it's the mechanism that renders the table.
    const known = new Set(['help', ...Object.keys(HELP).flatMap((k) => k.split(' '))]);
    for (const word of commands) {
      expect(known.has(word), `"securegit ${word}" is not a command HELP documents`).toBe(true);
    }
  });
});
