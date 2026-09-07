// Cross-package integration: does @trinoris/securelib's KeySource contract
// (produced by unlockKeyring()/keySourceFromSessionKey()) actually satisfy
// what this package's own filter.ts (clean/smudge) needs in practice, not
// just structurally? Lives here, not in securelib, because it's this
// package's contract being exercised — securelib has no reason to depend
// on securegit to test its own keyring/session in isolation.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassphraseFileProvider, type KeyProvider } from '@trinoris/securelib/provider';
import { createKeyring, rotateKeyring, unlockKeyring } from '@trinoris/securelib/keyring';
import {
  writeSession,
  readSession,
  type SessionEntry,
} from '@trinoris/securelib/session';
import { clean, smudge, LockedError } from './filter.js';

const FAST_COST = { N: 2 ** 10, r: 8, p: 1 };
const REPO = 'repo-a';
const PASSPHRASE = 'correct horse battery staple';

function passphraseProvider(pass = PASSPHRASE): KeyProvider {
  return new PassphraseFileProvider(() => pass, FAST_COST);
}

describe('bridges to keyring.ts\'s KeySource contract', () => {
  it('clean/smudge round-trip through a real unlocked keyring', async () => {
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    const keys = await unlockKeyring(file, [passphraseProvider()]);
    const pt = Buffer.from('{"timeout":30}\n');
    const path = 'config/production.json';
    const out = clean(pt, { keys, path });
    expect(smudge(out, { keys, path }).equals(pt)).toBe(true);
  });

  it('clean fails closed against a locked keyring', async () => {
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    const keys = await unlockKeyring(file, [passphraseProvider('wrong wrong wrong wrong')]);
    expect(() => clean(Buffer.from('x'), { keys, path: 'a.env' })).toThrow(LockedError);
  });

  it('smudge fails open against a locked keyring, decrypting nothing', async () => {
    const { file } = await createKeyring(REPO, [passphraseProvider()]);
    const unlocked = await unlockKeyring(file, [passphraseProvider()]);
    const envelope = clean(Buffer.from('secret'), { keys: unlocked, path: 'a.env' });

    const locked = await unlockKeyring(file, [passphraseProvider('wrong wrong wrong wrong')]);
    const warn = vi.fn();
    expect(smudge(envelope, { keys: locked, path: 'a.env', warn }).equals(envelope)).toBe(true);
    expect(warn).toHaveBeenCalled();
  });

  it('an old envelope survives two rotations', async () => {
    const gen1 = await createKeyring(REPO, [passphraseProvider()]);
    const path = 'config/production.json';
    const keys1 = await unlockKeyring(gen1.file, [passphraseProvider()]);
    const envelope = clean(Buffer.from('original secret'), { keys: keys1, path });

    const gen2 = await rotateKeyring(gen1.file, [passphraseProvider()]);
    const gen3 = await rotateKeyring(gen2.file, [passphraseProvider()]);
    const keysFinal = await unlockKeyring(gen3.file, [passphraseProvider()]);

    expect(smudge(envelope, { keys: keysFinal, path }).equals(Buffer.from('original secret'))).toBe(true);
  });
});

describe('bridges to session.ts\'s KeySource contract', () => {
  const SESSION_REPO = 'repo-a';
  const KEY_ID = '3.a1b2c3d4e5f60718';
  const RMK = Buffer.alloc(32, 0xa5);
  const ENTRIES: SessionEntry[] = [{ keyId: KEY_ID, rmk: RMK }];

  let dir: string;
  let sessionPath: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'securegit-session-bridge-'));
    sessionPath = join(dir, 'nested', `${SESSION_REPO}.session`);
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('clean/smudge round-trip through a real session', async () => {
    await writeSession({ repoId: SESSION_REPO, path: sessionPath, entries: ENTRIES, current: KEY_ID });
    const keys = await readSession({ repoId: SESSION_REPO, path: sessionPath });
    const pt = Buffer.from('{"timeout":30}\n');
    const path = 'config/production.json';
    const out = clean(pt, { keys, path });
    expect(smudge(out, { keys, path }).equals(pt)).toBe(true);
  });

  it('clean fails closed once the session has expired', async () => {
    const base = new Date('2026-09-01T10:00:00.000Z');
    await writeSession({
      repoId: SESSION_REPO, path: sessionPath, entries: ENTRIES, current: KEY_ID,
      ttlSeconds: 60, now: () => base,
    });
    const later = new Date(base.getTime() + 3600 * 1000);
    const keys = await readSession({ repoId: SESSION_REPO, path: sessionPath, now: () => later });
    expect(() => clean(Buffer.from('x'), { keys, path: 'a.env' })).toThrow(LockedError);
  });
});
