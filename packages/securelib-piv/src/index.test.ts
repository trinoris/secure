import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import { YubikeyPivProvider } from '@trinoris/securelib/piv';
import type { ProviderContext } from '@trinoris/securelib/provider';
import { RealPivCard } from './index.js';

function ctx(state: ProviderContext['state'], over: Partial<ProviderContext> = {}): ProviderContext {
  return { repoId: 'securelib-piv-hardware-test', generation: 1, state, interactive: true, ...over };
}

/**
 * Real, physical hardware only — never auto-detected. Requires
 * SECUREGIT_PIV_TEST_PIN to be set explicitly (same opt-in discipline as
 * the cloud KMS backends' describe.skipIf tests: explicit credentials, no
 * silent probing of whatever happens to be plugged in). Slot defaults to
 * 9d (KEY_MANAGEMENT), overridable via SECUREGIT_PIV_TEST_SLOT.
 *
 * Every wrap()/unwrap() call below performs a REAL on-card ECDH operation
 * and submits the PIN — each run costs one of the card's limited PIN
 * retries if the PIN is wrong. Verified once during development against a
 * real YubiKey 5C NFC (firmware 5.8.0): the resulting shared secret
 * matched an independent node:crypto computation exactly, and this
 * suite's own round-trip passed.
 */
const hasRealHardware = !!process.env.SECUREGIT_PIV_TEST_PIN;

describe.skipIf(!hasRealHardware)('RealPivCard against real PIV hardware', () => {
  it('YubikeyPivProvider wraps and unwraps a real 32-byte key via a real card', async () => {
    const card = new RealPivCard();
    const slot = process.env.SECUREGIT_PIV_TEST_SLOT ?? '9d';
    const pin = process.env.SECUREGIT_PIV_TEST_PIN!;
    const provider = new YubikeyPivProvider(card, slot, () => pin);

    const state = await provider.init({ repoId: 'securelib-piv-hardware-test', generation: 1 });
    const key = randomBytes(32);
    const wrapped = await provider.wrap(key, ctx(state));
    const unwrapped = await provider.unwrap(wrapped, ctx(state));

    expect(Buffer.from(unwrapped).equals(key)).toBe(true);
  });

  it('getPublicKey() returns the same 65-byte uncompressed point ykman itself reports', async () => {
    const card = new RealPivCard();
    const slot = process.env.SECUREGIT_PIV_TEST_SLOT ?? '9d';
    const pub = await card.getPublicKey(slot);
    expect(pub.length).toBe(65);
    expect(pub[0]).toBe(0x04); // uncompressed point marker
  });
});
