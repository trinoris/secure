import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import { YubikeyFido2Provider } from '@trinoris/securelib/fido2';
import type { ProviderContext } from '@trinoris/securelib/provider';
import { RealFido2Authenticator } from './index.js';

function ctx(state: ProviderContext['state'], over: Partial<ProviderContext> = {}): ProviderContext {
  return { repoId: 'securelib-fido2-hardware-test', generation: 1, state, interactive: true, ...over };
}

/**
 * Real, physical hardware only — never auto-detected. Requires
 * SECUREGIT_FIDO2_HARDWARE_TEST=1 to be set explicitly (same opt-in
 * discipline as every other hardware/cloud describe.skipIf suite in this
 * project). Unlike PIV, FIDO2's touch requirement can't be disabled the
 * way PIV's touch-policy could — every real invocation here needs a
 * genuine physical touch, so this test can only be run by a human present
 * to react to it, via `!` in an interactive terminal, never by an agent's
 * own non-interactive tool calls (there's no way to "watch" a touch
 * prompt and react to it from inside a sandboxed command execution).
 *
 * The underlying MakeCredential/GetAssertion behaviour was manually
 * verified against a real YubiKey 5C NFC (firmware 5.8.0) during
 * development, one command at a time: no PIN needed (this key's "Always
 * Require User Verification" is off), the same credential+salt produced
 * the byte-identical hmac secret across two calls with different
 * challenges, and a different salt produced a different secret. This
 * suite exercises the same real hardware through the actual
 * YubikeyFido2Provider/RealFido2Authenticator code path, not a
 * hand-verified CLI invocation.
 */
const hasRealHardware = process.env.SECUREGIT_FIDO2_HARDWARE_TEST === '1';

describe.skipIf(!hasRealHardware)('RealFido2Authenticator against real FIDO2 hardware', () => {
  it('YubikeyFido2Provider wraps and unwraps a real 32-byte key via a real authenticator (needs two touches)', async () => {
    const authenticator = new RealFido2Authenticator();
    const provider = new YubikeyFido2Provider(authenticator);

    const state = await provider.init({ repoId: 'securelib-fido2-hardware-test', generation: 1 });
    const key = randomBytes(32);
    const wrapped = await provider.wrap(key, ctx(state));
    const unwrapped = await provider.unwrap(wrapped, ctx(state));

    expect(Buffer.from(unwrapped).equals(key)).toBe(true);
  });
});
