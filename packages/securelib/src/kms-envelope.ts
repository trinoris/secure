// kms-envelope: a deliberate escrow provider — never the sole unwrap path
// for a repository (custodial: true; enforced by addProvider()'s existing
// "every generation keeps a non-custodial path" check and the L10 verify
// finding, both already built, neither provider-specific).
//
// wrap()/unwrap() never call a cloud SDK directly — they call a small
// KmsBackend port of their own, mirroring how KeyProvider itself sits
// behind provider.ts. A real backend (AWS/GCP/Azure) is one signed HTTPS
// request each way, buildable from node:crypto + node:https alone — no
// cloud SDK dependency, keeping this file inside securelib's zero-runtime-
// dependency core rather than behind a companion package (registry.ts's
// BUILTIN map, not COMPANION_PACKAGE).
// See specs/securegit/06-key-provider-port.md's "kms-envelope" design.

import { ProviderError, type KeyProvider, type ProviderContext, type ProviderInfo, type ProviderState, type WrappedKey } from './provider.js';
import { secret, type Secret } from './crypto.js';

/**
 * The only thing a backend does: wrap and unwrap the 32-byte RMK itself,
 * authenticated against a caller-supplied context (AWS calls this an
 * "encryption context", GCP and Azure both call it AAD) so a ciphertext
 * copied into another repository's keyring, or presented under the wrong
 * generation, fails to decrypt rather than silently succeeding somewhere
 * it shouldn't. Never sees, and this interface can't be handed, any actual
 * protected file's content — that always stays local.
 */
export interface KmsBackend {
  encrypt(rmkBytes: Buffer, keyId: string, context: Record<string, string>): Promise<Buffer>;
  decrypt(wrappedRmkBytes: Buffer, keyId: string, context: Record<string, string>): Promise<Buffer>;
}

export class KmsEnvelopeProvider implements KeyProvider {
  readonly id: string;

  constructor(
    private readonly backend: KmsBackend,
    /** Which cloud's backend this is — recorded in state, not just decoration: `securegit status` names it as the escrow party. */
    private readonly backendTag: 'aws' | 'gcp' | 'azure',
    private readonly keyId: string,
    id = 'kms-envelope',
  ) {
    this.id = id;
  }

  describe(): ProviderInfo {
    return {
      id: this.id,
      label: `Cloud KMS envelope (${this.backendTag})`,
      custodial: true,
      requiresHardware: false,
    };
  }

  async available(): Promise<boolean> {
    // A real backend's network reachability isn't checked here — same
    // reasoning as PassphraseFileProvider's own available(): must not
    // prompt, must resolve promptly, and unlock is where a genuine
    // failure (unreachable, revoked key) actually surfaces.
    return true;
  }

  async init(ctx: { repoId: string; generation: number }): Promise<ProviderState> {
    void ctx;
    return { keyId: this.keyId, backend: this.backendTag };
  }

  async wrap(key: Buffer, ctx: ProviderContext): Promise<WrappedKey> {
    const { keyId, backend } = requireState(ctx.state);
    const ciphertext = await this.backend.encrypt(key, keyId, kmsContext(ctx));
    return {
      provider: this.id,
      payload: { keyId, backend, ciphertext: ciphertext.toString('hex') },
    };
  }

  async unwrap(wrapped: WrappedKey, ctx: ProviderContext): Promise<Secret> {
    const { keyId: expectedKeyId } = requireState(ctx.state);
    const { keyId, ciphertext } = wrapped.payload;
    if (keyId === undefined || ciphertext === undefined) {
      throw new ProviderError('wrapped key is missing a required field');
    }
    // The payload's own keyId is trust-but-verify, not authoritative on its
    // own: without this check, any wrapped blob the backend still holds
    // ciphertext for would unwrap successfully regardless of which key
    // *this* provider instance is actually configured to use — the same
    // "fails rather than silently succeeding somewhere it shouldn't"
    // property repoId/generation binding already gives every other
    // provider, extended to the one field genuinely unique to this one.
    if (keyId !== expectedKeyId) {
      throw new ProviderError('could not unwrap: wrapped key belongs to a different KMS key');
    }
    try {
      const rmk = await this.backend.decrypt(Buffer.from(ciphertext, 'hex'), keyId, kmsContext(ctx));
      return secret(rmk);
    } catch {
      // Deliberately opaque, same reasoning as PassphraseFileProvider's
      // own unwrap(): never reveal which part (repo binding, generation
      // binding, or a genuinely revoked/unreachable key) was wrong.
      throw new ProviderError('could not unwrap: kms backend refused, or key belongs elsewhere');
    }
  }
}

function kmsContext(ctx: ProviderContext): Record<string, string> {
  return { repoId: ctx.repoId, generation: String(ctx.generation) };
}

function requireState(state: ProviderState): { keyId: string; backend: string } {
  const { keyId, backend } = state;
  if (typeof keyId !== 'string' || typeof backend !== 'string') {
    throw new ProviderError('provider state is missing keyId/backend');
  }
  return { keyId, backend };
}
