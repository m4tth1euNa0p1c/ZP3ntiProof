import { isDeepStrictEqual } from 'node:util';
import { z } from 'zod';
import { defineVerifiedTool } from '@m4tth1euna0p1c/proofkit-sdk';
import type { AuthorizationStore } from './store.js';
import type { ProofWorker } from './worker.js';
import type { RemoteTarget } from './target.js';
import { Challenge, Verified, type PublicConfig } from './types.js';

/** Reference adapter: real cryptography; the target is the store's synthetic SQLite action, or the
 * separate H14 sandbox target when one is configured (the controller then never records locally). */
export function createClaimTool(store: AuthorizationStore, worker: ProofWorker, config: PublicConfig, clock = Date.now, target?: RemoteTarget) {
  return defineVerifiedTool({
    name: 'record_claim_authorization', profile: 'horizon-range-v1',
    evidenceKind: config.policy.require_private ? 'zk' : 'signed-attestation', environment: 'sandbox',
    input: z.strictObject({}), challenge: Challenge, verified: Verified, clock,
    maxChallengeTtlMs: Math.min(30000, config.policy.max_challenge_ttl_ms),
    authority: {
      issue: () => store.issue(),
      expected: nonce => store.expected(nonce),
      verify: async (presentation, expected) => {
        const state = store.state();
        if (state.revoked) throw new Error('REVOKED');
        if (!isDeepStrictEqual(presentation['evidence'], config.evidence)) throw new Error('EVIDENCE_SUBSTITUTION');
        // The registry the verifier receives is the configured one plus the controller's own revocations (H13).
        const configured = Array.isArray(config.trust['revoked_public_keys_hex']) ? config.trust['revoked_public_keys_hex'] as unknown[] : [];
        const revokedKeys = [...new Set([...configured.map(String), ...store.revokedIssuerKeys()])].sort();
        return worker.request({ op: 'verify', presentation, expected,
          trust: { ...config.trust, epoch: state.trust_epoch, ...(revokedKeys.length ? { revoked_public_keys_hex: revokedKeys } : {}) },
          policy: { ...config.policy, policy_epoch: state.policy_epoch }, now_ms: clock() });
      },
      // Store rechecks time/epochs and consumes nonce + business operation under its own transaction.
      authorize: (expected, verified) => target ? store.dispatch(expected, verified, target) : store.authorize(expected, verified),
    },
  });
}
