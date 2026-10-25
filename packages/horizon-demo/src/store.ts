import { DatabaseSync } from 'node:sqlite';
import { createHash, randomBytes } from 'node:crypto';
import { Challenge, Verified, type PublicConfig, selectMethod } from './types.js';
import type { RemoteTarget } from './target.js';

export type Fault = 'none' | 'after_reservation' | 'after_target' | 'ambiguous';
type State = { policy_epoch: number; trust_epoch: number; revoked: number };
const digest = (text: string) => createHash('sha256').update(text).digest('hex');

/** Durable LOCAL sandbox. SQLite is also the simulated target; no external payment guarantee. */
export class AuthorizationStore {
  readonly db: DatabaseSync;
  constructor(path: string, readonly config: PublicConfig, private readonly clock = Date.now) {
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS state(id INTEGER PRIMARY KEY CHECK(id=1), policy_epoch INTEGER NOT NULL,
        trust_epoch INTEGER NOT NULL, revoked INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS challenges(nonce TEXT PRIMARY KEY, expected TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY, status TEXT NOT NULL, bundle_hash TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS effects(operation_id TEXT PRIMARY KEY, object_id TEXT NOT NULL, at_ms INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS dispatches(operation_id TEXT PRIMARY KEY, object_id TEXT NOT NULL, tenant TEXT NOT NULL,
        target_url TEXT NOT NULL, target_version INTEGER NOT NULL, at_ms INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS audit(sequence INTEGER PRIMARY KEY, event TEXT NOT NULL, previous_hash TEXT NOT NULL, hash TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS config_binding(id INTEGER PRIMARY KEY CHECK(id=1), hash TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS revoked_issuer_keys(public_key_hex TEXT PRIMARY KEY, at_ms INTEGER NOT NULL);`);
    // A database cannot silently acquire new trust roots, tenant or policy after restart.
    const binding = digest(JSON.stringify(config));
    this.db.prepare('INSERT OR IGNORE INTO config_binding VALUES(1,?)').run(binding);
    const stored = this.db.prepare('SELECT hash FROM config_binding WHERE id=1').get();
    if (stored?.['hash'] !== binding) { this.db.close(); throw new Error('CONFIGURATION_CHANGED'); }
    this.db.prepare('INSERT OR IGNORE INTO state VALUES(1,?,?,0)').run(config.policy.policy_epoch, config.challenge.trust_epoch);
  }

  state(): State {
    const row = this.db.prepare('SELECT policy_epoch,trust_epoch,revoked FROM state WHERE id=1').get();
    if (!row) throw new Error('STATE_UNAVAILABLE');
    return { policy_epoch: Number(row['policy_epoch']), trust_epoch: Number(row['trust_epoch']), revoked: Number(row['revoked']) };
  }

  private transaction<T>(body: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try { const result = body(); this.db.exec('COMMIT'); return result; }
    catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }

  private audit(event: Record<string, unknown>): void {
    const prior = this.db.prepare('SELECT hash FROM audit ORDER BY sequence DESC LIMIT 1').get();
    const previous = String(prior?.['hash'] ?? '0'.repeat(64));
    const serialized = JSON.stringify(event);
    this.db.prepare('INSERT INTO audit(event,previous_hash,hash) VALUES(?,?,?)').run(serialized, previous,
      digest('horizon/audit/v1\0' + previous + '\0' + serialized));
  }

  issue(): Challenge {
    return this.transaction(() => {
      const state = this.state();
      if (state.revoked) throw new Error('REVOKED');
      const count = this.db.prepare('SELECT COUNT(*) AS n FROM challenges').get();
      if (Number(count?.['n']) >= 10000) throw new Error('CAPACITY_REACHED');
      const now = this.clock();
      const template = this.config.challenge;
      const expected = Challenge.parse({ ...template, method: selectMethod(this.config.policy),
        operation_id: digest(JSON.stringify([template.tenant, template.audience, template.action, template.object_id])),
        nonce: randomBytes(32).toString('hex'), policy_epoch: state.policy_epoch, trust_epoch: state.trust_epoch,
        issued_at_ms: now, expires_at_ms: now + Math.min(30000, this.config.policy.max_challenge_ttl_ms) });
      if (this.db.prepare('SELECT id FROM operations WHERE id=?').get(expected.operation_id)) throw new Error('OPERATION_CONSUMED');
      this.db.prepare('INSERT INTO challenges(nonce,expected) VALUES(?,?)').run(expected.nonce, JSON.stringify(expected));
      this.audit({ type: 'challenge_issued', nonce: expected.nonce, at_ms: now });
      return expected;
    });
  }

  expected(nonce: string): Challenge {
    const row = this.db.prepare('SELECT expected,used FROM challenges WHERE nonce=?').get(nonce);
    if (!row || row['used'] !== 0) throw new Error('UNKNOWN_OR_USED_CHALLENGE');
    return Challenge.parse(JSON.parse(String(row['expected'])));
  }

  private current(expected: Challenge, verified: Verified): void {
    const state = this.state();
    const now = this.clock();
    if (state.revoked) throw new Error('REVOKED');
    if (state.policy_epoch !== expected.policy_epoch || state.trust_epoch !== expected.trust_epoch) throw new Error('STALE_EPOCH');
    if (now < Math.max(expected.issued_at_ms, verified.not_before_ms)
      || now >= Math.min(expected.expires_at_ms, verified.expires_at_ms)) throw new Error('EXPIRED');
    if (verified.tenant !== expected.tenant || verified.subject !== expected.subject
      || verified.object_id !== expected.object_id || verified.operation_id !== expected.operation_id
      || verified.method !== expected.method) throw new Error('VERIFIED_STATEMENT_MISMATCH');
  }

  /** First transaction: consume the nonce and reserve the business operation, or throw without any change. */
  private reserve(expected: Challenge, verified: Verified, dispatch?: { target_url: string; target_version: number }): void {
    this.transaction(() => {
      const stored = this.expected(expected.nonce);
      if (JSON.stringify(stored) !== JSON.stringify(expected)) throw new Error('CHALLENGE_CHANGED');
      this.current(expected, verified);
      if (this.db.prepare('SELECT id FROM operations WHERE id=?').get(expected.operation_id)) throw new Error('OPERATION_CONSUMED');
      this.db.prepare('UPDATE challenges SET used=1 WHERE nonce=? AND used=0').run(expected.nonce);
      this.db.prepare("INSERT INTO operations VALUES(?,'RESERVED',?)").run(expected.operation_id, verified.bundle_hash);
      if (dispatch) this.db.prepare('INSERT INTO dispatches VALUES(?,?,?,?,?,?)')
        .run(expected.operation_id, expected.object_id, expected.tenant, dispatch.target_url, dispatch.target_version, this.clock());
      this.audit({ type: 'reserved', operation_id: expected.operation_id, bundle_hash: verified.bundle_hash,
        ...(dispatch ? { target_url: dispatch.target_url, target_version: dispatch.target_version } : {}), at_ms: this.clock() });
    });
  }

  /** Second transaction of a remote dispatch. If reconciliation resolved the operation while the
   * single attempt was in flight, the stored terminal state wins and the attempt's answer is audited. */
  private settle(operationId: string, status: 'COMPLETED' | 'REJECTED' | 'UNKNOWN', event: Record<string, unknown>): { status: string; operation_id: string } {
    return this.transaction(() => {
      const operation = this.db.prepare('SELECT status FROM operations WHERE id=?').get(operationId);
      const stored = String(operation?.['status'] ?? '');
      if (!operation) throw new Error('UNKNOWN_OPERATION');
      if (stored !== 'RESERVED') {
        this.audit({ type: 'settled_after_reconciliation', operation_id: operationId, attempt: status.toLowerCase(), stored, ...event, at_ms: this.clock() });
        return { status: stored, operation_id: operationId };
      }
      this.db.prepare('UPDATE operations SET status=? WHERE id=?').run(status, operationId);
      this.audit({ type: status.toLowerCase(), operation_id: operationId, ...event, at_ms: this.clock() });
      return { status, operation_id: operationId };
    });
  }

  /**
   * H14: durable dispatch to a SEPARATE target process. The object version is read before
   * reservation and stored with it; the deadline is rechecked after reservation with no await
   * before the single network attempt; every transport ambiguity stays UNKNOWN until
   * `reconcileWith` fences the operation at the target. Never retries the mutation.
   */
  async dispatch(expected: Challenge, result: unknown, target: RemoteTarget, fault: Fault = 'none'): Promise<{ status: string; operation_id: string }> {
    const verified = Verified.parse(result);
    const targetVersion = await target.version(expected.object_id);
    if (targetVersion === undefined) throw new Error('TARGET_UNAVAILABLE'); // nothing consumed yet
    this.reserve(expected, verified, { target_url: target.url, target_version: targetVersion });
    if (fault === 'after_reservation') throw new Error('CRASH_AFTER_RESERVATION');
    try { this.current(expected, verified); }
    catch { return this.settle(expected.operation_id, 'REJECTED', { reason: 'stale_before_dispatch' }); }
    const outcome = await target.record(expected.operation_id, { object_id: expected.object_id, tenant: expected.tenant,
      bundle_hash: verified.bundle_hash, expires_at_ms: Math.min(expected.expires_at_ms, verified.expires_at_ms) }, targetVersion);
    if (fault === 'after_target') throw new Error('CRASH_AFTER_TARGET');
    if (fault === 'ambiguous') return this.settle(expected.operation_id, 'UNKNOWN', { reason: 'acknowledgement_discarded' });
    switch (outcome.outcome) {
      case 'recorded': case 'replayed': return this.settle(expected.operation_id, 'COMPLETED', { target: outcome.outcome, version: outcome.version });
      case 'conflict': case 'stale': case 'expired': case 'fenced': return this.settle(expected.operation_id, 'REJECTED', { target: outcome.outcome });
      default: return this.settle(expected.operation_id, 'UNKNOWN', { target: outcome.outcome, reason: outcome.reason });
    }
  }

  /** Reconciliation with the remote target the operation was dispatched to: observe or fence, never redispatch.
   * Terminal states are never rewritten; a reservation dispatched to another target is refused. */
  async reconcileWith(target: RemoteTarget, operationId: string): Promise<string> {
    const operation = this.db.prepare('SELECT status,bundle_hash FROM operations WHERE id=?').get(operationId);
    if (!operation) throw new Error('UNKNOWN_OPERATION');
    const dispatch = this.db.prepare('SELECT target_url FROM dispatches WHERE operation_id=?').get(operationId);
    if (!dispatch) throw new Error('LOCAL_OPERATION');
    if (dispatch['target_url'] !== target.url) throw new Error('TARGET_MISMATCH');
    const status = String(operation['status']);
    if (status === 'COMPLETED' || status === 'REJECTED') return status;
    const answer = await target.fence(operationId);
    const resolved = answer.outcome === 'recorded' ? (answer.bundle_hash === operation['bundle_hash'] ? 'COMPLETED' : 'REJECTED')
      : answer.outcome === 'fenced' ? 'REJECTED' : 'UNKNOWN';
    return this.transaction(() => {
      const again = String(this.db.prepare('SELECT status FROM operations WHERE id=?').get(operationId)?.['status']);
      if (again === 'COMPLETED' || again === 'REJECTED') {
        // The in-flight attempt settled first; its state is authoritative and already audited.
        this.audit({ type: 'reconciliation_superseded', operation_id: operationId, observed: answer.outcome, stored: again, at_ms: this.clock() });
        return again;
      }
      this.db.prepare('UPDATE operations SET status=? WHERE id=?').run(resolved, operationId);
      this.audit({ type: 'reconciled', operation_id: operationId, status: resolved, target: answer.outcome, at_ms: this.clock() });
      return resolved;
    });
  }

  /** Caller must obtain Verified from the independent cryptographic worker, never from HTTP input. */
  authorize(expected: Challenge, result: unknown, fault: Fault = 'none'): { status: string; operation_id: string } {
    const verified = Verified.parse(result);
    this.reserve(expected, verified);
    if (fault === 'after_reservation') throw new Error('CRASH_AFTER_RESERVATION');
    // No await between reservation and target transaction; recheck even across these transactions.
    return this.transaction(() => {
      const operation = this.db.prepare('SELECT status FROM operations WHERE id=?').get(expected.operation_id);
      if (operation?.['status'] !== 'RESERVED') throw new Error('OPERATION_CONSUMED');
      try { this.current(expected, verified); }
      catch {
        this.db.prepare("UPDATE operations SET status='REJECTED' WHERE id=?").run(expected.operation_id);
        this.audit({ type: 'rejected_after_reservation', operation_id: expected.operation_id, at_ms: this.clock() });
        return { status: 'REJECTED', operation_id: expected.operation_id };
      }
      this.db.prepare('INSERT INTO effects VALUES(?,?,?)').run(expected.operation_id, expected.object_id, this.clock());
      const status = fault === 'ambiguous' ? 'UNKNOWN' : 'COMPLETED';
      this.db.prepare('UPDATE operations SET status=? WHERE id=?').run(status, expected.operation_id);
      this.audit({ type: status.toLowerCase(), operation_id: expected.operation_id, at_ms: this.clock() });
      return { status, operation_id: expected.operation_id };
    });
  }

  /** Trusted sandbox operator only. Revocation is one-way; no reset/unrevoke endpoint. */
  revoke(): void { this.transaction(() => { this.db.exec('UPDATE state SET revoked=1,trust_epoch=trust_epoch+1 WHERE id=1');
    this.audit({ type: 'revoked', at_ms: this.clock() }); }); }
  rotatePolicy(): void { this.transaction(() => { this.db.exec('UPDATE state SET policy_epoch=policy_epoch+1 WHERE id=1');
    this.audit({ type: 'policy_rotated', at_ms: this.clock() }); }); }
  /** H13: withdraw one issuer key (one-way). The trust epoch moves so that every outstanding challenge is stale;
   * the key is added to the registry list the verifier receives, so attestations under it are refused even
   * under new challenges. Unlike revoke(), issuance continues for attestations under the other keys. */
  revokeIssuerKey(publicKeyHex: string): void {
    const key = String(publicKeyHex);
    if (!/^[0-9a-f]{64}$/.test(key)) throw new Error('INVALID_KEY');
    this.transaction(() => {
      this.db.prepare('INSERT OR IGNORE INTO revoked_issuer_keys VALUES(?,?)').run(key, this.clock());
      this.db.exec('UPDATE state SET trust_epoch=trust_epoch+1 WHERE id=1');
      this.audit({ type: 'issuer_key_revoked', public_key_hex: key, at_ms: this.clock() });
    });
  }
  revokedIssuerKeys(): string[] {
    return this.db.prepare('SELECT public_key_hex FROM revoked_issuer_keys ORDER BY public_key_hex').all().map(row => String(row['public_key_hex']));
  }
  /** Local target only: terminal states are never rewritten and remotely dispatched operations are refused. */
  reconcile(operationId: string): string {
    return this.transaction(() => {
      const operation = this.db.prepare('SELECT status FROM operations WHERE id=?').get(operationId);
      if (!operation) throw new Error('UNKNOWN_OPERATION');
      if (this.db.prepare('SELECT operation_id FROM dispatches WHERE operation_id=?').get(operationId)) throw new Error('REMOTE_OPERATION');
      const stored = String(operation['status']);
      if (stored === 'COMPLETED' || stored === 'REJECTED') return stored;
      const status = this.db.prepare('SELECT operation_id FROM effects WHERE operation_id=?').get(operationId) ? 'COMPLETED' : 'UNKNOWN';
      this.db.prepare('UPDATE operations SET status=? WHERE id=?').run(status, operationId);
      this.audit({ type: 'reconciled', operation_id: operationId, status, at_ms: this.clock() });
      return status;
    });
  }
  snapshot(): Record<string, unknown> {
    // Operation rows omit bundle_hash: with an unauthenticated target, a leaked hash lets a third party
    // record "our" bundle. The audit chain still carries it (sandbox operator view, see REMOTE_TARGET doc).
    return { state: this.state(), effects: this.db.prepare('SELECT * FROM effects').all(),
      operations: this.db.prepare('SELECT id,status FROM operations').all(), audit: this.db.prepare('SELECT * FROM audit ORDER BY sequence').all() };
  }
  close(): void { this.db.close(); }
}
