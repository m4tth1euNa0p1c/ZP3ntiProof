// H13: two separate synthetic authorities issue from real-format sources; every invalid input is
// refused before issuance or before any effect, and the counters prove it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { z } from 'zod';
import { ProofWorker } from '../../packages/horizon-demo/src/worker.js';
import { AuthorizationStore } from '../../packages/horizon-demo/src/store.js';
import { createClaimTool } from '../../packages/horizon-demo/src/tool.js';
import { PublicConfig, Verified, type Challenge } from '../../packages/horizon-demo/src/types.js';
import { DelegationLedgerIssuer, ExpertReportIssuer, IssuerError, LEDGER_DOMAIN, issuanceRequestBytes, publishRegistry, revokeIssuerKey,
  type IssuanceRequest, type IssuerKeys, type TrustRegistry } from '../../packages/horizon-demo/src/issuers.js';
import { createSandboxTarget, RemoteTarget } from '../../packages/horizon-demo/src/target.js';
import { createPrivateKey } from 'node:crypto';

const Record = z.record(z.string(), z.unknown());
const Fixture = PublicConfig.extend({ witness: Record, holder_secret_hex: z.string() });
const now = 1800000000000;
const binary = process.env['HORIZON_WORKER'] ?? resolve('labs/horizon/target/release',
  process.platform === 'win32' ? 'horizon-proof-worker.exe' : 'horizon-proof-worker');

function keypair(): { publicKeyHex: string; secretHex: string; key: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { publicKeyHex: publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'),
    secretHex: privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32).toString('hex'), key: privateKey };
}
const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
function jws(key: KeyObject, kid: string, payload: unknown, header: Record<string, unknown> = { alg: 'EdDSA', typ: 'horizon-expert-report+json', kid }): string {
  const signingInput = `${b64(header)}.${b64(payload)}`;
  return `${signingInput}.${sign(null, Buffer.from(signingInput, 'ascii'), key).toString('base64url')}`;
}
function ledgerLine(key: KeyObject, columns: (string | number)[]): { line: string; signature_hex: string } {
  const line = columns.join(',');
  return { line, signature_hex: sign(null, Buffer.from(LEDGER_DOMAIN + line, 'utf8'), key).toString('hex') };
}
function rawVerify(presentation: unknown, expected: Challenge, trust: unknown, policy: unknown): { ok: boolean; error: string } {
  const result = spawnSync(binary, [], { encoding: 'utf8', windowsHide: true,
    input: JSON.stringify({ op: 'verify', presentation, expected, trust, policy, now_ms: now }) + '\n' });
  const parsed = z.object({ ok: z.boolean(), error: z.string().optional() }).parse(JSON.parse(result.stdout.trim()));
  return { ok: parsed.ok, error: parsed.error ?? '' };
}
const refused = (code: string) => (error: unknown) => error instanceof IssuerError && error.code === code;

async function world() {
  const worker = new ProofWorker();
  let issuances = 0;
  const original = worker.request.bind(worker);
  worker.request = (payload: unknown) => { if (Record.parse(payload)['op'] === 'issue') issuances++; return original(payload); };
  const lab = Fixture.parse(await worker.request({ op: 'init', now_ms: now })); // holder key, challenge template and policy only
  const expertSystem = keypair(); const expertAuthority = keypair(); const ledgerSystem = keypair(); const delegationAuthority = keypair();
  const expertKeys: IssuerKeys = { issuer: 'expert', public_key_hex: expertAuthority.publicKeyHex, signing_secret_hex: expertAuthority.secretHex };
  const delegationKeys: IssuerKeys = { issuer: 'delegation', public_key_hex: delegationAuthority.publicKeyHex, signing_secret_hex: delegationAuthority.secretHex };
  const expert = new ExpertReportIssuer(worker, expertKeys, new Map([['assessment-system-7', expertSystem.publicKeyHex]]));
  const delegation = new DelegationLedgerIssuer(worker, delegationKeys, ledgerSystem.publicKeyHex);
  const holderPublic = z.string().parse(Record.parse(Record.parse(lab.evidence['amount'])['body'])['holder_public_key_hex']);
  const holderKey = createPrivateKey({ format: 'der', type: 'pkcs8',
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(lab.holder_secret_hex, 'hex')]) });
  /** Holder-side proof of possession over the canonical request bytes. */
  const signRequest = (fields: Omit<IssuanceRequest, 'request_signature_hex'>, key: KeyObject = holderKey): IssuanceRequest =>
    ({ ...fields, request_signature_hex: sign(null, issuanceRequestBytes(fields), key).toString('hex') });
  const request: IssuanceRequest = signRequest({ tenant: 'horizon-demo', subject: 'claim-001', holder_public_key_hex: holderPublic,
    valid_from_ms: now, valid_until_ms: now + 3_600_000 });
  const report = { case_id: 'claim-001', tenant: 'horizon-demo', assessed_amount_cents: 125000, currency: 'EUR', assessed_at_ms: now - 60_000, expert_system: 'assessment-system-7' };
  const validReport = jws(expertSystem.key, 'assessment-system-7', report);
  const validLine = ledgerLine(ledgerSystem.key, ['claim-001', 'horizon-demo', 250000, now - 86_400_000, now + 86_400_000, 'approver-12']);
  const trust = publishRegistry(1, expertKeys, delegationKeys);
  const directory = mkdtempSync(join(tmpdir(), 'horizon-h13-'));
  return { worker, lab, expert, delegation, expertSystem, ledgerSystem, expertKeys, delegationKeys, request, report, validReport, validLine, trust, directory,
    signRequest, holderKey, issuances: () => issuances, close: () => worker.close() };
}

/** Holder side: assemble the pair, keep the openings private, prove against a challenge. */
async function assemble(w: Awaited<ReturnType<typeof world>>, trust: TrustRegistry = w.trust) {
  const amount = await w.expert.issue(w.validReport, w.request);
  const cap = await w.delegation.issue(w.validLine, w.request);
  const evidence = { amount: amount.evidence, cap: cap.evidence };
  const witness = { amount: amount.opening.value, cap: cap.opening.value, amount_blinding_hex: amount.opening.blinding_hex, cap_blinding_hex: cap.opening.blinding_hex };
  const config = PublicConfig.parse({ trust, evidence, challenge: w.lab.challenge, policy: w.lab.policy });
  const prove = async (challenge: Challenge) => Record.parse(await w.worker.request({ op: 'prove', evidence, witness, holder_secret_hex: w.lab.holder_secret_hex, challenge }));
  return { evidence, witness, config, prove };
}
const effects = (store: AuthorizationStore) => Number(store.db.prepare('SELECT count(*) AS n FROM effects').get()?.['n']);

test('two authorities issue from a JWS report and a signed ledger line; the holder proves; the controller admits once', async () => {
  const w = await world();
  try {
    const h = await assemble(w);
    assert.equal(w.issuances(), 2);
    assert.equal(JSON.stringify(h.config).includes('blinding'), false);
    assert.equal(JSON.stringify(h.config).includes('125000'), false); // the amount stays with the holder
    const store = new AuthorizationStore(join(w.directory, 'nominal.sqlite'), h.config, () => now);
    try {
      const tool = createClaimTool(store, w.worker, h.config, () => now);
      const challenge = await tool.issue({}); assert.equal(challenge.method, 'reusable');
      // A challenge-bound proof is refused under a reusable policy; the holder follows the verifier's selection.
      const prepared = await w.worker.request({ op: 'prepare', evidence: h.evidence, witness: h.witness });
      const presentation = await w.worker.request({ op: 'present', evidence: h.evidence, prepared, holder_secret_hex: w.lab.holder_secret_hex, challenge });
      assert.equal(Record.parse(await tool.execute({ nonce: challenge.nonce, presentation }))['status'], 'COMPLETED');
      assert.equal(effects(store), 1);
      await assert.rejects(tool.execute({ nonce: challenge.nonce, presentation }));
      assert.equal(effects(store), 1);
    } finally { store.close(); }
  } finally { w.close(); }
});

test('expert adapter refuses substituted signers, broken signatures, wrong algorithms, other cases and out-of-domain reports without issuing', async () => {
  const w = await world();
  try {
    const intruder = keypair();
    const cases: [string, string, string][] = [
      ['unregistered signer', jws(intruder.key, 'assessment-system-7', w.report), 'REPORT_SIGNATURE'],
      ['unknown kid', jws(w.expertSystem.key, 'assessment-system-8', w.report), 'UNKNOWN_REPORT_SIGNER'],
      ['alg none', jws(w.expertSystem.key, 'assessment-system-7', w.report, { alg: 'none', typ: 'horizon-expert-report+json', kid: 'assessment-system-7' }), 'JWS_HEADER'],
      ['alg ES256', jws(w.expertSystem.key, 'assessment-system-7', w.report, { alg: 'ES256', typ: 'horizon-expert-report+json', kid: 'assessment-system-7' }), 'JWS_HEADER'],
      ['other typ', jws(w.expertSystem.key, 'assessment-system-7', w.report, { alg: 'EdDSA', typ: 'JWT', kid: 'assessment-system-7' }), 'JWS_HEADER'],
      ['extra header field', jws(w.expertSystem.key, 'assessment-system-7', w.report, { alg: 'EdDSA', typ: 'horizon-expert-report+json', kid: 'assessment-system-7', crit: ['x'] }), 'JWS_HEADER'],
      ['two parts', w.validReport.split('.').slice(0, 2).join('.'), 'JWS_FORMAT'],
      ['empty signature', w.validReport.replace(/\.[^.]+$/, '.'), 'JWS_FORMAT'],
      ['non base64url', w.validReport.replace(/\.[^.]+$/, '.not+valid/'), 'JWS_ENCODING'],
      ['tampered payload', (() => { const [h, , s] = w.validReport.split('.'); return `${h}.${b64({ ...w.report, assessed_amount_cents: 1 })}.${s}`; })(), 'REPORT_SIGNATURE'],
      ['other case', jws(w.expertSystem.key, 'assessment-system-7', { ...w.report, case_id: 'claim-002' }), 'CASE_MISMATCH'],
      ['other tenant', jws(w.expertSystem.key, 'assessment-system-7', { ...w.report, tenant: 'other-tenant' }), 'TENANT_MISMATCH'],
      ['assessed after validity start', jws(w.expertSystem.key, 'assessment-system-7', { ...w.report, assessed_at_ms: now + 1 }), 'ASSESSMENT_AFTER_VALIDITY'],
      ['USD', jws(w.expertSystem.key, 'assessment-system-7', { ...w.report, currency: 'USD' }), 'REPORT_SCHEMA'],
      ['zero amount', jws(w.expertSystem.key, 'assessment-system-7', { ...w.report, assessed_amount_cents: 0 }), 'REPORT_SCHEMA'],
      ['amount above 2^32', jws(w.expertSystem.key, 'assessment-system-7', { ...w.report, assessed_amount_cents: 2 ** 32 + 1 }), 'REPORT_SCHEMA'],
      ['fractional cents', jws(w.expertSystem.key, 'assessment-system-7', { ...w.report, assessed_amount_cents: 1250.5 }), 'REPORT_SCHEMA'],
      ['negative', jws(w.expertSystem.key, 'assessment-system-7', { ...w.report, assessed_amount_cents: -1 }), 'REPORT_SCHEMA'],
      ['string amount', jws(w.expertSystem.key, 'assessment-system-7', { ...w.report, assessed_amount_cents: '125000' }), 'REPORT_SCHEMA'],
      ['missing field', jws(w.expertSystem.key, 'assessment-system-7', (({ expert_system: _omitted, ...rest }) => rest)(w.report)), 'REPORT_SCHEMA'],
      ['extra field', jws(w.expertSystem.key, 'assessment-system-7', { ...w.report, approved: true }), 'REPORT_SCHEMA'],
      ['ledger line fed to the expert adapter', w.validLine.line, 'JWS_FORMAT'],
    ];
    cases.push(['assessment system differs from kid', jws(w.expertSystem.key, 'assessment-system-7', { ...w.report, expert_system: 'assessment-system-8' }), 'REPORT_SIGNER_MISMATCH']);
    for (const [name, document, code] of cases) await assert.rejects(w.expert.issue(document, w.request), refused(code), name);
    assert.equal(w.issuances(), 0);
    // The request: ordered window, bounded validity, and proof of possession of the named holder key.
    await assert.rejects(w.expert.issue(w.validReport, w.signRequest({ ...w.request, valid_until_ms: w.request.valid_from_ms })), refused('VALIDITY_WINDOW'));
    await assert.rejects(w.expert.issue(w.validReport, w.signRequest({ ...w.request, valid_until_ms: w.report.assessed_at_ms + 31 * 86_400_000 })), refused('VALIDITY_TOO_LONG'));
    await assert.rejects(w.expert.issue(w.validReport, { ...w.request, valid_until_ms: w.request.valid_until_ms - 1 }), refused('REQUEST_SIGNATURE')); // signed fields altered
    const stranger = keypair();
    await assert.rejects(w.expert.issue(w.validReport, w.signRequest({ ...w.request, holder_public_key_hex: stranger.publicKeyHex })), refused('REQUEST_SIGNATURE')); // names a key the requester does not hold
    assert.equal(w.issuances(), 0);
    // Residual by design (documented): whoever holds the signed report and a key of their own obtains ONE attestation to that key...
    assert.ok(await w.expert.issue(w.validReport, w.signRequest({ ...w.request, holder_public_key_hex: stranger.publicKeyHex }, stranger.key)));
    assert.equal(w.issuances(), 1);
    // ... and the report is then spent: the legitimate holder's request with the same report is refused.
    await assert.rejects(w.expert.issue(w.validReport, w.request), refused('SOURCE_ALREADY_USED'));
    assert.equal(w.issuances(), 1);
    // A fresh report issues again for the legitimate holder.
    const fresh = jws(w.expertSystem.key, 'assessment-system-7', { ...w.report, assessed_at_ms: w.report.assessed_at_ms + 1 });
    assert.ok(await w.expert.issue(fresh, w.request));
    assert.equal(w.issuances(), 2);
    // An authority cannot register itself as a source signer.
    assert.throws(() => new ExpertReportIssuer(w.worker, w.expertKeys, new Map([['self', w.expertKeys.public_key_hex]])), refused('SOURCE_KEY_IS_AUTHORITY_KEY'));
  } finally { w.close(); }
});

test('delegation adapter refuses malformed lines, wrong signatures, uncovered windows, other cases and out-of-domain caps without issuing', async () => {
  const w = await world();
  try {
    const sign = (columns: (string | number)[]) => ledgerLine(w.ledgerSystem.key, columns);
    const intruder = keypair();
    const cases: [string, { line: string; signature_hex: string }, string][] = [
      ['five columns', sign(['claim-001', 'horizon-demo', 250000, now - 1000, now + 86_400_000]), 'LEDGER_COLUMNS'],
      ['seven columns', sign(['claim-001', 'horizon-demo', 250000, now - 1000, now + 86_400_000, 'approver-12', 'extra']), 'LEDGER_COLUMNS'],
      ['quoted field', sign(['"claim-001"', 'horizon-demo', 250000, now - 1000, now + 86_400_000, 'approver-12']), 'LEDGER_FORMAT'],
      ['trailing newline', { ...w.validLine, line: w.validLine.line + '\n' }, 'LEDGER_FORMAT'],
      ['other ledger key', ledgerLine(intruder.key, ['claim-001', 'horizon-demo', 250000, now - 1000, now + 86_400_000, 'approver-12']), 'LEDGER_SIGNATURE'],
      ['tampered cap', { ...w.validLine, line: w.validLine.line.replace('250000', '250001') }, 'LEDGER_SIGNATURE'],
      ['cap zero', sign(['claim-001', 'horizon-demo', 0, now - 1000, now + 86_400_000, 'approver-12']), 'LEDGER_SCHEMA'],
      ['cap 2^33', sign(['claim-001', 'horizon-demo', 2 ** 33, now - 1000, now + 86_400_000, 'approver-12']), 'LEDGER_SCHEMA'],
      ['cap with sign', sign(['claim-001', 'horizon-demo', '+250000', now - 1000, now + 86_400_000, 'approver-12']), 'LEDGER_FIELD_CAP_CENTS'],
      ['cap decimal', sign(['claim-001', 'horizon-demo', '2500.00', now - 1000, now + 86_400_000, 'approver-12']), 'LEDGER_FIELD_CAP_CENTS'],
      ['leading zero timestamp', sign(['claim-001', 'horizon-demo', 250000, '0' + String(now - 1000), now + 86_400_000, 'approver-12']), 'LEDGER_FIELD_VALID_FROM_MS'],
      ['other case', sign(['claim-002', 'horizon-demo', 250000, now - 1000, now + 86_400_000, 'approver-12']), 'CASE_MISMATCH'],
      ['other tenant', sign(['claim-001', 'other-tenant', 250000, now - 1000, now + 86_400_000, 'approver-12']), 'TENANT_MISMATCH'],
      ['delegation starts after the requested window', sign(['claim-001', 'horizon-demo', 250000, now + 1, now + 86_400_000, 'approver-12']), 'DELEGATION_WINDOW'],
      ['delegation ends before the requested window', sign(['claim-001', 'horizon-demo', 250000, now - 1000, now + 3_599_999, 'approver-12']), 'DELEGATION_WINDOW'],
      ['empty approver', sign(['claim-001', 'horizon-demo', 250000, now - 1000, now + 86_400_000, '']), 'LEDGER_SCHEMA'],
    ];
    for (const [name, document, code] of cases) await assert.rejects(w.delegation.issue(document, w.request), refused(code), name);
    await assert.rejects(w.delegation.issue({ line: w.validReport, signature_hex: w.validLine.signature_hex }, w.request), refused('LEDGER_COLUMNS'), 'JWS fed to the ledger adapter');
    await assert.rejects(w.delegation.issue({ line: w.validLine.line, signature_hex: 'zz' }, w.request), error => error instanceof Error && error.name === 'ZodError');
    await assert.rejects(w.delegation.issue(w.validLine, { ...w.request, subject: 'claim-001' , valid_from_ms: w.request.valid_from_ms + 1 }), refused('REQUEST_SIGNATURE'));
    assert.equal(w.issuances(), 0);
    assert.ok(await w.delegation.issue(w.validLine, w.request));
    await assert.rejects(w.delegation.issue(w.validLine, w.request), refused('SOURCE_ALREADY_USED'));
    assert.equal(w.issuances(), 1);
    assert.throws(() => new DelegationLedgerIssuer(w.worker, w.delegationKeys, w.delegationKeys.public_key_hex), refused('SOURCE_KEY_IS_AUTHORITY_KEY'));
  } finally { w.close(); }
});

test('wrong role at the registry and attestations for another case or holder never reach an effect', async () => {
  const w = await world();
  try {
    const h = await assemble(w);
    const store = new AuthorizationStore(join(w.directory, 'roles.sqlite'), h.config, () => now);
    try {
      const challenge = store.issue(); const presentation = await h.prove({ ...challenge, method: 'challenge_bound' });
      // Registry with the roles swapped: the expert key cannot vouch for the cap.
      const swapped = publishRegistry(1, w.delegationKeys, w.expertKeys);
      const raw = rawVerify(presentation, { ...challenge, method: 'challenge_bound' }, swapped, h.config.policy);
      assert.equal(raw.ok, false); assert.ok(raw.error.startsWith('UNKNOWN_ISSUER'), raw.error);
      // Same authority registered for both roles is refused at publication.
      assert.throws(() => publishRegistry(1, w.expertKeys, w.expertKeys), refused('DISTINCT_AUTHORITIES_REQUIRED'));
      // Attestations issued to another holder, submitted through the SDK with this holder's config: refused, zero effects.
      const otherHolder = keypair();
      const foreignRequest = w.signRequest({ ...w.request, holder_public_key_hex: otherHolder.publicKeyHex }, otherHolder.key);
      const foreignAmount = await w.expert.issue(jws(w.expertSystem.key, 'assessment-system-7', { ...w.report, assessed_at_ms: w.report.assessed_at_ms + 1 }), foreignRequest);
      const foreignCap = await w.delegation.issue(ledgerLine(w.ledgerSystem.key, ['claim-001', 'horizon-demo', 250000, now - 86_400_000, now + 86_400_000, 'approver-13']), foreignRequest);
      const foreign = { ...Record.parse(presentation), evidence: { amount: foreignAmount.evidence, cap: foreignCap.evidence } };
      const tool = createClaimTool(store, w.worker, h.config, () => now);
      const issued = await tool.issue({});
      await assert.rejects(tool.execute({ nonce: issued.nonce, presentation: foreign }), error => error instanceof Error && error.message === 'REJECTED');
      assert.equal(effects(store), 0);
      // The SDK refuses by evidence pinning; the verifier itself refuses the same bundle by the holder signature.
      const rawForeign = rawVerify(foreign, { ...challenge, method: 'challenge_bound' }, h.config.trust, h.config.policy);
      assert.equal(rawForeign.ok, false); assert.ok(rawForeign.error.startsWith('INVALID_SIGNATURE'), rawForeign.error);
    } finally { store.close(); }
  } finally { w.close(); }
});

test('revocation during dispatch: a verified bundle is refused by the controller and by the verifier under the new registry, zero effects', async () => {
  const w = await world();
  try {
    const h = await assemble(w);
    const store = new AuthorizationStore(join(w.directory, 'revocation.sqlite'), h.config, () => now);
    try {
      const challenge = store.issue();
      const presentation = await h.prove({ ...challenge, method: 'challenge_bound' });
      const verified = Verified.parse(await w.worker.request({ op: 'verify', presentation, expected: { ...challenge, method: 'challenge_bound' },
        trust: h.config.trust, policy: h.config.policy, now_ms: now }));
      // Registry publication: the operator's new registry lists the key and moves to epoch 2.
      const revoked = revokeIssuerKey(w.trust, w.expertKeys.public_key_hex);
      assert.equal(revoked.epoch, 2); assert.deepEqual(revoked.revoked_public_keys_hex, [w.expertKeys.public_key_hex]);
      assert.throws(() => revokeIssuerKey(w.trust, 'ab'.repeat(32)), refused('UNKNOWN_ISSUER_KEY'));
      // Controller: the same revocation applied through revokeIssuerKey; the verified bundle under epoch 1 is stale.
      store.revokeIssuerKey(w.expertKeys.public_key_hex);
      assert.deepEqual(store.revokedIssuerKeys(), [w.expertKeys.public_key_hex]); assert.equal(store.state().trust_epoch, 2);
      assert.throws(() => store.authorize(challenge, { ...verified, method: 'challenge_bound' }), /^Error: STALE_EPOCH$/);
      assert.equal(effects(store), 0);
      // A NEW challenge at epoch 2 still cannot be authorized: the SDK adapter hands the revocation list to the verifier.
      const tool = createClaimTool(store, w.worker, h.config, () => now);
      const fresh = await tool.issue({}); assert.equal(fresh.trust_epoch, 2);
      const prepared = await w.worker.request({ op: 'prepare', evidence: h.evidence, witness: h.witness });
      const bundle = await w.worker.request({ op: 'present', evidence: h.evidence, prepared, holder_secret_hex: w.lab.holder_secret_hex, challenge: fresh });
      await assert.rejects(tool.execute({ nonce: fresh.nonce, presentation: bundle }), error => error instanceof Error && error.message === 'REJECTED');
      assert.equal(effects(store), 0);
      const raw = rawVerify(bundle, fresh, { ...revoked }, h.config.policy);
      assert.equal(raw.ok, false); assert.ok(raw.error.startsWith('REVOKED_ISSUER_KEY'), raw.error);
      // Under the old registry at epoch 1 the old bundle is only stale; an uppercase entry in the list is refused as non-canonical.
      const stale = rawVerify(presentation, { ...challenge, method: 'challenge_bound' }, revoked, h.config.policy);
      assert.ok(stale.error.startsWith('TRUST_EPOCH_MISMATCH'), stale.error);
      const uppercase = rawVerify(bundle, fresh, { ...revoked, revoked_public_keys_hex: [w.expertKeys.public_key_hex.toUpperCase()] }, h.config.policy);
      assert.ok(uppercase.error.startsWith('NONCANONICAL_HEX'), uppercase.error);
      // A registry written before the field existed still verifies (compatibility).
      assert.equal(rawVerify(presentation, { ...challenge, method: 'challenge_bound' }, w.trust, h.config.policy).ok, true);
    } finally { store.close(); }
  } finally { w.close(); }
});

test('revocation between reservation and the single remote attempt: REJECTED before any target attempt', async () => {
  const w = await world();
  const target = createSandboxTarget({ databasePath: join(w.directory, 'target.sqlite'), clock: () => now });
  await new Promise<void>(done => target.server.listen(0, '127.0.0.1', done));
  const address = target.server.address(); assert.ok(address && typeof address !== 'string');
  const remote = new RemoteTarget(`http://127.0.0.1:${address.port}`, 1000);
  try {
    const h = await assemble(w);
    const store = new AuthorizationStore(join(w.directory, 'dispatch-revocation.sqlite'), h.config, () => now);
    try {
      const challenge = store.issue(); // reusable, as the verifier's policy selects
      const prepared = await w.worker.request({ op: 'prepare', evidence: h.evidence, witness: h.witness });
      const bundle = await w.worker.request({ op: 'present', evidence: h.evidence, prepared, holder_secret_hex: w.lab.holder_secret_hex, challenge });
      const verified = Verified.parse(await w.worker.request({ op: 'verify', presentation: bundle, expected: challenge,
        trust: h.config.trust, policy: h.config.policy, now_ms: now }));
      // The operator revokes the key while the version read is in flight, i.e. after the controller decided to dispatch.
      const original = remote.version.bind(remote);
      remote.version = async objectId => { const version = await original(objectId); store.revokeIssuerKey(w.expertKeys.public_key_hex); return version; };
      await assert.rejects(store.dispatch(challenge, verified, remote), /^Error: STALE_EPOCH$/);
      assert.equal(target.attempts(), 0); assert.equal(target.effects(), 0); assert.equal(effects(store), 0);
      assert.deepEqual(store.expected(challenge.nonce), challenge); // nothing consumed: refused inside the reservation transaction
    } finally { store.close(); }
  } finally { await target.close(); w.close(); }
});
