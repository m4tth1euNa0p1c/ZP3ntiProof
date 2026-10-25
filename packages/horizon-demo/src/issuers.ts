import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { z } from 'zod';
import type { ProofWorker } from './worker.js';

/**
 * H13 issuer provenance adapters. Two SEPARATE synthetic authorities consume a source document in a
 * real-world format, validate it against their own registered source signer, and ask the Rust worker
 * to issue the exact attestation schema under the authority's own key. The opening (value and
 * blinding) is returned to the caller for the holder only; nothing here authorizes an action.
 *
 * Synthetic keys and documents authenticate no real organization; truth of the facts is the
 * authority's responsibility (CLAIMS P01, ticket H13).
 */
const token = z.string().min(1).max(128).regex(/^[A-Za-z0-9._:/-]+$/);
const hex64 = z.string().regex(/^[0-9a-f]{64}$/);
const uint = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const RANGE = 2 ** 32;

export const IssuerKeys = z.strictObject({ issuer: token, public_key_hex: hex64, signing_secret_hex: hex64 });
export type IssuerKeys = z.infer<typeof IssuerKeys>;

/** What the holder asks for: the window must be covered by the source and is shared by both attestations.
 * The holder proves possession of the named key by signing the request (domain-separated canonical JSON). */
export const IssuanceRequest = z.strictObject({ tenant: token, subject: token, holder_public_key_hex: hex64,
  valid_from_ms: uint, valid_until_ms: uint, request_signature_hex: z.string().regex(/^[0-9a-f]{128}$/) });
export type IssuanceRequest = z.infer<typeof IssuanceRequest>;
export const REQUEST_DOMAIN = 'horizon/issuance-request/v1\0';
/** Canonical bytes signed by the holder: declaration order, no signature field. */
export function issuanceRequestBytes(request: Omit<IssuanceRequest, 'request_signature_hex'>): Buffer {
  return Buffer.from(REQUEST_DOMAIN + JSON.stringify({ tenant: request.tenant, subject: request.subject,
    holder_public_key_hex: request.holder_public_key_hex, valid_from_ms: request.valid_from_ms, valid_until_ms: request.valid_until_ms }), 'utf8');
}
function checkRequest(request: IssuanceRequest): IssuanceRequest {
  const parsed = IssuanceRequest.parse(request);
  if (parsed.valid_from_ms >= parsed.valid_until_ms) throw new IssuerError('VALIDITY_WINDOW');
  if (!verifySignature(null, issuanceRequestBytes(parsed), spki(parsed.holder_public_key_hex), Buffer.from(parsed.request_signature_hex, 'hex')))
    throw new IssuerError('REQUEST_SIGNATURE');
  return parsed;
}
/** Each source document backs at most one issuance per adapter instance (in-memory; a deployment needs a durable store). */
class UsedSources {
  private readonly digests = new Set<string>();
  claim(document: string): void {
    const digest = createHash('sha256').update(document, 'utf8').digest('hex');
    if (this.digests.has(digest)) throw new IssuerError('SOURCE_ALREADY_USED');
    this.digests.add(digest);
  }
}

export const Issued = z.strictObject({
  evidence: z.strictObject({ body: z.record(z.string(), z.unknown()), signature_hex: z.string().regex(/^[0-9a-f]{128}$/) }),
  opening: z.strictObject({ value: uint, blinding_hex: hex64 }),
});
export type Issued = z.infer<typeof Issued>;

export class IssuerError extends Error {
  constructor(readonly code: string) { super(code); this.name = 'IssuerError'; }
}

const spki = (publicKeyHex: string) => createPublicKey({ format: 'der', type: 'spki',
  key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(publicKeyHex, 'hex')]) });

async function issueThroughWorker(worker: ProofWorker, keys: IssuerKeys, role: 'amount' | 'cap', request: IssuanceRequest, value: number): Promise<Issued> {
  const result = await worker.request({ op: 'issue', issuer_secret_hex: keys.signing_secret_hex,
    request: { role, issuer: keys.issuer, tenant: request.tenant, subject: request.subject,
      holder_public_key_hex: request.holder_public_key_hex, valid_from_ms: request.valid_from_ms, valid_until_ms: request.valid_until_ms, value } })
    .catch(() => { throw new IssuerError('ISSUANCE_REFUSED'); });
  return Issued.parse(result);
}

/* ------------------------------------------------------------------------------------------------ */
/* Authority 1: claims expert. Source = a JWS (RFC 7515 compact serialization, EdDSA/Ed25519)        */
/* emitted by the expert's assessment system; the authority only accepts registered signers.         */
/* ------------------------------------------------------------------------------------------------ */
const JwsHeader = z.strictObject({ alg: z.literal('EdDSA'), typ: z.literal('horizon-expert-report+json'), kid: token });
export const ExpertReport = z.strictObject({
  case_id: token, tenant: token, assessed_amount_cents: z.number().int().min(1).max(RANGE), currency: z.literal('EUR'),
  assessed_at_ms: uint, expert_system: token,
});
export type ExpertReport = z.infer<typeof ExpertReport>;

const base64url = (text: string): Buffer => {
  if (!/^[A-Za-z0-9_-]+$/.test(text)) throw new IssuerError('JWS_ENCODING');
  return Buffer.from(text, 'base64url');
};

export class ExpertReportIssuer {
  private readonly used = new UsedSources();
  private readonly maxValidityMs: number;
  /** `reportSigners`: kid → Ed25519 public key (hex) of the assessment systems this authority trusts.
   * `maxValidityMs`: longest attestation validity measured from the assessment date (default 30 days). */
  constructor(private readonly worker: ProofWorker, private readonly keys: IssuerKeys, private readonly reportSigners: ReadonlyMap<string, string>,
    options: { maxValidityMs?: number } = {}) {
    IssuerKeys.parse(keys);
    for (const key of reportSigners.values()) { hex64.parse(key); if (key === keys.public_key_hex) throw new IssuerError('SOURCE_KEY_IS_AUTHORITY_KEY'); }
    this.maxValidityMs = z.number().int().min(1).max(366 * 86_400_000).parse(options.maxValidityMs ?? 30 * 86_400_000);
  }

  /** Verify the JWS and return the report, or throw an IssuerError. Pure validation, no issuance. */
  verifyReport(jws: string): ExpertReport {
    const parts = jws.split('.');
    if (parts.length !== 3 || parts.some(part => part.length === 0)) throw new IssuerError('JWS_FORMAT');
    const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];
    let header: z.infer<typeof JwsHeader>;
    try { header = JwsHeader.parse(JSON.parse(base64url(encodedHeader).toString('utf8'))); }
    catch (error) { throw error instanceof IssuerError ? error : new IssuerError('JWS_HEADER'); }
    const signer = this.reportSigners.get(header.kid);
    if (signer === undefined) throw new IssuerError('UNKNOWN_REPORT_SIGNER');
    const signature = base64url(encodedSignature);
    if (signature.length !== 64 || !verifySignature(null, Buffer.from(`${encodedHeader}.${encodedPayload}`, 'ascii'), spki(signer), signature))
      throw new IssuerError('REPORT_SIGNATURE');
    let report: ExpertReport;
    try { report = ExpertReport.parse(JSON.parse(base64url(encodedPayload).toString('utf8'))); }
    catch (error) { throw error instanceof IssuerError ? error : new IssuerError('REPORT_SCHEMA'); }
    if (report.expert_system !== header.kid) throw new IssuerError('REPORT_SIGNER_MISMATCH');
    return report;
  }

  async issue(jws: string, request: IssuanceRequest): Promise<Issued> {
    const parsed = checkRequest(request);
    const report = this.verifyReport(jws);
    if (report.case_id !== parsed.subject) throw new IssuerError('CASE_MISMATCH');
    if (report.tenant !== parsed.tenant) throw new IssuerError('TENANT_MISMATCH');
    if (report.assessed_at_ms > parsed.valid_from_ms) throw new IssuerError('ASSESSMENT_AFTER_VALIDITY');
    if (parsed.valid_until_ms - report.assessed_at_ms > this.maxValidityMs) throw new IssuerError('VALIDITY_TOO_LONG');
    this.used.claim(jws); // one report, one attestation; a refused worker call does not release it
    return issueThroughWorker(this.worker, this.keys, 'amount', parsed, report.assessed_amount_cents);
  }
}

/* ------------------------------------------------------------------------------------------------ */
/* Authority 2: delegating insurer. Source = one CSV record of the delegation ledger with a detached */
/* Ed25519 signature by the ledger system over the domain-separated canonical line.                  */
/* ------------------------------------------------------------------------------------------------ */
export const LEDGER_DOMAIN = 'horizon/delegation-ledger/v1\0';
export const LEDGER_COLUMNS = ['case_id', 'tenant', 'cap_cents', 'valid_from_ms', 'valid_until_ms', 'approver'] as const;
export const LedgerRecord = z.strictObject({ case_id: token, tenant: token, cap_cents: z.number().int().min(1).max(2 * RANGE - 1),
  valid_from_ms: uint, valid_until_ms: uint, approver: token });
export type LedgerRecord = z.infer<typeof LedgerRecord>;
export const SignedLedgerLine = z.strictObject({ line: z.string().min(1).max(1024), signature_hex: z.string().regex(/^[0-9a-f]{128}$/) });
export type SignedLedgerLine = z.infer<typeof SignedLedgerLine>;

export class DelegationLedgerIssuer {
  private readonly used = new UsedSources();
  constructor(private readonly worker: ProofWorker, private readonly keys: IssuerKeys, private readonly ledgerPublicKeyHex: string) {
    IssuerKeys.parse(keys); hex64.parse(ledgerPublicKeyHex);
    if (ledgerPublicKeyHex === keys.public_key_hex) throw new IssuerError('SOURCE_KEY_IS_AUTHORITY_KEY');
  }

  /** Strict CSV: exactly six unquoted ASCII columns, decimal integers, no surrounding whitespace. */
  verifyLine(input: SignedLedgerLine): LedgerRecord {
    const { line, signature_hex } = SignedLedgerLine.parse(input);
    if (/[\r\n"']/.test(line) || line !== line.trim()) throw new IssuerError('LEDGER_FORMAT');
    const columns = line.split(',');
    if (columns.length !== LEDGER_COLUMNS.length) throw new IssuerError('LEDGER_COLUMNS');
    if (!verifySignature(null, Buffer.from(LEDGER_DOMAIN + line, 'utf8'), spki(this.ledgerPublicKeyHex), Buffer.from(signature_hex, 'hex')))
      throw new IssuerError('LEDGER_SIGNATURE');
    const integer = (text: string | undefined, field: string): number => {
      if (text === undefined || !/^(0|[1-9][0-9]{0,15})$/.test(text)) throw new IssuerError(`LEDGER_FIELD_${field.toUpperCase()}`);
      return Number(text);
    };
    try {
      return LedgerRecord.parse({ case_id: columns[0], tenant: columns[1], cap_cents: integer(columns[2], 'cap_cents'),
        valid_from_ms: integer(columns[3], 'valid_from_ms'), valid_until_ms: integer(columns[4], 'valid_until_ms'), approver: columns[5] });
    } catch (error) { throw error instanceof IssuerError ? error : new IssuerError('LEDGER_SCHEMA'); }
  }

  async issue(input: SignedLedgerLine, request: IssuanceRequest): Promise<Issued> {
    const parsed = checkRequest(request);
    const record = this.verifyLine(input);
    if (record.case_id !== parsed.subject) throw new IssuerError('CASE_MISMATCH');
    if (record.tenant !== parsed.tenant) throw new IssuerError('TENANT_MISMATCH');
    if (record.valid_from_ms > parsed.valid_from_ms || parsed.valid_until_ms > record.valid_until_ms) throw new IssuerError('DELEGATION_WINDOW');
    this.used.claim(input.line);
    return issueThroughWorker(this.worker, this.keys, 'cap', parsed, record.cap_cents);
  }
}

/* ------------------------------------------------------------------------------------------------ */
/* Verifier-side registry publication. Versioned by epoch; revocation lists a key and bumps the epoch. */
/* ------------------------------------------------------------------------------------------------ */
export const TrustRegistry = z.strictObject({
  epoch: uint, amount_issuer: z.strictObject({ issuer: token, public_key_hex: hex64 }), cap_issuer: z.strictObject({ issuer: token, public_key_hex: hex64 }),
  revoked_public_keys_hex: z.array(hex64).optional(),
});
export type TrustRegistry = z.infer<typeof TrustRegistry>;

export function publishRegistry(epoch: number, amount: Pick<IssuerKeys, 'issuer' | 'public_key_hex'>, cap: Pick<IssuerKeys, 'issuer' | 'public_key_hex'>): TrustRegistry {
  if (amount.issuer === cap.issuer || amount.public_key_hex === cap.public_key_hex) throw new IssuerError('DISTINCT_AUTHORITIES_REQUIRED');
  return TrustRegistry.parse({ epoch, amount_issuer: { issuer: amount.issuer, public_key_hex: amount.public_key_hex },
    cap_issuer: { issuer: cap.issuer, public_key_hex: cap.public_key_hex } });
}

/** One-way: the key stays listed, the epoch increases, every challenge issued under the old epoch becomes stale. */
export function revokeIssuerKey(registry: TrustRegistry, publicKeyHex: string): TrustRegistry {
  const current = TrustRegistry.parse(registry);
  if (current.amount_issuer.public_key_hex !== publicKeyHex && current.cap_issuer.public_key_hex !== publicKeyHex) throw new IssuerError('UNKNOWN_ISSUER_KEY');
  const revoked = new Set(current.revoked_public_keys_hex ?? []); revoked.add(publicKeyHex);
  return TrustRegistry.parse({ ...current, epoch: current.epoch + 1, revoked_public_keys_hex: [...revoked].sort() });
}
