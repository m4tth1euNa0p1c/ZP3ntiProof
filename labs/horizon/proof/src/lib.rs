//! Experimental admission relation on two issuer-signed Pedersen commitments.
//!
//! Amounts are hidden, metadata and stable commitments are public and linkable.
//! No payment, revocation service, durable replay store or security audit is implied.
#![forbid(unsafe_code)]

use anyhow::{bail, ensure, Context, Result};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use merlin::Transcript;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub const PROFILE: &str = "horizon-range-v1";
pub const MAX_INPUT_BYTES: usize = 65_536;
const RANGE: u64 = 1_u64 << 32;
const MAX_PROOF_BYTES: usize = 672;

// Immutable, publicly derived parameters for this fixed two-value 32-bit profile.
// Callers cannot choose or mutate these generators. No witness or RNG is cached.
fn bulletproof_generators() -> &'static BulletproofGens {
    static GENERATORS: OnceLock<BulletproofGens> = OnceLock::new();
    GENERATORS.get_or_init(|| BulletproofGens::new(32, 2))
}

fn pedersen_generators() -> &'static PedersenGens {
    static GENERATORS: OnceLock<PedersenGens> = OnceLock::new();
    GENERATORS.get_or_init(PedersenGens::default)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    ChallengeBound,
    Reusable,
    Disclosure,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Amount,
    Cap,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub profile: String,
    pub role: Role,
    pub issuer: String,
    pub tenant: String,
    pub subject: String,
    pub currency: String,
    pub exponent: u8,
    pub version: u64,
    pub holder_public_key_hex: String,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub commitment_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedEvidence {
    pub body: Evidence,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidencePair {
    pub amount: SignedEvidence,
    pub cap: SignedEvidence,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuerKey {
    pub issuer: String,
    pub public_key_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustRegistry {
    pub epoch: u64,
    pub amount_issuer: IssuerKey,
    pub cap_issuer: IssuerKey,
    /// Issuer public keys withdrawn by the verifier's operator (H13). Absent in registries
    /// written before 2026-10-25, which keep parsing; attestations under a listed key are refused
    /// before any signature check. The field is verifier-local and never enters a commitment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_public_keys_hex: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationPolicy {
    pub policy_id: String,
    pub policy_epoch: u64,
    pub require_private: bool,
    pub allow_reuse: bool,
    pub max_challenge_ttl_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub tenant: String,
    pub client_id: String,
    pub audience: String,
    pub action: String,
    pub operation_id: String,
    pub object_id: String,
    pub subject: String,
    pub policy_id: String,
    pub policy_epoch: u64,
    pub trust_epoch: u64,
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub method: Method,
}

/// Secrets are accepted only by the prover (or explicitly disclosed mode).
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateWitness {
    pub amount: u64,
    pub cap: u64,
    pub amount_blinding_hex: String,
    pub cap_blinding_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReusableProof {
    pub evidence_hash: String,
    pub proof_hex: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Payload {
    ChallengeBound { proof_hex: String },
    Reusable { prepared: ReusableProof },
    Disclosure { witness: PrivateWitness },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Presentation {
    pub profile: String,
    pub evidence: EvidencePair,
    pub challenge: Challenge,
    pub payload: Payload,
    pub holder_signature_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Verified {
    pub bundle_hash: String,
    pub method: Method,
    pub tenant: String,
    pub subject: String,
    pub operation_id: String,
    pub object_id: String,
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    pub trust: TrustRegistry,
    pub evidence: EvidencePair,
    pub witness: PrivateWitness,
    pub holder_secret_hex: String,
    pub challenge: Challenge,
    pub policy: VerificationPolicy,
}

/// The single encoding is typed JSON in declaration order; no maps or floats.
/// Unknown fields are rejected on input. Domain labels prevent cross-protocol use.
fn message<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= MAX_INPUT_BYTES, "INPUT_TOO_LARGE");
    let mut output = Vec::with_capacity(domain.len() + 1 + bytes.len());
    output.extend_from_slice(domain);
    output.push(0);
    output.extend_from_slice(&bytes);
    Ok(output)
}

fn digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String> {
    Ok(hex::encode(Sha256::digest(message(domain, value)?)))
}

fn decode<const N: usize>(value: &str) -> Result<[u8; N]> {
    ensure!(value.len() == N * 2, "ENCODING_LENGTH");
    let bytes: [u8; N] = hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("ENCODING_LENGTH"))?;
    ensure!(hex::encode(bytes) == value, "NONCANONICAL_HEX");
    Ok(bytes)
}

fn scalar(value: &str) -> Result<Scalar> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(decode(value)?))
        .context("NONCANONICAL_SCALAR")
}

fn point(value: &str) -> Result<CompressedRistretto> {
    let compressed = CompressedRistretto(decode(value)?);
    ensure!(compressed.decompress().is_some(), "INVALID_POINT");
    Ok(compressed)
}

fn key(value: &str) -> Result<VerifyingKey> {
    let public = VerifyingKey::from_bytes(&decode(value)?)?;
    ensure!(!public.is_weak(), "WEAK_KEY");
    Ok(public)
}

fn signed<T: Serialize>(domain: &[u8], value: &T, secret: &SigningKey) -> Result<String> {
    Ok(hex::encode(
        secret.sign(&message(domain, value)?).to_bytes(),
    ))
}

fn check_signature<T: Serialize>(
    domain: &[u8],
    value: &T,
    signature: &str,
    public: &str,
) -> Result<()> {
    key(public)?
        .verify_strict(
            &message(domain, value)?,
            &Signature::from_bytes(&decode(signature)?),
        )
        .context("INVALID_SIGNATURE")
}

fn label(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value.bytes().all(|b| (0x21..=0x7e).contains(&b)),
        "INVALID_LABEL"
    );
    Ok(())
}

fn validate_pair(evidence: &EvidencePair) -> Result<()> {
    let a = &evidence.amount.body;
    let c = &evidence.cap.body;
    ensure!(a.role == Role::Amount && c.role == Role::Cap, "ISSUER_ROLE");
    for e in [a, c] {
        ensure!(
            e.profile == PROFILE && e.currency == "EUR" && e.exponent == 2 && e.version == 1,
            "EVIDENCE_PROFILE"
        );
        for value in [&e.issuer, &e.tenant, &e.subject] {
            label(value)?;
        }
        ensure!(e.valid_from_ms < e.valid_until_ms, "EVIDENCE_TIME");
        point(&e.commitment_hex)?;
        key(&e.holder_public_key_hex)?;
    }
    ensure!(
        a.tenant == c.tenant
            && a.subject == c.subject
            && a.currency == c.currency
            && a.exponent == c.exponent
            && a.version == c.version
            && a.holder_public_key_hex == c.holder_public_key_hex
            && a.valid_from_ms == c.valid_from_ms
            && a.valid_until_ms == c.valid_until_ms,
        "EVIDENCE_JOIN"
    );
    ensure!(a.issuer != c.issuer, "DISTINCT_AUTHORITIES_REQUIRED");
    Ok(())
}

fn check_witness(evidence: &EvidencePair, witness: &PrivateWitness) -> Result<(Scalar, Scalar)> {
    validate_pair(evidence)?;
    ensure!((1..=RANGE).contains(&witness.amount), "AMOUNT_RANGE");
    let difference = witness
        .cap
        .checked_sub(witness.amount)
        .context("CAP_BELOW_AMOUNT")?;
    ensure!(difference < RANGE, "DIFFERENCE_RANGE");
    let a = scalar(&witness.amount_blinding_hex)?;
    let c = scalar(&witness.cap_blinding_hex)?;
    let generators = pedersen_generators();
    ensure!(
        generators
            .commit(Scalar::from(witness.amount), a)
            .compress()
            == point(&evidence.amount.body.commitment_hex)?,
        "AMOUNT_OPENING"
    );
    ensure!(
        generators.commit(Scalar::from(witness.cap), c).compress()
            == point(&evidence.cap.body.commitment_hex)?,
        "CAP_OPENING"
    );
    Ok((a, c))
}

fn commitments(evidence: &EvidencePair) -> Result<[CompressedRistretto; 2]> {
    let a = point(&evidence.amount.body.commitment_hex)?
        .decompress()
        .context("INVALID_POINT")?;
    let c = point(&evidence.cap.body.commitment_hex)?
        .decompress()
        .context("INVALID_POINT")?;
    Ok([(a - pedersen_generators().B).compress(), (c - a).compress()])
}

fn transcript(evidence: &EvidencePair, challenge: Option<&Challenge>) -> Result<Transcript> {
    let mut transcript = Transcript::new(b"horizon-range-v1");
    transcript.append_message(
        b"evidence",
        &message(b"horizon/evidence-pair/v1", evidence)?,
    );
    if let Some(challenge) = challenge {
        transcript.append_message(b"mode", b"challenge_bound");
        transcript.append_message(b"challenge", &message(b"horizon/challenge/v1", challenge)?);
    } else {
        transcript.append_message(b"mode", b"reusable");
    }
    Ok(transcript)
}

fn range_prove(
    evidence: &EvidencePair,
    witness: &PrivateWitness,
    challenge: Option<&Challenge>,
) -> Result<String> {
    let (a, c) = check_witness(evidence, witness)?;
    let (proof, actual) = RangeProof::prove_multiple_with_rng(
        bulletproof_generators(),
        pedersen_generators(),
        &mut transcript(evidence, challenge)?,
        &[witness.amount - 1, witness.cap - witness.amount],
        &[a, c - a],
        32,
        &mut OsRng,
    )
    .context("RANGE_PROVING")?;
    ensure!(
        actual.as_slice() == commitments(evidence)?,
        "DERIVED_COMMITMENTS"
    );
    Ok(hex::encode(proof.to_bytes()))
}

fn range_verify(evidence: &EvidencePair, proof: &str, challenge: Option<&Challenge>) -> Result<()> {
    ensure!(proof.len() == MAX_PROOF_BYTES * 2, "PROOF_LENGTH");
    let bytes = hex::decode(proof)?;
    ensure!(hex::encode(&bytes) == proof, "NONCANONICAL_HEX");
    RangeProof::from_bytes(&bytes)?
        .verify_multiple_with_rng(
            bulletproof_generators(),
            pedersen_generators(),
            &mut transcript(evidence, challenge)?,
            &commitments(evidence)?,
            32,
            &mut OsRng,
        )
        .context("INVALID_RANGE_PROOF")
}

pub fn evidence_hash(evidence: &EvidencePair) -> Result<String> {
    digest(b"horizon/evidence-pair/v1", evidence)
}

/// A policy decision, never a fallback after a failed proof.
pub fn select_method(policy: &VerificationPolicy) -> Method {
    if !policy.require_private {
        Method::Disclosure
    } else if policy.allow_reuse {
        Method::Reusable
    } else {
        Method::ChallengeBound
    }
}

/// Offline prover work on immutable attestations. Does not authorize an action.
pub fn prepare(evidence: &EvidencePair, witness: &PrivateWitness) -> Result<ReusableProof> {
    Ok(ReusableProof {
        evidence_hash: evidence_hash(evidence)?,
        proof_hex: range_prove(evidence, witness, None)?,
    })
}

fn holder_message(presentation: &Presentation) -> Result<String> {
    digest(
        b"horizon/presentation/v1",
        &(
            &presentation.profile,
            &presentation.evidence,
            &presentation.challenge,
            &presentation.payload,
        ),
    )
}

fn present(
    evidence: &EvidencePair,
    payload: Payload,
    holder_secret_hex: &str,
    challenge: &Challenge,
) -> Result<Presentation> {
    validate_pair(evidence)?;
    let holder = SigningKey::from_bytes(&decode(holder_secret_hex)?);
    ensure!(
        hex::encode(holder.verifying_key().to_bytes())
            == evidence.amount.body.holder_public_key_hex,
        "HOLDER_KEY"
    );
    let mut presentation = Presentation {
        profile: PROFILE.into(),
        evidence: evidence.clone(),
        challenge: challenge.clone(),
        payload,
        holder_signature_hex: String::new(),
    };
    presentation.holder_signature_hex = signed(
        b"horizon/holder-authorization/v1",
        &holder_message(&presentation)?,
        &holder,
    )?;
    Ok(presentation)
}

/// Online holder work: reuse the supplied proof and sign this exact new session.
pub fn present_reusable(
    evidence: &EvidencePair,
    prepared: &ReusableProof,
    holder_secret_hex: &str,
    challenge: &Challenge,
) -> Result<Presentation> {
    ensure!(challenge.method == Method::Reusable, "METHOD_MISMATCH");
    ensure!(
        prepared.evidence_hash == evidence_hash(evidence)?,
        "PREPARED_EVIDENCE_MISMATCH"
    );
    present(
        evidence,
        Payload::Reusable {
            prepared: prepared.clone(),
        },
        holder_secret_hex,
        challenge,
    )
}

pub fn prove(
    evidence: &EvidencePair,
    witness: &PrivateWitness,
    holder_secret_hex: &str,
    challenge: &Challenge,
) -> Result<Presentation> {
    let payload = match challenge.method {
        Method::ChallengeBound => Payload::ChallengeBound {
            proof_hex: range_prove(evidence, witness, Some(challenge))?,
        },
        Method::Disclosure => {
            check_witness(evidence, witness)?;
            Payload::Disclosure {
                witness: witness.clone(),
            }
        }
        Method::Reusable => bail!("USE_PREPARE_THEN_PRESENT"),
    };
    present(evidence, payload, holder_secret_hex, challenge)
}

/// Full verification. All mutable authorization state belongs to the caller.
/// `expected`, registry, policy and clock MUST be independently trusted inputs.
pub fn verify(
    presentation: &Presentation,
    expected: &Challenge,
    trust: &TrustRegistry,
    policy: &VerificationPolicy,
    now_ms: u64,
) -> Result<Verified> {
    ensure!(
        serde_json::to_vec(presentation)?.len() <= MAX_INPUT_BYTES,
        "INPUT_TOO_LARGE"
    );
    ensure!(presentation.profile == PROFILE, "PROFILE_MISMATCH");
    ensure!(&presentation.challenge == expected, "CHALLENGE_MISMATCH");
    ensure!(
        expected.policy_id == policy.policy_id && expected.policy_epoch == policy.policy_epoch,
        "POLICY_MISMATCH"
    );
    ensure!(expected.trust_epoch == trust.epoch, "TRUST_EPOCH_MISMATCH");
    ensure!(
        expected.action == "record_claim_authorization",
        "ACTION_MISMATCH"
    );
    for value in [
        &expected.tenant,
        &expected.client_id,
        &expected.audience,
        &expected.operation_id,
        &expected.object_id,
        &expected.subject,
        &expected.policy_id,
    ] {
        label(value)?;
    }
    decode::<32>(&expected.nonce)?;
    let ttl = expected
        .expires_at_ms
        .checked_sub(expected.issued_at_ms)
        .context("CHALLENGE_TIME")?;
    ensure!(
        ttl > 0 && ttl <= policy.max_challenge_ttl_ms,
        "CHALLENGE_TTL"
    );
    ensure!(
        expected.issued_at_ms <= now_ms && now_ms < expected.expires_at_ms,
        "CHALLENGE_EXPIRED"
    );
    ensure!(
        !(policy.require_private && expected.method == Method::Disclosure),
        "DISCLOSURE_FORBIDDEN"
    );
    ensure!(
        policy.allow_reuse || expected.method != Method::Reusable,
        "REUSE_FORBIDDEN"
    );
    validate_pair(&presentation.evidence)?;
    ensure!(
        trust.amount_issuer.issuer != trust.cap_issuer.issuer
            && trust.amount_issuer.public_key_hex != trust.cap_issuer.public_key_hex,
        "DISTINCT_AUTHORITIES_REQUIRED"
    );
    let mut expiry = expected.expires_at_ms;
    let mut not_before = expected.issued_at_ms;
    for (signed_evidence, issuer) in [
        (&presentation.evidence.amount, &trust.amount_issuer),
        (&presentation.evidence.cap, &trust.cap_issuer),
    ] {
        let body = &signed_evidence.body;
        ensure!(body.issuer == issuer.issuer, "UNKNOWN_ISSUER");
        for revoked in &trust.revoked_public_keys_hex {
            // Canonical lowercase hex only: a differently cased entry must not silently never match.
            decode::<32>(revoked)?;
            ensure!(revoked != &issuer.public_key_hex, "REVOKED_ISSUER_KEY");
        }
        ensure!(
            body.tenant == expected.tenant && body.subject == expected.subject,
            "SUBJECT_MISMATCH"
        );
        ensure!(
            body.valid_from_ms <= now_ms && now_ms < body.valid_until_ms,
            "EVIDENCE_EXPIRED"
        );
        check_signature(
            b"horizon/issuer-attestation/v1",
            body,
            &signed_evidence.signature_hex,
            &issuer.public_key_hex,
        )?;
        expiry = expiry.min(body.valid_until_ms);
        not_before = not_before.max(body.valid_from_ms);
    }
    check_signature(
        b"horizon/holder-authorization/v1",
        &holder_message(presentation)?,
        &presentation.holder_signature_hex,
        &presentation.evidence.amount.body.holder_public_key_hex,
    )?;
    match (&presentation.payload, expected.method) {
        (Payload::ChallengeBound { proof_hex }, Method::ChallengeBound) => {
            range_verify(&presentation.evidence, proof_hex, Some(expected))?
        }
        (Payload::Reusable { prepared }, Method::Reusable) => {
            ensure!(
                prepared.evidence_hash == evidence_hash(&presentation.evidence)?,
                "PREPARED_EVIDENCE_MISMATCH"
            );
            range_verify(&presentation.evidence, &prepared.proof_hex, None)?;
        }
        (Payload::Disclosure { witness }, Method::Disclosure) => {
            check_witness(&presentation.evidence, witness)?;
        }
        _ => bail!("METHOD_MISMATCH"),
    }
    Ok(Verified {
        bundle_hash: holder_message(presentation)?,
        method: expected.method,
        tenant: expected.tenant.clone(),
        subject: expected.subject.clone(),
        operation_id: expected.operation_id.clone(),
        object_id: expected.object_id.clone(),
        not_before_ms: not_before,
        expires_at_ms: expiry,
    })
}

/// H13 issuance request: one authority, one validated fact, one holder. The authority is
/// responsible for the truth of `value`; this function only builds and signs the exact schema.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssueRequest {
    pub role: Role,
    pub issuer: String,
    pub tenant: String,
    pub subject: String,
    pub holder_public_key_hex: String,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    /// Minor units (`currency = EUR`, `exponent = 2`). Amount: `1..=2^32`; cap: `1..=2^33 - 1`.
    pub value: u64,
}

/// Opening handed to the holder only. Never part of a public configuration.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Opening {
    pub value: u64,
    pub blinding_hex: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Issued {
    pub evidence: SignedEvidence,
    pub opening: Opening,
}

/// Issuer-side work: fresh blinding, Pedersen commitment to the validated fact, Ed25519
/// signature over the canonical body under the issuer domain. Refuses out-of-domain values
/// so that an issued attestation can always be opened within the relation's bounds.
pub fn issue(request: &IssueRequest, issuer_secret_hex: &str) -> Result<Issued> {
    for value in [&request.issuer, &request.tenant, &request.subject] {
        label(value)?;
    }
    ensure!(
        request.valid_from_ms < request.valid_until_ms,
        "EVIDENCE_TIME"
    );
    key(&request.holder_public_key_hex)?;
    let upper = match request.role {
        Role::Amount => RANGE,
        Role::Cap => 2 * RANGE - 1,
    };
    ensure!((1..=upper).contains(&request.value), "VALUE_OUT_OF_DOMAIN");
    let signer = SigningKey::from_bytes(&decode(issuer_secret_hex)?);
    let blinding = Scalar::random(&mut OsRng);
    let body = Evidence {
        profile: PROFILE.into(),
        role: request.role,
        issuer: request.issuer.clone(),
        tenant: request.tenant.clone(),
        subject: request.subject.clone(),
        currency: "EUR".into(),
        exponent: 2,
        version: 1,
        holder_public_key_hex: request.holder_public_key_hex.clone(),
        valid_from_ms: request.valid_from_ms,
        valid_until_ms: request.valid_until_ms,
        commitment_hex: hex::encode(
            pedersen_generators()
                .commit(Scalar::from(request.value), blinding)
                .compress()
                .to_bytes(),
        ),
    };
    let signature_hex = signed(b"horizon/issuer-attestation/v1", &body, &signer)?;
    Ok(Issued {
        evidence: SignedEvidence {
            body,
            signature_hex,
        },
        opening: Opening {
            value: request.value,
            blinding_hex: hex::encode(blinding.to_bytes()),
        },
    })
}

impl Fixture {
    /// Fixture issuance only: random keys, arbitrary laboratory facts, no live issuer.
    pub fn generate(now_ms: u64) -> Result<Self> {
        Self::with_values(now_ms, 125_000, 250_000)
    }

    /// Public for boundary tests. Issuers construct commitments from these lab facts.
    pub fn with_values(now_ms: u64, amount: u64, cap: u64) -> Result<Self> {
        let issuer_a = SigningKey::generate(&mut OsRng);
        let issuer_c = SigningKey::generate(&mut OsRng);
        let holder = SigningKey::generate(&mut OsRng);
        let a_blind = Scalar::random(&mut OsRng);
        let c_blind = Scalar::random(&mut OsRng);
        let until = now_ms.checked_add(3_600_000).context("TIME_OVERFLOW")?;
        let make = |role: Role,
                    issuer: &str,
                    value: u64,
                    blind: Scalar,
                    signer: &SigningKey|
         -> Result<SignedEvidence> {
            let body = Evidence {
                profile: PROFILE.into(),
                role,
                issuer: issuer.into(),
                tenant: "horizon-demo".into(),
                subject: "claim-001".into(),
                currency: "EUR".into(),
                exponent: 2,
                version: 1,
                holder_public_key_hex: hex::encode(holder.verifying_key().to_bytes()),
                valid_from_ms: now_ms,
                valid_until_ms: until,
                commitment_hex: hex::encode(
                    pedersen_generators()
                        .commit(Scalar::from(value), blind)
                        .compress()
                        .to_bytes(),
                ),
            };
            let signature_hex = signed(b"horizon/issuer-attestation/v1", &body, signer)?;
            Ok(SignedEvidence {
                body,
                signature_hex,
            })
        };
        let evidence = EvidencePair {
            amount: make(Role::Amount, "expert", amount, a_blind, &issuer_a)?,
            cap: make(Role::Cap, "delegation", cap, c_blind, &issuer_c)?,
        };
        let mut nonce = [0; 32];
        OsRng.fill_bytes(&mut nonce);
        let policy = VerificationPolicy {
            policy_id: "claim-range-v1".into(),
            policy_epoch: 1,
            require_private: true,
            allow_reuse: true,
            max_challenge_ttl_ms: 30_000,
        };
        let challenge = Challenge {
            tenant: "horizon-demo".into(),
            client_id: "claims-agent".into(),
            audience: "horizon-verifier".into(),
            action: "record_claim_authorization".into(),
            operation_id: "operation-001".into(),
            object_id: "claim-001".into(),
            subject: "claim-001".into(),
            policy_id: policy.policy_id.clone(),
            policy_epoch: 1,
            trust_epoch: 1,
            nonce: hex::encode(nonce),
            issued_at_ms: now_ms,
            expires_at_ms: now_ms.checked_add(30_000).context("TIME_OVERFLOW")?,
            method: Method::ChallengeBound,
        };
        Ok(Self {
            trust: TrustRegistry {
                epoch: 1,
                amount_issuer: IssuerKey {
                    issuer: "expert".into(),
                    public_key_hex: hex::encode(issuer_a.verifying_key().to_bytes()),
                },
                cap_issuer: IssuerKey {
                    issuer: "delegation".into(),
                    public_key_hex: hex::encode(issuer_c.verifying_key().to_bytes()),
                },
                revoked_public_keys_hex: Vec::new(),
            },
            evidence,
            witness: PrivateWitness {
                amount,
                cap,
                amount_blinding_hex: hex::encode(a_blind.to_bytes()),
                cap_blinding_hex: hex::encode(c_blind.to_bytes()),
            },
            holder_secret_hex: hex::encode(holder.to_bytes()),
            challenge,
            policy,
        })
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod binding_tests;

#[cfg(test)]
mod issuer_tests;
