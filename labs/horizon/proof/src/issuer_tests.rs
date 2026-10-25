//! H13: issuer-side issuance and verifier-side revocation.
use super::*;

const NOW: u64 = 1_800_000_000_000;

fn request(role: Role, issuer: &str, value: u64, holder: &SigningKey) -> IssueRequest {
    IssueRequest {
        role,
        issuer: issuer.into(),
        tenant: "horizon-demo".into(),
        subject: "claim-001".into(),
        holder_public_key_hex: hex::encode(holder.verifying_key().to_bytes()),
        valid_from_ms: NOW,
        valid_until_ms: NOW + 3_600_000,
        value,
    }
}

/// Refusal code of an issuer or prover call whose success type deliberately has no Debug (secrets).
fn refused<T>(result: Result<T>) -> String {
    match result {
        Ok(_) => panic!("expected a refusal"),
        Err(error) => error.to_string(),
    }
}

fn secret(key: &SigningKey) -> String {
    hex::encode(key.to_bytes())
}

/// Two separate authorities issue; the holder assembles the pair and proves against the fixture's challenge/policy.
fn issued_fixture(amount: u64, cap: u64) -> (Fixture, SigningKey, SigningKey) {
    let mut f = Fixture::generate(NOW).unwrap();
    let expert = SigningKey::generate(&mut OsRng);
    let delegation = SigningKey::generate(&mut OsRng);
    let holder = SigningKey::from_bytes(&decode(&f.holder_secret_hex).unwrap());
    let a = issue(
        &request(Role::Amount, "expert", amount, &holder),
        &secret(&expert),
    )
    .unwrap();
    let c = issue(
        &request(Role::Cap, "delegation", cap, &holder),
        &secret(&delegation),
    )
    .unwrap();
    f.evidence = EvidencePair {
        amount: a.evidence,
        cap: c.evidence,
    };
    f.witness = PrivateWitness {
        amount: a.opening.value,
        cap: c.opening.value,
        amount_blinding_hex: a.opening.blinding_hex,
        cap_blinding_hex: c.opening.blinding_hex,
    };
    f.trust = TrustRegistry {
        epoch: 1,
        amount_issuer: IssuerKey {
            issuer: "expert".into(),
            public_key_hex: hex::encode(expert.verifying_key().to_bytes()),
        },
        cap_issuer: IssuerKey {
            issuer: "delegation".into(),
            public_key_hex: hex::encode(delegation.verifying_key().to_bytes()),
        },
        revoked_public_keys_hex: Vec::new(),
    };
    (f, expert, delegation)
}

fn authorize(f: &Fixture) -> Result<Verified> {
    let p = prove(&f.evidence, &f.witness, &f.holder_secret_hex, &f.challenge)?;
    verify(&p, &f.challenge, &f.trust, &f.policy, NOW)
}

#[test]
fn separately_issued_attestations_open_and_verify_within_the_relation() {
    for (amount, cap) in [(1, 1), (125_000, 250_000), (RANGE, 2 * RANGE - 1)] {
        let (f, _, _) = issued_fixture(amount, cap);
        assert!(authorize(&f).is_ok(), "{amount}/{cap}");
        let serialized = serde_json::to_string(&f.evidence).unwrap();
        assert!(!serialized.contains("blinding"));
        if amount >= 1_000 {
            assert!(!serialized.contains(&amount.to_string()));
        }
    }
    // Reusable path on issued attestations.
    let (mut f, _, _) = issued_fixture(125_000, 250_000);
    let prepared = prepare(&f.evidence, &f.witness).unwrap();
    f.challenge.method = Method::Reusable;
    let p = present_reusable(&f.evidence, &prepared, &f.holder_secret_hex, &f.challenge).unwrap();
    assert!(verify(&p, &f.challenge, &f.trust, &f.policy, NOW).is_ok());
}

#[test]
fn issuance_refuses_out_of_domain_values_bad_labels_times_and_holder_keys() {
    let signer = SigningKey::generate(&mut OsRng);
    let holder = SigningKey::generate(&mut OsRng);
    for (role, value) in [
        (Role::Amount, 0),
        (Role::Amount, RANGE + 1),
        (Role::Amount, u64::MAX),
        (Role::Cap, 0),
        (Role::Cap, 2 * RANGE),
    ] {
        assert_eq!(
            refused(issue(
                &request(role, "expert", value, &holder),
                &secret(&signer)
            )),
            "VALUE_OUT_OF_DOMAIN",
            "{role:?} {value}"
        );
    }
    // The cap domain is wider than the amount domain: the same value is role-dependent.
    assert!(issue(
        &request(Role::Cap, "delegation", RANGE + 1, &holder),
        &secret(&signer)
    )
    .is_ok());
    assert!(issue(
        &request(Role::Amount, "expert", RANGE + 1, &holder),
        &secret(&signer)
    )
    .is_err());
    let mut r = request(Role::Amount, "expert", 10, &holder);
    r.valid_until_ms = r.valid_from_ms;
    assert_eq!(refused(issue(&r, &secret(&signer))), "EVIDENCE_TIME");
    let mut r = request(Role::Amount, "expert", 10, &holder);
    r.subject = "claim 001".into();
    assert_eq!(refused(issue(&r, &secret(&signer))), "INVALID_LABEL");
    let mut r = request(Role::Amount, "expert", 10, &holder);
    r.holder_public_key_hex = "00".repeat(32);
    assert_eq!(refused(issue(&r, &secret(&signer))), "WEAK_KEY");
    assert!(issue(&request(Role::Amount, "expert", 10, &holder), "zz").is_err());
    // Two issuances of the same fact never share a blinding or a commitment.
    let one = issue(
        &request(Role::Amount, "expert", 10, &holder),
        &secret(&signer),
    )
    .unwrap();
    let two = issue(
        &request(Role::Amount, "expert", 10, &holder),
        &secret(&signer),
    )
    .unwrap();
    assert_ne!(one.opening.blinding_hex, two.opening.blinding_hex);
    assert_ne!(
        one.evidence.body.commitment_hex,
        two.evidence.body.commitment_hex
    );
}

#[test]
fn substituted_source_wrong_role_other_case_and_mixed_pair_are_refused() {
    let (f, expert, delegation) = issued_fixture(125_000, 250_000);
    let holder = SigningKey::from_bytes(&decode(&f.holder_secret_hex).unwrap());
    let refusal = |g: &Fixture| authorize(g).unwrap_err().to_string();

    // Substituted source: an unregistered authority signs the amount.
    let mut g = f.clone();
    let intruder = SigningKey::generate(&mut OsRng);
    let a = issue(
        &request(Role::Amount, "expert", 125_000, &holder),
        &secret(&intruder),
    )
    .unwrap();
    g.evidence.amount = a.evidence;
    g.witness.amount_blinding_hex = a.opening.blinding_hex;
    assert_eq!(refusal(&g), "INVALID_SIGNATURE");

    // Wrong role: the registered cap authority issues the amount under its own name.
    let mut g = f.clone();
    let a = issue(
        &request(Role::Amount, "delegation", 125_000, &holder),
        &secret(&delegation),
    )
    .unwrap();
    g.evidence.amount = a.evidence;
    g.witness.amount_blinding_hex = a.opening.blinding_hex;
    assert_eq!(refusal(&g), "DISTINCT_AUTHORITIES_REQUIRED");
    // ... or the registered expert key signs a cap role body.
    let mut g = f.clone();
    let c = issue(
        &request(Role::Cap, "delegation", 250_000, &holder),
        &secret(&expert),
    )
    .unwrap();
    g.evidence.cap = c.evidence;
    g.witness.cap_blinding_hex = c.opening.blinding_hex;
    assert_eq!(refusal(&g), "INVALID_SIGNATURE");

    // Other case: both attestations consistently name claim-002.
    let mut g = f.clone();
    let mut ra = request(Role::Amount, "expert", 125_000, &holder);
    ra.subject = "claim-002".into();
    let mut rc = request(Role::Cap, "delegation", 250_000, &holder);
    rc.subject = "claim-002".into();
    let a = issue(&ra, &secret(&expert)).unwrap();
    let c = issue(&rc, &secret(&delegation)).unwrap();
    g.evidence = EvidencePair {
        amount: a.evidence,
        cap: c.evidence,
    };
    g.witness.amount_blinding_hex = a.opening.blinding_hex;
    g.witness.cap_blinding_hex = c.opening.blinding_hex;
    assert_eq!(refusal(&g), "SUBJECT_MISMATCH");

    // Mixed pair: amount for claim-001, cap for claim-002.
    let mut g = f.clone();
    let c = issue(&rc, &secret(&delegation)).unwrap();
    g.evidence.cap = c.evidence;
    g.witness.cap_blinding_hex = c.opening.blinding_hex;
    assert_eq!(
        refused(prove(
            &g.evidence,
            &g.witness,
            &g.holder_secret_hex,
            &g.challenge
        )),
        "EVIDENCE_JOIN"
    );

    // Another holder: the attestations name a holder key the prover does not hold.
    let mut g = f.clone();
    let other_holder = SigningKey::generate(&mut OsRng);
    let a = issue(
        &request(Role::Amount, "expert", 125_000, &other_holder),
        &secret(&expert),
    )
    .unwrap();
    let c = issue(
        &request(Role::Cap, "delegation", 250_000, &other_holder),
        &secret(&delegation),
    )
    .unwrap();
    g.evidence = EvidencePair {
        amount: a.evidence,
        cap: c.evidence,
    };
    g.witness.amount_blinding_hex = a.opening.blinding_hex;
    g.witness.cap_blinding_hex = c.opening.blinding_hex;
    assert_eq!(
        refused(prove(
            &g.evidence,
            &g.witness,
            &g.holder_secret_hex,
            &g.challenge
        )),
        "HOLDER_KEY"
    );
}

#[test]
fn revoked_issuer_key_is_refused_before_signatures_and_old_registries_still_parse() {
    let (f, expert, _) = issued_fixture(125_000, 250_000);
    let p = prove(&f.evidence, &f.witness, &f.holder_secret_hex, &f.challenge).unwrap();
    assert!(verify(&p, &f.challenge, &f.trust, &f.policy, NOW).is_ok());

    let mut trust = f.trust.clone();
    trust.revoked_public_keys_hex = vec![hex::encode(expert.verifying_key().to_bytes())];
    assert_eq!(
        verify(&p, &f.challenge, &trust, &f.policy, NOW)
            .unwrap_err()
            .to_string(),
        "REVOKED_ISSUER_KEY"
    );
    // Revoking an unrelated key changes nothing; revoking the cap key is caught too.
    let mut trust = f.trust.clone();
    trust.revoked_public_keys_hex = vec!["ab".repeat(32)];
    assert!(verify(&p, &f.challenge, &trust, &f.policy, NOW).is_ok());
    let mut trust = f.trust.clone();
    trust.revoked_public_keys_hex = vec![trust.cap_issuer.public_key_hex.clone()];
    assert_eq!(
        verify(&p, &f.challenge, &trust, &f.policy, NOW)
            .unwrap_err()
            .to_string(),
        "REVOKED_ISSUER_KEY"
    );

    // Wire compatibility: a registry serialized before the field existed parses with no revocation,
    // an empty list is omitted on output, a populated list round-trips.
    let legacy = serde_json::json!({
        "epoch": 1,
        "amount_issuer": { "issuer": "expert", "public_key_hex": f.trust.amount_issuer.public_key_hex },
        "cap_issuer": { "issuer": "delegation", "public_key_hex": f.trust.cap_issuer.public_key_hex }
    });
    let parsed: TrustRegistry = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(parsed, f.trust);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), legacy);
    let mut populated = f.trust.clone();
    populated.revoked_public_keys_hex = vec!["cd".repeat(32)];
    let round_trip: TrustRegistry =
        serde_json::from_str(&serde_json::to_string(&populated).unwrap()).unwrap();
    assert_eq!(round_trip, populated);
    // The historical public fixture (no revocation field) must keep verifying through this type.
    let fixture = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/fixtures/horizon/public-presentation.json"
    ))
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(&fixture).unwrap();
    let historic: TrustRegistry = serde_json::from_value(value["trust"].clone()).unwrap();
    assert!(historic.revoked_public_keys_hex.is_empty());
}

#[test]
fn revocation_list_entries_must_be_canonical_lowercase_hex() {
    let (f, expert, _) = issued_fixture(125_000, 250_000);
    let p = prove(&f.evidence, &f.witness, &f.holder_secret_hex, &f.challenge).unwrap();
    let mut trust = f.trust.clone();
    trust.revoked_public_keys_hex =
        vec![hex::encode(expert.verifying_key().to_bytes()).to_uppercase()];
    assert_eq!(
        verify(&p, &f.challenge, &trust, &f.policy, NOW)
            .unwrap_err()
            .to_string(),
        "NONCANONICAL_HEX"
    );
    trust.revoked_public_keys_hex = vec!["ab".repeat(31)];
    assert_eq!(
        verify(&p, &f.challenge, &trust, &f.policy, NOW)
            .unwrap_err()
            .to_string(),
        "ENCODING_LENGTH"
    );
}
