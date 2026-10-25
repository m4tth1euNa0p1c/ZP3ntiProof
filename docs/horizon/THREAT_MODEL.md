# Horizon threat model

Profile `horizon-range-v1`, laboratory for controlling a claims authorization.
The relation is defined in [FORMAL_STATEMENT](FORMAL_STATEMENT.md). No payment.

## Assets and boundaries

Amounts and Pedersen openings are private to the provider. Authorities' private
keys are used only for synthetic issuance; the holder key stays with the prover.
The verifying client receives only public attestations, approved public keys
and presentations. Its controller alone holds the simulated-action database.
A proof does not grant access to a mutation credential.

The agent, transport and presentations are potentially hostile: substitution,
omission, replay, method changes and arbitrary prompts. The verifier, its
configuration, binary, storage and operating system are trusted. Compromising
this boundary allows rules to be changed or writes to the target; ZK does not
protect against such a compromise.

Authorities are trusted for factual truth, units and issuance from known values.
A signer signing a lie can produce an authentic but false attestation. The proof
checks the relation over what is attested, not the reality of the claim. Here,
the prover knows both values: this is not a multiparty computation in which
each source retains its witness.

## Attacks and observable controls

| Attack | Control | Limitation |
| --- | --- | --- |
| Hallucination/injection requesting a different action | Server-issued expectations, fully signed context and transcript A | The agent receives no financial API |
| Fake proof or signature | Dalek/Bulletproofs verification, canonical scalars, pinned keys | No external cryptographic audit performed |
| Source substitution or omission | Two mandatory roles, signatures and joins, exact configured evidence | Real issuance not connected |
| Forced disclosure | Local provider and client policies; no weakening through HTTP selection | An explicitly public policy permits the disclosed baseline |
| Replay/concurrency/new challenge | Nonce consumed and business operation reserved under `BEGIN IMMEDIATE` | No cross-region consensus |
| Revocation/policy/expiration during proving | Reread after waiting and after reservation; start/end bounds checked | Trusted clock and revocation source; no secure clock |
| Shutdown after reservation | SQLite WAL/FULL, persistent reserved state, no automatic retry | Durability depends on storage and its actual guarantees |
| Unknown target response | `UNKNOWN` remains consumed; read-only reconciliation before a decision | No exactly-once promise for a remote target |
| Saturation | 64 KiB bodies, queue/HTTP 8, 30 s worker timeout, 10,000 challenges, Docker limits | Local controls, not certified DDoS protection |
| Wrong tenant | Bound attestations/context; database pinned to its configuration | One configuration/instance per tenant; no qualified multi-tenant SaaS |

The clock-rollback test covers a challenge before attestation validity starts,
verification within the validity interval, then dispatch before its start.
It requires zero effects. It is not general protection against an attacker-controlled clock.

## Confidentiality and cryptographic assumptions

Bulletproofs/Ristretto relies on discrete-log assumptions and the Fiat–Shamir
transcript model; Ed25519 is a classical signature. No profile in this experiment
is post-quantum. Standard generators are fixed in the code, with no toxic-secret
trusted setup.

The profile reveals identifiers, tenant, currency, unit, versions, keys, dates,
commitments, action and verdict. Reusing commitments and the holder key makes
presentations linkable. A reused proof is itself a stable identifier. No
anonymity or unlinkability. Secrets are not erased from RAM with qualified
guarantees; side channels and dump resistance have not been evaluated. Non-ZK
mode intentionally discloses values and openings.

## Deployment and compliance

The demonstration HTTP routes, with no user authentication, are restricted to
loopback and fictitious organizations. The four operator routes (`/api/revoke`,
`/api/rotate-policy`, `/api/reconcile`, `/api/revoke-key` since 25 October 2026) now require a server-configured secret;
they fail closed when it is absent. Compose does not configure it and the
browser does not receive it. A local shared secret is not banking IAM. See the
[dated operator tests](../publication/OPERATOR_VALIDATION_2026-10-17.json).
Operator revocation routes must not be exposed as agent tools. CORS/CSP do not
replace authentication. Industrialization requires mTLS/IAM, role separation,
HSM/KMS, controlled origins, rotation/revocation, tested backups, external audit
and a migration policy. The requirement-by-requirement state, with what has
been exercised and what has not, is in the
[production threat model of 25 October 2026](../publication/PRODUCTION_THREAT_MODEL_2026-10-25.md);
its verdict is NO-GO until the listed experiments are run.

DORA, GDPR, the AI Act and sector obligations do not follow from a proof.
Linkability and metadata may constitute personal data. This POC establishes no
legal opinion, certification or regulatory compliance. The texts and their scope
are referenced in [MARKET_DISCOVERY](MARKET_DISCOVERY.md).
