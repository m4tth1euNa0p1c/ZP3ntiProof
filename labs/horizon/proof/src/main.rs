//! One request/response per JSON line. No stdout diagnostics or implicit clock.
use anyhow::Result;
use horizon_proof::{
    Challenge, EvidencePair, Fixture, IssueRequest, Presentation, PrivateWitness, ReusableProof,
    TrustRegistry, VerificationPolicy, MAX_INPUT_BYTES,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Init {
        now_ms: u64,
    },
    Prepare {
        evidence: EvidencePair,
        witness: PrivateWitness,
    },
    Present {
        evidence: EvidencePair,
        prepared: ReusableProof,
        holder_secret_hex: String,
        challenge: Challenge,
    },
    Prove {
        evidence: EvidencePair,
        witness: PrivateWitness,
        holder_secret_hex: String,
        challenge: Challenge,
    },
    Verify {
        presentation: Box<Presentation>,
        expected: Challenge,
        trust: TrustRegistry,
        policy: VerificationPolicy,
        now_ms: u64,
    },
    Select {
        policy: VerificationPolicy,
    },
    /// H13 issuer-side operation: the issuer secret never leaves the issuer's process.
    Issue {
        request: IssueRequest,
        issuer_secret_hex: String,
    },
}

fn process(bytes: &[u8]) -> Result<Value> {
    Ok(match serde_json::from_slice::<Request>(bytes)? {
        Request::Init { now_ms } => serde_json::to_value(Fixture::generate(now_ms)?)?,
        Request::Prepare { evidence, witness } => {
            serde_json::to_value(horizon_proof::prepare(&evidence, &witness)?)?
        }
        Request::Present {
            evidence,
            prepared,
            holder_secret_hex,
            challenge,
        } => serde_json::to_value(horizon_proof::present_reusable(
            &evidence,
            &prepared,
            &holder_secret_hex,
            &challenge,
        )?)?,
        Request::Prove {
            evidence,
            witness,
            holder_secret_hex,
            challenge,
        } => serde_json::to_value(horizon_proof::prove(
            &evidence,
            &witness,
            &holder_secret_hex,
            &challenge,
        )?)?,
        Request::Verify {
            presentation,
            expected,
            trust,
            policy,
            now_ms,
        } => serde_json::to_value(horizon_proof::verify(
            &presentation,
            &expected,
            &trust,
            &policy,
            now_ms,
        )?)?,
        Request::Select { policy } => serde_json::to_value(horizon_proof::select_method(&policy))?,
        Request::Issue {
            request,
            issuer_secret_hex,
        } => serde_json::to_value(horizon_proof::issue(&request, &issuer_secret_hex)?)?,
    })
}

fn main() -> Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut line = Vec::new();
        let mut oversized = false;
        loop {
            let available = input.fill_buf()?;
            if available.is_empty() {
                break;
            }
            let newline = available.iter().position(|b| *b == b'\n');
            let count = newline.map_or(available.len(), |index| index + 1);
            if line.len() + count > MAX_INPUT_BYTES {
                oversized = true;
            }
            if !oversized {
                line.extend_from_slice(&available[..count]);
            }
            input.consume(count);
            if newline.is_some() {
                break;
            }
        }
        if line.is_empty() && !oversized {
            break;
        }
        let response = if oversized {
            json!({"ok":false,"error":"INPUT_TOO_LARGE"})
        } else {
            match process(&line) {
                Ok(result) => json!({"ok":true,"result":result}),
                Err(error) => json!({"ok":false,"error":format!("{error:#}")}),
            }
        };
        serde_json::to_writer(&mut output, &response)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    Ok(())
}
