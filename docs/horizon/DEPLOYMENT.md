# Local demonstrator

Prerequisites: Node 24.11.1+, Rust 1.93.0 with Cargo, npm, Linux Docker for Compose.
The root pins Rust 1.93.0; the Linux experiments use the Rust 1.98.0 image
pinned by digest. Clone the research branch, then, from the root:

```sh
npm ci --ignore-scripts
npm run horizon:build
npm run test:horizon
npm run horizon:demo
```

`horizon:demo` creates an independent synthetic scenario, generates a real
proof, tests refusal and admission, then stops its processes. Its target is a
new local database, with no financial operation. Local artifacts are kept; the
script refuses an additional effect in each scenario.

## Persistent web application

```sh
npm run horizon:init
docker compose -f deploy/horizon/compose.yaml up -d --build --wait
```

On Linux with a non-root user, set `export HORIZON_PROVER_UID=$(id -u)` before
Compose. The provider then reads the `0600` private file with the identity of
its owner. The verifier remains UID 1000, with its own volume; only
`public.json`, without witness or private key, is `0644`. On Windows/Docker
Desktop, the default value 1000 is suitable for the mount.

Open **http://127.0.0.1:38080**. The provider answers on port 38081. The local
relay fixes both destinations; only its loopback ports are published. The
provider and verifier processes are on an internal Docker network. The relay
owns no private configuration, no keys and no database.

The interface allows challenge, presentation, verification before synthetic
action, tampering, replay and reading of the state. Operator controls are
disabled in the browser. Revocation and consumption are persistent. A consumed
operation remains refused after a restart:

```sh
node scripts/horizon-http-smoke.mjs
docker compose -f deploy/horizon/compose.yaml restart
node scripts/horizon-http-smoke.mjs replay
```

The first smoke requires an empty database and consumes the action; the second
verifies the refusal on that same database. Do not rerun the first on an
already-consumed scenario. No reset/unrevoke endpoint is provided. Stop without
erasing:

```sh
docker compose -f deploy/horizon/compose.yaml stop
```

Configurations are in `.tools/horizon/demo`, ignored by Git and excluded from
the build context. The prover sees only `private.json`. The verifier sees only
`public.json` and the SQLite volume. Fixture attestations expire after **one
hour**, challenges after at most **30 seconds**. After expiration, a new
experiment requires a new configuration directory and a new, explicitly
distinct sandbox target. Keep the old databases; never implicitly reset an
authorization state.

An alternative without Docker is `npm run horizon:serve`, after stopping the
services that occupy the same ports. It uses two processes and a distinct host
SQLite target. These independent databases represent distinct experiments, not
a coordination solution between verifiers of the same real target.

## CLI and library

The Rust worker processes JSONL, one result per line. Example of public
verification, with an explicit historical time and no action admission:

```sh
node scripts/horizon-fixture.mjs verify
node scripts/horizon.mjs request tests/fixtures/horizon/public-presentation.json
```

Operations: `init`, `prepare`, `prove`, `present`, `verify`, `select`.
`init` generates synthetic secrets: use the initialization script, which writes
them to local files, not to shared logs. Strict signatures and encodings are
documented in [the library](../../labs/horizon/proof/README.md).
The Rust API and the TypeScript types constitute the laboratory's interfaces;
no additional production banking/MCP SDK is claimed to be delivered.

## Reproducing the measurements

```sh
npm run horizon:benchmark
node scripts/horizon-firewall-benchmark.mjs --samples 500 --warmup 30
node scripts/horizon-vega.mjs
```

The native runner produces a timestamped raw file and a summary without
overwriting old results. Vega creates a dedicated reference container, compiles
with network access, then disconnects it before measuring; it keeps it stopped
at the end. The before/after details are in [EXPERIMENT_LOG](EXPERIMENT_LOG.md).
The full execution of the Criterion benches takes several minutes. It does not
reproduce the credential circuit absent from the public repository.

## Operating boundary

Compose enforces a non-root user, read-only rootfs, CPU/RAM/PID limits, no
Linux capabilities and no privilege escalation. HTTP is local, without banking
IAM and without TLS. The four operator routes (`/api/revoke`,
`/api/rotate-policy`, `/api/reconcile`, `/api/revoke-key` since 25 October 2026) refuse any request by default with
HTTP 403. A separately configured operator server can provide
`HORIZON_OPERATOR_TOKEN` (32 random bytes encoded as 64 lowercase hexadecimal
characters); the client must provide `x-horizon-operator-token`. The comparison
is constant-time, after validation of the encoding. Tests cover refusals
without mutation and authenticated operations. This local shared secret is not
a qualified IAM.

Compose configures no token and the relay does not forward this header. The
browser and the MCP tools never receive this secret. Do not place it in a URL,
public JavaScript, a log or a manifest. A future operator channel requires
identity, roles, TLS, secret management and suitable audit; no cloud activation
is included in this demonstrator.

Do not open these ports to a corporate network. The application has no
financial connector and uses no customer data. Limits and qualification work
are in [THREAT_MODEL](THREAT_MODEL.md) and the [tickets](../../issues/horizon/NEXT_EXPERIMENTS.md).

## Optional remote sandbox target (H14, 25 October 2026)

The verifier records locally by default. To exercise the separated-target
path, start the sandbox target process and point the verifier at it:

```sh
PORT=38082 HORIZON_TARGET_DB=.tools/horizon/demo/target.sqlite node packages/horizon-demo/dist/target.js
HORIZON_TARGET_URL=http://127.0.0.1:38082 node packages/horizon-demo/dist/server.js verifier .tools/horizon/demo/public.json
```

The target has no authentication and binds to loopback; it is a laboratory
stand-in for a remote API with an idempotency key, an exact version
precondition, a status route and a fence. `/api/reconcile` (operator token
required) fences the operation at the target and never redispatches. The
Compose deployment is unchanged and keeps the local target. See
[REMOTE_TARGET_2026-10-25.md](REMOTE_TARGET_2026-10-25.md).
