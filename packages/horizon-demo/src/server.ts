import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { AuthorizationStore } from './store.js';
import { ProofWorker } from './worker.js';
import { RemoteTarget } from './target.js';
import { Challenge, PrivateConfig, PublicConfig, selectMethod } from './types.js';
import { createClaimTool } from './tool.js';

const MAX_BODY = 65535;
function send(response: ServerResponse, status: number, value: unknown): void {
  response.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  response.end(JSON.stringify(value));
}
async function body(request: IncomingMessage): Promise<unknown> {
  if (request.headers['content-type'] !== 'application/json') throw new Error('CONTENT_TYPE');
  const chunks: Buffer[] = []; let bytes = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    bytes += buffer.length; if (bytes > MAX_BODY) throw new Error('BODY_TOO_LARGE');
    chunks.push(buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
}
export interface ServerOptions {
  role: 'prover' | 'verifier'; configPath: string; databasePath?: string;
  binary?: string; origin: string; clock?: () => number;
  /** Optional 32-byte hexadecimal operator secret; operator routes fail closed without it. */
  operatorToken?: string;
  /** Optional H14 remote sandbox target URL (verifier only). Without it the store records locally. */
  targetUrl?: string;
}

/** Two separate processes/configurations. Only the verifier process can mutate its SQLite target. */
export function createHorizonServer(options: ServerOptions) {
  const clock = options.clock ?? Date.now;
  const parsed: unknown = JSON.parse(readFileSync(options.configPath, 'utf8'));
  const privateConfig = options.role === 'prover' ? PrivateConfig.parse(parsed) : undefined;
  const publicConfig = options.role === 'verifier' ? PublicConfig.parse(parsed) : undefined;
  const target = publicConfig && options.targetUrl ? new RemoteTarget(options.targetUrl) : undefined;
  const store = publicConfig ? new AuthorizationStore(options.databasePath ?? 'horizon.sqlite', publicConfig, clock) : undefined;
  const worker = new ProofWorker(options.binary);
  let tool: ReturnType<typeof createClaimTool> | undefined;
  try { tool = store && publicConfig ? createClaimTool(store, worker, publicConfig, clock, target) : undefined; }
  catch (error) { worker.close(); store?.close(); throw error; }
  let prepared: unknown;
  let preparation: Promise<unknown> | undefined;
  let inFlight = 0;
  const operatorToken = options.operatorToken ?? process.env['HORIZON_OPERATOR_TOKEN'] ?? '';
  const operatorRoutes = new Set(['/api/revoke', '/api/rotate-policy', '/api/reconcile', '/api/revoke-key']);
  const server = createServer(async (request, response) => {
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('Content-Security-Policy', `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' ${options.origin.replace(/38080$/, '38081')}; frame-ancestors 'none'; base-uri 'none'`);
    const origin = request.headers.origin;
    if (origin && origin !== options.origin) return send(response, 403, { error: 'ORIGIN_REJECTED' });
    if (origin) response.setHeader('Access-Control-Allow-Origin', options.origin);
    // CORS and loopback are not operator authentication. Deny mutation endpoints by default.
    if (operatorRoutes.has(request.url ?? '')) {
      const supplied = request.headers['x-horizon-operator-token'];
      const valid = typeof supplied === 'string' && /^[0-9a-f]{64}$/.test(operatorToken)
        && /^[0-9a-f]{64}$/.test(supplied)
        && timingSafeEqual(Buffer.from(operatorToken, 'hex'), Buffer.from(supplied, 'hex'));
      if (!valid) return send(response, 403, { error: 'OPERATOR_AUTH_REQUIRED' });
    }
    if (request.method === 'OPTIONS') {
      response.setHeader('Access-Control-Allow-Methods', 'POST,GET');
      response.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      response.writeHead(204); response.end(); return;
    }
    if (++inFlight > 8) { inFlight--; return send(response, 429, { error: 'CAPACITY_REACHED' }); }
    try {
      if (request.method === 'GET' && request.url === '/health') return send(response, 200, { role: options.role, sandbox: true });
      if (request.method === 'GET' && publicConfig && ['/', '/app.js', '/style.css'].includes(request.url ?? '')) {
        const resource = request.url === '/' ? 'index.html' : request.url?.slice(1);
        const type = resource === 'index.html' ? 'text/html' : resource === 'app.js' ? 'text/javascript' : 'text/css';
        response.writeHead(200, { 'Content-Type': `${type}; charset=utf-8`, 'Cache-Control': 'no-store' });
        response.end(readFileSync(fileURLToPath(new URL(`../public/${resource}`, import.meta.url)))); return;
      }
      if (request.method === 'GET' && request.url === '/api/state' && store) return send(response, 200, store.snapshot());
      if (request.method !== 'POST') return send(response, 404, { error: 'NOT_FOUND' });
      const input = await body(request);
      if (request.url === '/api/prove' && privateConfig) {
        const { challenge } = z.strictObject({ challenge: Challenge }).parse(input);
        if (challenge.method !== selectMethod(privateConfig.policy)
          || challenge.policy_id !== privateConfig.policy.policy_id
          || challenge.policy_epoch !== privateConfig.policy.policy_epoch
          || challenge.client_id !== privateConfig.client_id
          || challenge.audience !== privateConfig.audience
          || challenge.action !== privateConfig.action) throw new Error('SUPPLIER_POLICY');
        let presentation: unknown;
        if (challenge.method === 'reusable') {
          if (prepared === undefined) {
            preparation ??= worker.request({ op: 'prepare', evidence: privateConfig.evidence, witness: privateConfig.witness });
            try { prepared = await preparation; } catch (error) { preparation = undefined; throw error; }
          }
          presentation = await worker.request({ op: 'present', evidence: privateConfig.evidence, prepared,
            holder_secret_hex: privateConfig.holder_secret_hex, challenge });
        } else {
          presentation = await worker.request({ op: 'prove', evidence: privateConfig.evidence,
            witness: privateConfig.witness, holder_secret_hex: privateConfig.holder_secret_hex, challenge });
        }
        return send(response, 200, { presentation });
      }
      if (!store || !publicConfig || !tool) return send(response, 404, { error: 'NOT_FOUND' });
      if (request.url === '/api/challenge') {
        return send(response, 200, { challenge: await tool.issue(input) });
      }
      if (request.url === '/api/execute') {
        const outcome = await tool.execute(input);
        return send(response, outcome.status === 'COMPLETED' ? 200 : 409, outcome);
      }
      // These are explicit sandbox operator controls, absent from the MCP agent toolset.
      if (request.url === '/api/revoke') { z.strictObject({}).parse(input); store.revoke(); return send(response, 200, { revoked: true }); }
      if (request.url === '/api/rotate-policy') { z.strictObject({}).parse(input); store.rotatePolicy(); return send(response, 200, { rotated: true }); }
      if (request.url === '/api/revoke-key') {
        const { public_key_hex } = z.strictObject({ public_key_hex: z.string().regex(/^[0-9a-f]{64}$/) }).parse(input);
        store.revokeIssuerKey(public_key_hex); return send(response, 200, { revoked_key: public_key_hex, trust_epoch: store.state().trust_epoch });
      }
      if (request.url === '/api/reconcile') {
        const { operation_id } = z.strictObject({ operation_id: z.string().regex(/^[0-9a-f]{64}$/) }).parse(input);
        return send(response, 200, { status: target ? await store.reconcileWith(target, operation_id) : store.reconcile(operation_id) });
      }
      send(response, 404, { error: 'NOT_FOUND' });
    } catch { if (!response.headersSent) send(response, 400, { error: 'REQUEST_REJECTED',
      authorization_result: 'rejected_or_unknown', reconciliation_required_before_retry: true }); }
    finally { inFlight--; }
  });
  server.requestTimeout = 10000; server.headersTimeout = 5000; server.maxRequestsPerSocket = 100;
  return { server, store, close: async () => { worker.close(); await new Promise<void>(resolve => server.close(() => resolve())); store?.close(); } };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const role = z.enum(['prover', 'verifier']).parse(process.argv[2]);
  const configPath = process.argv[3]; if (!configPath) throw new Error('CONFIG_REQUIRED');
  const app = createHorizonServer({ role, configPath,
    databasePath: process.env['HORIZON_DB'] ?? '.tools/horizon/demo/authorization.sqlite',
    origin: process.env['HORIZON_ORIGIN'] ?? 'http://127.0.0.1:38080',
    ...(process.env['HORIZON_TARGET_URL'] ? { targetUrl: process.env['HORIZON_TARGET_URL'] } : {}) });
  const port = Number(process.env['PORT'] ?? (role === 'prover' ? 38081 : 38080));
  app.server.listen(port, process.env['HORIZON_BIND'] ?? '127.0.0.1', () => process.stdout.write(`Horizon ${role} sandbox on port ${port}\n`));
  for (const signal of ['SIGTERM', 'SIGINT'] as const) process.once(signal, () => { void app.close().then(() => process.exit(0)); });
}
