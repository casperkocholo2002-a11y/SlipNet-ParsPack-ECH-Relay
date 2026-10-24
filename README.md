# SlipNet ParsPack ECH Relay

Fail-closed Rust WebSocket relay for the ParsPack -> Cloudflare leg of SlipNet.

## Security contract

- TLS 1.3 only for the ECH connection.
- ECH is mandatory. If ECH is unavailable, rejected, or incompatible, the upstream connection fails.
- No fallback to ordinary TLS with plaintext SNI.
- Worker DNS resolution and HTTPS/ECH discovery use DNS-over-HTTPS.
- No UUID, origin token, or other SlipNet secret is required by this relay.

## Required environment

```text
PORT=8080
PUBLIC_RELAY_PATH=/your-public-parspack-path
WORKER_HOST=your-worker.workers.dev
WORKER_PATH=/your-worker-path
WORKER_PORT=443
ECH_MODE=hard
CONNECT_TIMEOUT_MS=6000
MAX_MESSAGE_BYTES=67108864
RUST_LOG=info
```

`PUBLIC_RELAY_PATH` and `WORKER_PATH` must start with a single slash.

## Health

```text
GET /health
```

Returns service state only. It intentionally does not expose secrets, Worker paths, or ECH configuration material.

## Local validation

```bash
cargo fmt --check
cargo check --locked
cargo test --locked
cargo clippy --locked -- -D warnings
```

## Zero-downtime rollout rule

Deploy and validate this repository on a separate ParsPack canary app first. Do not change any active SlipNet route during canary validation.

After ECH, WebSocket, VLESS E2E, reconnect, and regression tests pass, deploy the same source to the existing ParsPack applications while keeping their existing public hostnames and public relay paths. This preserves existing user configurations.

## Observability

A successful upstream connection logs:

```text
upstream ECH WebSocket established ... ech="accepted"
```

If ECH is not accepted, the session is rejected. There is no insecure fallback.
