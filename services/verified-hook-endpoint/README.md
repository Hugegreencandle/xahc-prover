# Verified-Hook endpoint

A small, **read-only** HTTP service that surfaces the xahc-prover **Proof Registry** to the
public: given an on-chain Xahau **HookHash**, it answers *"what has been PROVEN about this
hook — which invariants, signed by whom, with what stated residual?"* — **without re-running
the prover**.

It is the public face of the fifth leg of the toolchain:
**write → simulate → prove → watch → REGISTER → (serve)**.

## What it is (and is not)

- It **imports the existing registry** (`src/registry`, the `status_of` verb behind `get`/`check`)
  and passes that verdict through verbatim. It does **not** re-implement, re-derive, or
  re-judge any proof.
- **Honest semantics — this is the product:**
  - `PROVEN` only when the registry reports PROVEN (≥1 intact, optionally-signed PROVEN entry
    for that HookHash). The response lists the proven invariant set, the `signed` flag, and the
    **stated residual** (`scope_caveats`). PROVEN is scoped to *those invariants and that
    residual* — never a blanket "safe".
  - **Absence of a proof is `UNPROVEN`, reported loudly — never "unsafe", never an implicit
    pass.** This service never asserts safety the registry did not establish.
  - A broken hash-chain / bad signature is `TAMPERED`, also surfaced loudly.
  - Any internal error returns **HTTP 500/503** — it never falls back to an optimistic verdict.
    (This layer can only narrow or pass through the registry's verdict; it cannot manufacture a
    PROVEN.)
- **Dependency-light:** Python **stdlib `http.server` only**. No Flask, no async, no DB.
- **Read-only:** `GET`/`HEAD` only. It opens the registry JSONL log read-only and writes nothing.

## Endpoints

| Method | Path                      | Purpose |
|--------|---------------------------|---------|
| `GET`  | `/healthz`                | Liveness + registry reachability + chain integrity. Reveals no proof verdicts. `200 ok`, `503 degraded` (chain broken), `503 error` (registry unreadable). |
| `GET`  | `/verified/<HookHash>`    | Proof status for a 64-hex HookHash. Always `200` with a `status` of `PROVEN` / `UNPROVEN` / `TAMPERED` in the body (a successful *query*). `400` if the HookHash is malformed. |
| `GET`  | `/`                       | Tiny service descriptor (endpoint list + honesty note). |

### `GET /verified/<HookHash>` — response shapes

`<HookHash>` is the on-chain Xahau HookHash: SHA-512Half of the hook bytecode, **64 hex chars**
(case-insensitive; echoed back uppercase).

**PROVEN** (HTTP 200):
```json
{
  "service": "verified-hook-endpoint",
  "hook_hash": "0C83DB48E989A8132CCC26E1934EDEF97BE8CA9EF954C63E9AC01C40CD5528E6",
  "status": "PROVEN",
  "proven": true,
  "invariants": ["limit"],
  "proofs": [{ "invariant": "limit", "prover_args": ["--field", "01:0:8"], "entry": 0 }],
  "signed": false,
  "residual": ["LIM=1000000 drops; spend-limit only"],
  "hook_accounts": ["rSmokeAcct"],
  "entries": [0],
  "chain_ok": true,
  "note": "PROVEN means ... It does NOT mean the hook is safe beyond those invariants and their residual."
}
```

**UNPROVEN** (HTTP 200) — no proof on record (NOT a safety claim):
```json
{
  "service": "verified-hook-endpoint",
  "hook_hash": "AAAA...AAAA",
  "status": "UNPROVEN",
  "proven": false,
  "invariants": [],
  "residual": [],
  "detail": "no proof on record for this HookHash (absence of proof is not safety)",
  "chain_ok": true
}
```

**TAMPERED** (HTTP 200, but loud) — a record exists yet the registry chain/signature failed:
```json
{ "service": "verified-hook-endpoint", "status": "TAMPERED", "proven": false,
  "detail": "registry chain failed to verify: ...", "chain_ok": false }
```

**Malformed HookHash** → HTTP 400. **Internal error** → HTTP 500.

## Local run

From the repo root, with the project venv active (registry is stdlib-only; `cryptography` is
only needed for *signed* registries and key-pinning — the service runs fine unsigned):

```sh
. .venv/bin/activate

# point at your registry log (default: $XAHC_REGISTRY or ./proof-registry.jsonl)
python services/verified-hook-endpoint/app.py \
    --store proof-registry.jsonl \
    --host 127.0.0.1 --port 8787
```

Flags (all also read from env):

| Flag       | Env                  | Default                | Meaning |
|------------|----------------------|------------------------|---------|
| `--host`   | `XAHC_VERIFIED_HOST` | `127.0.0.1`            | Bind address. **Keep loopback** and front with the tunnel/proxy (below). |
| `--port`   | `XAHC_VERIFIED_PORT` | `8787`                 | Bind port. |
| `--store`  | `XAHC_REGISTRY`      | `proof-registry.jsonl` | Path to the registry JSONL log. |
| `--pin`    | `XAHC_VERIFIED_PIN`  | *(none)*               | Require the chain be signed **entirely** by this attester pubkey (hex). Closes the "rebuild the chain under the attacker's own key" gap. Use the pubkey you trust. |

Smoke it:
```sh
curl -s http://127.0.0.1:8787/healthz | python -m json.tool
curl -s http://127.0.0.1:8787/verified/<HookHash> | python -m json.tool
```

> Tip: to populate a test registry, mint a manifest from a proven `.wasm` and register it:
> ```sh
> python -m registry --store proof-registry.jsonl make-manifest hooks/agent_guardrail.wasm \
>     --invariant guardrail --out /tmp/m.json
> python -m registry --store proof-registry.jsonl add /tmp/m.json
> ```
> (`make-manifest` fails closed: a non-PROVEN run cannot produce a manifest.)

## Deploy runbook (Contabo + Kong + Cloudflare) — MANUAL steps

> These are **manual** operator steps for the existing Contabo node (the live verification box
> at `/opt/xahc-prover`, behind the existing Cloudflare tunnel). **Nothing here is automated and
> no host is touched by this repo.** Run each step by hand and verify before moving on.

### 0. Prereqs (on the Contabo box, over the existing SSH access)
- The repo is already at `/opt/xahc-prover` with its `.venv`. Pull the branch carrying this
  service. Confirm Python ≥ 3.10.
- Decide which **registry log** the endpoint serves. Use a **read-only copy or a read-only bind**
  of the canonical `proof-registry.jsonl`; the service never writes, but mounting it read-only
  enforces that at the OS level. Pin the attester pubkey if the registry is signed.

### 1. Run as a service (systemd) — bound to loopback only
Create `/etc/systemd/system/verified-hook.service` (adjust paths/user):
```ini
[Unit]
Description=Verified-Hook proof-status endpoint (read-only registry surface)
After=network.target

[Service]
Type=simple
User=xahc
WorkingDirectory=/opt/xahc-prover
Environment=XAHC_REGISTRY=/opt/xahc-prover/proof-registry.jsonl
# Optional: pin the attester pubkey if the registry is signed
# Environment=XAHC_VERIFIED_PIN=<attester-pubkey-hex>
ExecStart=/opt/xahc-prover/.venv/bin/python services/verified-hook-endpoint/app.py \
    --host 127.0.0.1 --port 8787
Restart=on-failure
# Hardening — it's a read-only service:
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/opt/xahc-prover
# (If the log must be writable elsewhere, it is NOT here — this service only reads.)

[Install]
WantedBy=multi-user.target
```
Then:
```sh
systemctl daemon-reload
systemctl enable --now verified-hook
systemctl status verified-hook
curl -s http://127.0.0.1:8787/healthz       # expect {"status":"ok",...}
```
**Bind loopback only (`127.0.0.1`).** Never expose `:8787` to the public interface — Kong and
the Cloudflare tunnel are the only front doors.

### 2. Kong (API gateway in front of the loopback service)
Register the loopback service + a route, and apply read-only + rate-limit guards. Adjust to
your Kong admin endpoint (declarative `kong.yml` or the Admin API):

```sh
# Service -> the loopback app
curl -s -X POST http://localhost:8001/services \
  --data name=verified-hook \
  --data url=http://127.0.0.1:8787

# Route -> public path prefix
curl -s -X POST http://localhost:8001/services/verified-hook/routes \
  --data 'paths[]=/verified-hook' \
  --data 'methods[]=GET' \
  --data 'methods[]=HEAD' \
  --data strip_path=true

# Guardrails: rate-limit + (defense in depth) only allow GET/HEAD
curl -s -X POST http://localhost:8001/services/verified-hook/plugins \
  --data name=rate-limiting --data config.minute=120 --data config.policy=local

curl -s -X POST http://localhost:8001/services/verified-hook/plugins \
  --data name=request-termination \
  --data config.status_code=405 --data config.message='read-only: GET/HEAD only' \
  # apply this on a separate route scoped to non-GET methods, OR rely on the GET/HEAD-only
  # route above so any other method simply 404s at the gateway.
```
The service itself already rejects non-GET (only `do_GET`/`do_HEAD` are implemented), but
constraining methods at the gateway is the defense-in-depth posture. Smoke through Kong:
```sh
curl -s http://localhost:8000/verified-hook/healthz
```

### 3. Cloudflare tunnel (the existing tunnel — add a hostname/ingress)
The box already runs `cloudflared` with a named tunnel. **Add an ingress rule** pointing a public
hostname at Kong's proxy port (or directly at `127.0.0.1:8787` if you are not fronting with Kong).
Edit the tunnel config (typically `/etc/cloudflared/config.yml`):

```yaml
tunnel: <existing-tunnel-id>
credentials-file: /etc/cloudflared/<existing-tunnel-id>.json

ingress:
  # Verified-Hook endpoint, fronted by Kong on :8000
  - hostname: verified.<your-domain>
    service: http://127.0.0.1:8000
    path: /verified-hook/*
  # ... existing rules ...
  - service: http_status:404
```
Then create the DNS route and restart the tunnel:
```sh
cloudflared tunnel route dns <existing-tunnel-id> verified.<your-domain>
systemctl restart cloudflared
systemctl status cloudflared
```
Public smoke (through Cloudflare → tunnel → Kong → loopback app):
```sh
curl -s https://verified.<your-domain>/verified-hook/healthz | python -m json.tool
curl -s https://verified.<your-domain>/verified-hook/verified/<HookHash> | python -m json.tool
```

### 4. Operational notes
- **Updating proofs:** the registry is append-only. When new proofs are registered, the endpoint
  reflects them on the next request (it reads the log per request — no restart needed).
- **Integrity alarm:** poll `/healthz`. A `503 degraded` with a `chain_break` means the served
  registry no longer verifies — investigate the `proof-registry.jsonl` on the box immediately; the
  endpoint will (correctly) report `TAMPERED` for any hook until the log is restored.
- **Caching:** responses set `Cache-Control: no-store`. If you add Cloudflare/Kong caching, keep
  TTLs short and never cache `TAMPERED`/`degraded` responses, so an integrity break surfaces fast.
- **No write surface:** there is intentionally no endpoint to add/modify proofs here. Registration
  stays on the operator side via `python -m registry add` against the canonical log.
```
