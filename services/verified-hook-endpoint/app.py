"""Verified-Hook endpoint — a small, read-only HTTP wrapper over the Proof Registry.

The public face of the fifth leg (write → simulate → prove → watch → REGISTER): anyone
holding an on-chain HookHash can ask "what has been PROVEN about this hook, under which
invariants, signed by whom, with what stated residual?" — WITHOUT re-running the engine.

This service is deliberately thin and SURFACES the registry; it does NOT re-derive or
re-judge any proof. The only source of truth is `registry.status_of`. In particular:

  • PROVEN is reported only when the registry reports PROVEN — i.e. ≥1 intact (and, if
    pinned, correctly-signed) PROVEN entry exists for that HookHash. We pass the registry's
    verdict through verbatim, including the proven invariant set, signed flag, and the
    stated residual (`scope_caveats`).
  • Absence of a proof is UNPROVEN — reported loudly, as "no proof on record", NEVER as
    "safe". This endpoint never asserts safety the registry did not establish.
  • A broken hash-chain / bad signature is TAMPERED — also surfaced loudly, never hidden.

Soundness posture (mirrors the prover): this layer can only ever *narrow or pass through*
the registry's verdict. It cannot manufacture a PROVEN. Any internal error answers 500 with
an error body — it never falls back to an optimistic "ok".

Dependency-light: Python stdlib `http.server` only. No Flask, no async. Read-only: GET only.

Run:  python services/verified-hook-endpoint/app.py [--store PATH] [--host H] [--port N]
Endpoints:
  GET /healthz              liveness + registry reachability (never reveals proof verdicts)
  GET /verified/<HookHash>  the proof status for an on-chain HookHash (PROVEN/UNPROVEN/TAMPERED)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

# Put the prover's src/ on sys.path exactly like the tests do, so we IMPORT (not reimplement)
# the existing registry. Layout: <repo>/services/verified-hook-endpoint/app.py -> <repo>/src.
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))
_SRC = os.path.join(_REPO, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from registry import registry as R  # noqa: E402  (the ONLY proof-status authority)

# An Xahau HookHash is SHA-512Half (32 bytes) -> 64 hex chars. Accept upper/lower, normalize
# to upper (registry compares case-insensitively but upper is the on-chain canonical form).
_HOOKHASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")

SERVICE = "verified-hook-endpoint"
SERVICE_VERSION = 1


def _public_status(hook_hash: str, store: str, pin_pubkey: str | None) -> tuple[int, dict]:
    """Map the registry verdict for a HookHash to (http_status, body).

    Pure pass-through of `registry.status_of` — this function adds NO judgement of its own;
    it only re-shapes the registry's dict into a stable public payload and never upgrades a
    verdict. PROVEN/UNPROVEN/TAMPERED all return HTTP 200 (a successful *query*); the verdict
    itself lives in the body's `status`. An unknown hook is UNPROVEN, not 404-as-safe.
    """
    out = R.status_of(hook_hash, store, pin_pubkey)
    status = out.get("status")

    body: dict = {
        "service": SERVICE,
        "hook_hash": out.get("hook_hash", hook_hash.upper()),
        "status": status,
        "chain_ok": out.get("chain_ok"),
    }

    if status == R.PROVEN:
        # Surface exactly what the registry established — nothing more.
        body["proven"] = True
        body["invariants"] = out.get("invariants", [])
        body["proofs"] = out.get("proofs", [])               # [{invariant, prover_args, entry}]
        body["signed"] = bool(out.get("signed"))
        body["residual"] = out.get("residual", [])           # stated residual = honesty surface
        body["hook_accounts"] = out.get("hook_accounts", [])
        body["entries"] = out.get("entries", [])
        body["note"] = ("PROVEN means: the listed invariant(s) were proven for this exact "
                        "HookHash and recorded in an intact registry chain. It does NOT mean "
                        "the hook is safe in any sense beyond those invariants and their "
                        "stated residual.")
    elif status == R.UNPROVEN:
        # Absence of a proof is NOT a safety claim. Loud, honest.
        body["proven"] = False
        body["invariants"] = []
        body["residual"] = []
        body["detail"] = out.get("detail",
                                 "no proof on record for this HookHash (absence of proof is not safety)")
        body["note"] = ("UNPROVEN means NO proof is on record for this HookHash. This is NOT a "
                        "statement that the hook is unsafe — only that this registry establishes "
                        "nothing about it.")
    elif status == R.TAMPERED:
        # A record exists but the chain/signature failed. Surfaced loudly, never swallowed.
        body["proven"] = False
        body["invariants"] = []
        body["residual"] = []
        body["detail"] = out.get("detail", "registry chain failed to verify")
        body["note"] = ("TAMPERED means a record exists for this HookHash but the registry's "
                        "integrity check failed; no proof can be trusted from it.")
    else:
        # The registry only ever returns PROVEN/UNPROVEN/TAMPERED. Anything else is an
        # internal contract violation — fail closed, never report an optimistic verdict.
        return 500, {"service": SERVICE, "error": "unexpected registry status",
                     "status": status, "hook_hash": hook_hash.upper()}

    return 200, body


class VerifiedHookHandler(BaseHTTPRequestHandler):
    server_version = f"{SERVICE}/{SERVICE_VERSION}"

    # Injected by make_server (per-process config).
    store: str = R.DEFAULT_STORE
    pin_pubkey: str | None = None

    # ---- helpers -------------------------------------------------------------------------
    def _send_json(self, code: int, body: dict) -> None:
        payload = json.dumps(body, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        # HEAD has no body; GET does.
        if self.command != "HEAD":
            self.wfile.write(payload)

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        # One-line access log to stderr (quiet, structured-ish). Never logs proof contents.
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # ---- routing -------------------------------------------------------------------------
    def _route(self) -> None:
        path = urlsplit(self.path).path.rstrip("/") or "/"

        if path == "/healthz":
            self._healthz()
            return

        if path.startswith("/verified/"):
            raw = path[len("/verified/"):]
            self._verified(raw)
            return

        if path == "/" or path == "":
            self._send_json(200, {
                "service": SERVICE, "version": SERVICE_VERSION,
                "endpoints": ["/healthz", "/verified/<HookHash>"],
                "note": "read-only proof-status surface over the xahc-prover Proof Registry; "
                        "absence of a proof is UNPROVEN, never a safety claim.",
            })
            return

        self._send_json(404, {"service": SERVICE, "error": "not found", "path": path})

    def do_GET(self) -> None:  # noqa: N802
        try:
            self._route()
        except BrokenPipeError:
            pass
        except Exception as ex:  # fail closed: an error is 500, NEVER an optimistic verdict.
            try:
                self._send_json(500, {"service": SERVICE, "error": "internal error",
                                      "detail": str(ex)})
            except Exception:
                pass

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    # ---- endpoints -----------------------------------------------------------------------
    def _healthz(self) -> None:
        """Liveness + registry reachability. Never reveals any proof verdict.

        We confirm the registry log is readable and its chain verifies. A broken chain is
        reported as degraded (not crashed) so an operator can tell "service up but registry
        compromised" apart from "service down".
        """
        store = type(self).store
        info: dict = {"service": SERVICE, "version": SERVICE_VERSION, "store": store}
        try:
            chain_ok, reason = R.verify_chain(store, type(self).pin_pubkey)
            info["registry_reachable"] = True
            info["chain_ok"] = chain_ok
            info["entries"] = len(R.read_log(store))
            info["head"] = R.head(store)
            if chain_ok:
                info["status"] = "ok"
                self._send_json(200, info)
            else:
                # Service is alive but the registry it serves is not trustworthy. Loud, 503.
                info["status"] = "degraded"
                info["chain_break"] = reason
                self._send_json(503, info)
        except Exception as ex:
            info["registry_reachable"] = False
            info["status"] = "error"
            info["detail"] = str(ex)
            self._send_json(503, info)

    def _verified(self, raw: str) -> None:
        hook_hash = raw.strip()
        if not _HOOKHASH_RE.match(hook_hash):
            self._send_json(400, {
                "service": SERVICE, "error": "invalid HookHash",
                "detail": "expected a 64-character hex HookHash (SHA-512Half of the hook bytecode)",
                "given": hook_hash[:80],
            })
            return
        code, body = _public_status(hook_hash, type(self).store, type(self).pin_pubkey)
        self._send_json(code, body)


def make_server(host: str, port: int, store: str, pin_pubkey: str | None) -> ThreadingHTTPServer:
    # Bind config onto the handler class (BaseHTTPRequestHandler is instantiated per request).
    handler = type("BoundVerifiedHookHandler", (VerifiedHookHandler,),
                   {"store": store, "pin_pubkey": pin_pubkey})
    return ThreadingHTTPServer((host, port), handler)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog=SERVICE,
                                description="Read-only Verified-Hook proof-status HTTP endpoint")
    p.add_argument("--host", default=os.environ.get("XAHC_VERIFIED_HOST", "127.0.0.1"),
                   help="bind address (default 127.0.0.1; bind the loopback and front with a tunnel/proxy)")
    p.add_argument("--port", type=int, default=int(os.environ.get("XAHC_VERIFIED_PORT", "8787")),
                   help="bind port (default 8787)")
    p.add_argument("--store", default=os.environ.get("XAHC_REGISTRY", R.DEFAULT_STORE),
                   help="path to the proof-registry JSONL log (default: $XAHC_REGISTRY or proof-registry.jsonl)")
    p.add_argument("--pin", dest="pin", default=os.environ.get("XAHC_VERIFIED_PIN"),
                   help="require the registry chain be signed entirely by this attester pubkey (hex)")
    a = p.parse_args(argv)

    srv = make_server(a.host, a.port, a.store, a.pin)
    pin_note = f", pinned to {a.pin[:12]}…" if a.pin else ""
    sys.stderr.write(
        f"{SERVICE} listening on http://{a.host}:{a.port}  "
        f"(store={a.store}{pin_note})\n"
        f"  GET /healthz\n  GET /verified/<HookHash>\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\nshutting down\n")
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
