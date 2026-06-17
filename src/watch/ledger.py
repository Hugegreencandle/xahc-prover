"""Ledger transport + decode — isolated from predicate logic so the latter is unit-testable
offline. Two responsibilities:

  1. DECODE a transaction record (the shape the node returns, mirrored by the offline fixture)
     into the concrete fields the shared predicate needs + the watched hook's on-chain execution.
  2. TRANSPORT (live): websocket `subscribe` to an account's validated transactions, with
     `account_tx` gap-backfill on reconnect. Network deps (`websockets`) are imported LAZILY so
     offline tests and the replay path need no network.

Record shape (live + fixture share it, so classify() runs identically on both):
  {
    "hash": "...", "ledger_index": int, "engine_result": "tesSUCCESS"|"tecHOOK_REJECTED"|...,
    "tx":   {"TransactionType": "Payment", "Account": "r...", "Destination": "r...",
             "Amount": "3000000" | {"currency":..,"value":..,"issuer":..}},
    "meta": {"HookExecutions": [{"HookExecution":
             {"HookAccount":"r...","HookHash":"<64hex>","HookResult":int,"HookReturnCode":"<hex>"}}]}
  }
"""
from __future__ import annotations

from typing import Optional

from xrpl.core.addresscodec import decode_classic_address

NATIVE_FLAG = 0x4000000000000000  # sfAmount native (XAH): bit63=0 (is-XRP), bit62=1 (positive)
GUARD_VIOLATION_BIT = 1 << 63     # HookReturnCode top bit set = GUARD_VIOLATION / error exit

# Canonical HookResult enum (chain-validated; see xahau-mcp src/fidelity.ts): the WATCHED hook's
# OWN exit, distinct from the tx-level engine_result. 3 = accept(), 0/4 = rollback(), else unknown.
HR_ACCEPT = 3
HR_ROLLBACK = (0, 4)


def account_id(r_address: str) -> bytes:
    """r-address -> 20-byte account-id (the form the guardrail compares on-chain)."""
    return decode_classic_address(r_address)


def _safe_account_id(a):
    """Decode an r-address from UNTRUSTED ledger data; (None, error?) on garbage — never raises
    (a crash on a crafted tx would blind the monitor = a silent 'all good')."""
    if not a or not isinstance(a, str):
        return None, bool(a)
    try:
        return decode_classic_address(a), False
    except Exception:
        return None, True


def hook_decision(ex: dict) -> str:
    """The WATCHED hook's OWN accept/reject decision, from its HookResult (+ GUARD_VIOLATION via
    HookReturnCode top bit) — NOT the aggregate tx engine_result (a Payment runs several hooks and
    can fail at apply-time for non-hook reasons). Returns 'ACCEPT' / 'REJECT' / 'OTHER'.
    Fail-closed: any unknown/error exit -> 'OTHER' (the caller treats that as UNVERIFIED, loud)."""
    rc = ex.get("hook_return_code")
    if isinstance(rc, int) and rc >= 0 and (rc & GUARD_VIOLATION_BIT):
        return "OTHER"                    # GUARD_VIOLATION / error exit
    try:
        n = int(ex.get("hook_result"))
    except (TypeError, ValueError):
        return "OTHER"
    if n == HR_ACCEPT:
        return "ACCEPT"
    if n in HR_ROLLBACK:
        return "REJECT"
    return "OTHER"


def native_amount8(amount_field) -> Optional[bytes]:
    """The 8-byte native sfAmount serialization, or None for IOU/issued (out of the guardrail's
    native model). For native, the node gives a drops STRING; we reconstruct the on-chain 8-byte
    field (drops | native/positive flags) so the SAME 0x3F-masking decode the prover proved runs
    over real bytes."""
    if not isinstance(amount_field, str):
        return None                      # dict => IOU/issued amount: out of model
    try:
        drops = int(amount_field)
    except ValueError:
        return None
    if drops < 0 or drops >= NATIVE_FLAG:
        return None                      # implausible as native drops; fail closed
    return (drops | NATIVE_FLAG).to_bytes(8, "big")


_TT = {"Payment": 0}


def tx_fields(record: dict, hook_account_id: bytes) -> dict:
    """Decode the fields the guardrail predicate needs from UNTRUSTED ledger data. Undecodable
    pieces are left None (predicate fails closed to UNVERIFIED). `_has_tx_body` is False when the
    tx body / TransactionType is absent (so the caller never treats a missing body as a benign
    pass-through), and `_decode_error` flags a present-but-malformed address (caller -> UNVERIFIED).
    Never raises — a crash on a crafted tx would blind the monitor."""
    tx = record.get("tx")
    if not isinstance(tx, dict):
        tx = {}
    tt_name = tx.get("TransactionType")
    acct_id, acct_err = _safe_account_id(tx.get("Account"))
    dest_id, dest_err = _safe_account_id(tx.get("Destination"))
    return {
        "tx_type": _TT.get(tt_name, 1),  # only Payment(0) is in scope; anything else is non-0
        "account": acct_id,
        "hook_account": hook_account_id,
        "amount8": native_amount8(tx.get("Amount")),
        "destination": dest_id,
        "_has_tx_body": bool(tt_name),
        "_decode_error": acct_err or dest_err,
    }


def engine_result(record: dict) -> str:
    return record.get("engine_result", "")


def hook_executions(record: dict) -> list:
    """Flatten the meta HookExecutions array to a list of execution dicts. Tolerates malformed
    shapes from untrusted metadata (non-dict items / wrong types are skipped, never crash)."""
    meta = record.get("meta")
    if not isinstance(meta, dict):
        return []
    out = []
    for item in meta.get("HookExecutions") or []:
        if not isinstance(item, dict):
            continue
        ex = item.get("HookExecution", item)   # tolerate both wrapped and bare shapes
        if isinstance(ex, dict):
            out.append(ex)
    return out


def watched_execution(record: dict, hook_hash: str, hook_account: Optional[str]) -> Optional[dict]:
    """The execution row for the WATCHED hook on this tx, or None if it didn't execute here.

    The watched hook is identified by BOTH its account (when bound) AND its HookHash — on a
    hook-chain account several hooks execute, so matching account alone could pick the wrong row.
    A row on the bound account whose HookHash differs is still returned (so the binding check in
    classify can raise PROOF_VOID); but when the proven HookHash is present on the account we
    prefer it. Returns {hook_hash, hook_result, hook_return_code:int|None, raw}."""
    want_hash = hook_hash.upper()
    rows = hook_executions(record)
    candidates = []
    for ex in rows:
        ex_acct = ex.get("HookAccount")
        if hook_account is not None and ex_acct != hook_account:
            continue
        candidates.append(ex)
    if hook_account is None:
        candidates = [ex for ex in rows if (ex.get("HookHash") or "").upper() == want_hash]
    if not candidates:
        return None
    # Prefer the row whose hash matches the proven hash; else the first on the account (so a
    # genuine hash mismatch surfaces as PROOF_VOID rather than being hidden behind another hook).
    chosen = next((ex for ex in candidates if (ex.get("HookHash") or "").upper() == want_hash),
                  candidates[0])
    rc_raw = chosen.get("HookReturnCode", "0")
    try:
        rc = int(rc_raw, 16) if isinstance(rc_raw, str) else int(rc_raw)
    except (ValueError, TypeError):
        rc = None
    return {
        "hook_hash": (chosen.get("HookHash") or "").upper(),
        "hook_result": chosen.get("HookResult"),
        "hook_return_code": rc,
        "raw": chosen,
    }


# ── live transport (network-gated; websockets imported lazily) ─────────────────────────────

_MAX_FRAME = 16 * 1024 * 1024   # bound inbound frames (max_size=None = memory-exhaustion DoS)


def _connect(ws_url: str):
    import os
    # TLS guard FIRST (independent of the optional websockets dep): a plaintext ws:// node can be
    # MITM'd to suppress a VIOLATION (a silent 'all good').
    if not ws_url.startswith("wss://") and not os.environ.get("XAHC_WATCH_ALLOW_INSECURE"):
        raise ValueError(
            f"refusing insecure websocket {ws_url!r}: use wss:// (a MITM on a plaintext feed can "
            "suppress a VIOLATION). Set XAHC_WATCH_ALLOW_INSECURE=1 to override.")
    import websockets  # lazy: offline tests / replay never import this
    return websockets.connect(ws_url, max_size=_MAX_FRAME)


async def account_tx_backfill(ws_url: str, account: str, ledger_min: int):
    """Fetch ALL validated txns for `account` from `ledger_min` forward, normalized to the shared
    record shape. Follows the `account_tx` `marker` until exhausted — a single-page read would
    SILENTLY DROP every tx past the first page, defeating the gap-free guarantee. Raises on
    transport failure (the caller must NOT treat a partial/failed backfill as 'caught up')."""
    import json
    records = []
    marker = None
    async with _connect(ws_url) as ws:
        while True:
            req = {"id": "backfill", "command": "account_tx", "account": account,
                   "ledger_index_min": ledger_min, "ledger_index_max": -1,
                   "binary": False, "forward": True, "limit": 200}
            if marker is not None:
                req["marker"] = marker
            await ws.send(json.dumps(req))
            # correlate the response to our request id (ignore stray/async frames)
            while True:
                resp = json.loads(await ws.recv())
                if resp.get("id") == "backfill":
                    break
            result = resp.get("result", {})
            for row in result.get("transactions", []):
                rec = _normalize_account_tx_row(row)
                if rec:
                    records.append(rec)
            marker = result.get("marker")
            if marker is None:
                break
    return records


def _normalize_account_tx_row(row: dict) -> Optional[dict]:
    """Normalize a node row to the shared record shape. Handles BOTH account_tx rows (tx/tx_json
    + meta) AND live `subscribe` transaction messages (the tx body is under `transaction`, the
    engine result is the top-level `engine_result`, and the ledger index is top-level)."""
    if not isinstance(row, dict):
        return None
    tx = row.get("transaction") or row.get("tx_json") or row.get("tx") or {}
    meta = row.get("meta") or row.get("metaData") or {}
    if not isinstance(tx, dict):
        tx = {}
    if not isinstance(meta, dict):
        meta = {}
    return {
        "hash": tx.get("hash") or row.get("hash"),
        "ledger_index": (row.get("ledger_index") or tx.get("ledger_index")
                         or tx.get("LedgerIndex") or meta.get("ledger_index")),
        # live messages carry top-level engine_result; account_tx carries meta.TransactionResult
        "engine_result": row.get("engine_result") or meta.get("TransactionResult", ""),
        "tx": tx,
        "meta": meta,
    }


async def stream_account(ws_url: str, account: str):
    """Async generator of validated-tx records for `account`, normalized to the shared shape.

    Gap-free reconnect: SUBSCRIBE FIRST, then backfill from the last-seen ledger, so a tx landing
    in the window between backfill and subscribe is never missed. A bounded `seen` set of tx
    hashes de-dups the backfill/live overlap (no double-count). If the backfill itself fails it is
    surfaced LOUDLY and retried — a partial backfill is never treated as 'caught up'."""
    import asyncio
    import json
    last_seen = None
    seen = {}            # hash -> insertion order (bounded LRU-ish; prevents double-count)
    SEEN_CAP = 4096

    def _mark(h):
        if h is None:
            return False
        if h in seen:
            return True
        seen[h] = True
        if len(seen) > SEEN_CAP:
            for k in list(seen)[:len(seen) - SEEN_CAP]:
                del seen[k]
        return False

    while True:
        try:
            async with _connect(ws_url) as ws:
                await ws.send(json.dumps({"id": "sub", "command": "subscribe", "accounts": [account]}))
                # 1) backfill the gap (subscribe is already live, so nothing slips through)
                if last_seen is not None:
                    for rec in await account_tx_backfill(ws_url, account, last_seen + 1):
                        if _mark(rec.get("hash")):
                            continue
                        if rec.get("ledger_index"):
                            last_seen = max(last_seen or 0, rec["ledger_index"])
                        yield rec
                # 2) live stream
                async for raw in ws:
                    msg = json.loads(raw)
                    if msg.get("type") != "transaction" or not msg.get("validated"):
                        continue
                    rec = _normalize_account_tx_row(msg)
                    if not rec or _mark(rec.get("hash")):
                        continue
                    if rec.get("ledger_index"):
                        last_seen = max(last_seen or 0, rec["ledger_index"])
                    yield rec
        except Exception as e:  # noqa: BLE001 — reconnect loop; surface LOUDLY and retry with backfill
            print(f"🚨 stream/backfill error ({e}); reconnecting + re-backfilling from {last_seen} "
                  "(no tx treated as caught-up until backfill completes)")
            await asyncio.sleep(2)
