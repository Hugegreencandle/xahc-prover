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


def account_id(r_address: str) -> bytes:
    """r-address -> 20-byte account-id (the form the guardrail compares on-chain)."""
    return decode_classic_address(r_address)


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
    """Decode the fields the guardrail predicate needs. Unknown / undecodable pieces are left
    None so the predicate fails closed to UNVERIFIED rather than guessing."""
    tx = record.get("tx", {})
    tt_name = tx.get("TransactionType")
    tx_type = _TT.get(tt_name, 1)        # only Payment(0) is in scope; anything else is non-0
    acct = tx.get("Account")
    dest = tx.get("Destination")
    return {
        "tx_type": tx_type,
        "account": account_id(acct) if acct else None,
        "hook_account": hook_account_id,
        "amount8": native_amount8(tx.get("Amount")),
        "destination": account_id(dest) if dest else None,
    }


def engine_result(record: dict) -> str:
    return record.get("engine_result", "")


def hook_executions(record: dict) -> list:
    """Flatten the meta HookExecutions array to a list of execution dicts."""
    out = []
    for item in (record.get("meta", {}) or {}).get("HookExecutions", []) or []:
        ex = item.get("HookExecution", item)   # tolerate both wrapped and bare shapes
        out.append(ex)
    return out


def watched_execution(record: dict, hook_hash: str, hook_account: Optional[str]) -> Optional[dict]:
    """The execution row for the WATCHED hook on this tx, or None if it didn't execute here.

    Match by HookAccount (the account we bound to) when known; otherwise by HookHash. Returns a
    normalized dict: {hook_hash, hook_result, hook_return_code:int, raw}."""
    want_acct = hook_account
    for ex in hook_executions(record):
        ex_acct = ex.get("HookAccount")
        ex_hash = (ex.get("HookHash") or "").upper()
        if want_acct is not None:
            if ex_acct != want_acct:
                continue
        elif ex_hash != hook_hash.upper():
            continue
        rc_raw = ex.get("HookReturnCode", "0")
        try:
            rc = int(rc_raw, 16) if isinstance(rc_raw, str) else int(rc_raw)
        except ValueError:
            rc = None
        return {
            "hook_hash": ex_hash,
            "hook_result": ex.get("HookResult"),
            "hook_return_code": rc,
            "raw": ex,
        }
    return None


# ── live transport (network-gated; websockets imported lazily) ─────────────────────────────

def _connect(ws_url: str):
    import websockets  # lazy: offline tests / replay never import this
    return websockets.connect(ws_url, max_size=None)


async def account_tx_backfill(ws_url: str, account: str, ledger_min: int):
    """Fetch validated txns for `account` from `ledger_min` forward (gap backfill on reconnect),
    normalized into the shared record shape. Best-effort; on transport error returns what it has."""
    import json
    records = []
    try:
        async with _connect(ws_url) as ws:
            await ws.send(json.dumps({
                "command": "account_tx", "account": account,
                "ledger_index_min": ledger_min, "ledger_index_max": -1, "binary": False,
            }))
            resp = json.loads(await ws.recv())
        for row in resp.get("result", {}).get("transactions", []):
            records.append(_normalize_account_tx_row(row))
    except Exception as e:  # noqa: BLE001 — backfill is best-effort; live loop logs and continues
        print(f"⚠️  backfill error from {ledger_min}: {e}")
    return [r for r in records if r]


def _normalize_account_tx_row(row: dict) -> Optional[dict]:
    tx = row.get("tx") or row.get("tx_json") or {}
    meta = row.get("meta") or row.get("metaData") or {}
    return {
        "hash": tx.get("hash") or row.get("hash"),
        "ledger_index": row.get("ledger_index") or tx.get("ledger_index"),
        "engine_result": meta.get("TransactionResult", ""),
        "tx": tx,
        "meta": meta,
    }


async def stream_account(ws_url: str, account: str):
    """Async generator of validated-tx records for `account`, normalized to the shared shape.
    Reconnects with backfill from the last-seen ledger so no transaction is silently skipped."""
    import json
    last_seen = None
    while True:
        try:
            async with _connect(ws_url) as ws:
                if last_seen is not None:
                    for rec in await account_tx_backfill(ws_url, account, last_seen + 1):
                        if rec.get("ledger_index"):
                            last_seen = max(last_seen or 0, rec["ledger_index"])
                        yield rec
                await ws.send(json.dumps({"command": "subscribe", "accounts": [account]}))
                async for raw in ws:
                    msg = json.loads(raw)
                    if msg.get("type") != "transaction" or not msg.get("validated"):
                        continue
                    rec = _normalize_account_tx_row(msg)
                    if rec.get("ledger_index"):
                        last_seen = max(last_seen or 0, rec["ledger_index"])
                    yield rec
        except Exception as e:  # noqa: BLE001 — reconnect loop; surface and retry with backfill
            print(f"⚠️  stream dropped ({e}); reconnecting + backfilling from {last_seen}")
            import asyncio
            await asyncio.sleep(2)
