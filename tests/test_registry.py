"""Tests for the Proof Registry — offline, stdlib-only, runnable as a plain script.
Run: python tests/test_registry.py  (also folded into tests/test_prover.py's runner).

Coverage (the guarantees that matter):
  • fail-closed: a non-PROVEN manifest CANNOT be registered.
  • round-trip: add -> read_log -> status_of returns the proven invariant set + residual.
  • UNPROVEN is loud: an unknown HookHash is never an implicit pass.
  • tamper-evidence: editing, reordering, or dropping any past entry breaks the chain
    and verify_chain pinpoints it; status flips to TAMPERED.
  • multi-invariant + multi-hook rollups.
  • signing (only if `cryptography` is present): a signed entry verifies; a forged
    signature fails closed.
"""
import json
import os
import sys
import tempfile
from dataclasses import asdict as dataclasses_asdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from watch.manifest import ProofManifest, hook_hash_of  # noqa: E402
from registry import registry as R  # noqa: E402
from registry.signing import Signer, crypto_available  # noqa: E402

WASM_A = b"\x00asm\x01\x00\x00\x00fixture-A"
WASM_B = b"\x00asm\x01\x00\x00\x00fixture-B"


def _manifest(wasm: bytes, invariant: str, exit_code: int = 0, caveats=None, account=None):
    return ProofManifest(
        invariant=invariant,
        verdict=("PROVEN" if exit_code == 0 else "INCONCLUSIVE"),
        exit_code=exit_code,
        hook_hash=hook_hash_of(wasm),
        wasm_sha256="AA",
        params={"LIM": 5000000},
        scope_caveats=list(caveats or []),
        hook_account=account,
        network_id=21338,
    )


def _tmp():
    fd, path = tempfile.mkstemp(suffix=".jsonl"); os.close(fd); os.remove(path)
    return path


def test_fail_closed_rejects_non_proven():
    store = _tmp()
    try:
        R.add(_manifest(WASM_A, "limit", exit_code=3), store)
        raise AssertionError("registry accepted a non-PROVEN manifest")
    except ValueError:
        pass
    assert R.read_log(store) == [], "a refused add must not write anything"
    print("  ok: fail-closed — non-PROVEN refused, nothing written")


def test_roundtrip_and_status():
    store = _tmp()
    R.add(_manifest(WASM_A, "limit", caveats=["cbak present"], account="rAcc"), store)
    out = R.status_of(hook_hash_of(WASM_A), store)
    assert out["status"] == R.PROVEN, out
    assert out["invariants"] == ["limit"], out
    assert out["residual"] == ["cbak present"], out
    assert out["hook_accounts"] == ["rAcc"], out
    print("  ok: round-trip — PROVEN with invariant set + residual + account")


def test_unproven_is_loud():
    store = _tmp()
    R.add(_manifest(WASM_A, "limit"), store)
    out = R.status_of(hook_hash_of(WASM_B), store)   # different hook, never registered
    assert out["status"] == R.UNPROVEN, out
    assert out["invariants"] == [], out
    print("  ok: unknown HookHash -> UNPROVEN (loud, not a pass)")


def test_multi_invariant_and_multi_hook():
    store = _tmp()
    R.add(_manifest(WASM_A, "limit"), store)
    R.add(_manifest(WASM_A, "guardrail"), store)
    R.add(_manifest(WASM_B, "termination"), store)
    a = R.status_of(hook_hash_of(WASM_A), store)
    assert a["invariants"] == ["guardrail", "limit"], a
    s = R.summary(store)
    assert s["chain_ok"] and len(s["hooks"]) == 2, s
    print("  ok: multi-invariant per hook + multi-hook rollup")


def test_tamper_edit_breaks_chain():
    store = _tmp()
    R.add(_manifest(WASM_A, "limit"), store)
    R.add(_manifest(WASM_A, "guardrail"), store)
    ok, _ = R.verify_chain(store); assert ok
    # Forge entry 0's manifest invariant in place, leave its entry_hash untouched.
    lines = [json.loads(l) for l in open(store) if l.strip()]
    lines[0]["manifest"]["invariant"] = "termination"
    with open(store, "w") as f:
        for d in lines:
            f.write(json.dumps(d, sort_keys=True) + "\n")
    ok, reason = R.verify_chain(store)
    assert not ok and "entry 0" in reason, (ok, reason)
    assert R.status_of(hook_hash_of(WASM_A), store)["status"] == R.TAMPERED
    print(f"  ok: edited entry breaks chain -> {reason}")


def test_tamper_drop_breaks_chain():
    store = _tmp()
    R.add(_manifest(WASM_A, "limit"), store)
    R.add(_manifest(WASM_A, "guardrail"), store)
    R.add(_manifest(WASM_B, "termination"), store)
    lines = [l for l in open(store) if l.strip()]
    with open(store, "w") as f:        # drop the middle entry
        f.write(lines[0]); f.write(lines[2])
    ok, reason = R.verify_chain(store)
    assert not ok and "entry 1" in reason, (ok, reason)
    print(f"  ok: dropped entry breaks chain -> {reason}")


def test_head_is_stable_commitment():
    store = _tmp()
    assert R.head(store) == R.GENESIS_PREV
    e0 = R.add(_manifest(WASM_A, "limit"), store)
    assert R.head(store) == e0.entry_hash
    e1 = R.add(_manifest(WASM_A, "guardrail"), store)
    assert R.head(store) == e1.entry_hash and e1.prev_hash == e0.entry_hash
    print("  ok: head advances + chains to prev entry_hash")


def test_signing_roundtrip():
    if not crypto_available():
        print("  skip: signing (cryptography not installed) — unsigned mode is the default")
        return
    store = _tmp()
    signer = Signer.generate()
    e = R.add(_manifest(WASM_A, "limit"), store, signer=signer)
    assert e.signed
    ok, _ = R.verify_chain(store); assert ok, "signed chain must verify"
    out = R.status_of(hook_hash_of(WASM_A), store)
    assert out["status"] == R.PROVEN and out["signed"] is True, out
    # Forge the signature -> must fail closed.
    lines = [json.loads(l) for l in open(store) if l.strip()]
    lines[0]["sig"] = ("00" * 64)
    with open(store, "w") as f:
        for d in lines:
            f.write(json.dumps(d, sort_keys=True) + "\n")
    ok, reason = R.verify_chain(store)
    assert not ok and "signature" in reason, (ok, reason)
    print("  ok: signed entry verifies; forged signature fails closed")


def test_key_pinning_catches_rechain_under_attacker_key():
    """AUDIT: an attacker who controls the file can rebuild a fully self-consistent
    chain — but only under THEIR key. Plain verify passes (sigs valid); key-pinning to
    the original attester rejects it. This is the enforced half of the trust model."""
    if not crypto_available():
        print("  skip: key-pinning audit (cryptography not installed)")
        return
    store = _tmp()
    good = Signer.generate()
    R.add(_manifest(WASM_A, "limit"), store, signer=good)
    R.add(_manifest(WASM_A, "guardrail"), store, signer=good)
    assert R.verify_chain(store, good.public_hex())[0], "honest chain must pass pinning"

    # Attacker rewrites entry 0's manifest and rebuilds the ENTIRE chain under their key.
    attacker = Signer.generate()
    forged = [
        _manifest(WASM_A, "termination"),   # the lie
        _manifest(WASM_A, "guardrail"),
    ]
    os.remove(store)
    for m in forged:
        R.add(m, store, signer=attacker)

    # Plain verification PASSES — the forged chain is internally consistent + signed.
    assert R.verify_chain(store)[0], "rebuilt chain is internally consistent (the gap)"
    # Pinning the ORIGINAL attester catches it.
    ok, reason = R.verify_chain(store, good.public_hex())
    assert not ok and "unpinned key" in reason, (ok, reason)
    assert R.status_of(hook_hash_of(WASM_A), store, good.public_hex())["status"] == R.TAMPERED
    print(f"  ok: re-chain under attacker key — plain verify passes, pinning rejects ({reason[:40]}…)")


def test_injected_non_proven_entry_is_caught_on_read():
    """AUDIT (CRITICAL fix): add() refuses non-PROVEN, but a hand-authored, correctly
    hash-chained entry with exit_code != 0 must NEVER read back as PROVEN. verify_chain
    rejects it on READ; status flips to TAMPERED."""
    store = _tmp()
    R.add(_manifest(WASM_A, "limit"), store)
    # Hand-author a fully consistent entry whose manifest is INCONCLUSIVE (exit_code=3),
    # chaining + entry_hash computed exactly like add() would.
    from registry.registry import _entry_hash
    prev = R.read_log(store)[-1].entry_hash
    bad = dataclasses_asdict(_manifest(WASM_A, "guardrail", exit_code=3))
    eh = _entry_hash(1, prev, bad, None, None)
    with open(store, "a") as f:
        f.write(json.dumps({"index": 1, "prev_hash": prev, "manifest": bad,
                            "entry_hash": eh, "registry_version": 1}, sort_keys=True) + "\n")
    ok, reason = R.verify_chain(store)
    assert not ok and "non-PROVEN" in reason, (ok, reason)
    assert R.status_of(hook_hash_of(WASM_A), store)["status"] == R.TAMPERED
    print(f"  ok: injected non-PROVEN entry caught on read -> {reason[:48]}…")


def test_prover_args_roundtrip_for_reverify():
    """prover_args are recorded + surfaced per-proof so `reverify` can replay each proof exactly."""
    store = _tmp()
    m = _manifest(WASM_A, "monotonic")
    m.prover_args = ["--field", "01:0:8"]
    R.add(m, store)
    out = R.status_of(hook_hash_of(WASM_A), store)
    assert out["status"] == R.PROVEN, out
    proofs = out.get("proofs", [])
    assert proofs and proofs[0]["invariant"] == "monotonic", out
    assert proofs[0]["prover_args"] == ["--field", "01:0:8"], proofs
    print("  ok: prover_args recorded + surfaced per-proof (reverify can replay)")


def test_float_in_manifest_refused():
    """AUDIT (MED fix): a manifest carrying a float has no stable hash domain — refuse it."""
    store = _tmp()
    m = _manifest(WASM_A, "limit")
    m.params = {"LIM": 5.0e6}          # a float sneaks in
    try:
        R.add(m, store)
        raise AssertionError("registry accepted a manifest containing a float")
    except ValueError as e:
        assert "float" in str(e)
    assert R.read_log(store) == []
    print("  ok: float-bearing manifest refused (deterministic hash domain preserved)")


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]


def run() -> int:
    print("test_registry:")
    failed = 0
    for t in TESTS:
        try:
            t()
        except Exception as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
    print(f"  {len(TESTS) - failed}/{len(TESTS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(run())
