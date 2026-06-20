"""Proof manifest — the prove -> watch seam.

A small JSON the prover emits after a PROVEN verdict and the watcher consumes. It lets the
watcher know WHAT was proven (invariant, params, scope caveats) and WHICH bytecode it was
proven for (the Xahau HookHash) WITHOUT importing the symbolic engine.

HookHash = SHA-512Half (first 32 bytes of SHA-512) of the hook bytecode — the same digest
xahaud exposes via `util_sha512h` and stores as the `HookHash` in HookDefinition /
HookExecutions metadata (see docs/XAHAU-DEV-REFERENCE.md §HookExecutions, §HookHash).

Fail-closed posture:
  • write_manifest REFUSES to write a PROVEN manifest for a non-zero (not-PROVEN) exit code.
  • The binding check (in watch.py) compares this hook_hash to the DEPLOYED hook's HookHash.
    If the preimage/algorithm ever disagreed with xahaud, the hashes would simply never match
    -> every tx classifies PROOF_VOID (loud over-alert), NEVER a silent "consistent". A wrong
    assumption fails toward alarm, not toward false comfort.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import subprocess
from dataclasses import dataclass, field, asdict
from typing import Optional

MANIFEST_VERSION = 3
PROVEN_EXIT = 0


def make_anchor(anchor_type: str, value: str, account: Optional[str] = None,
                network_id: Optional[int] = None) -> dict:
    """A domain-neutral deployment anchor (the cross-domain re-check format). `anchor_type` names the
    KIND of on-chain identifier a verifier recomputes from the deployed artifact and compares; `value`
    is that hash/id. Examples: xahau.hook_hash (SHA-512Half of the WASM), xrpl.code_hash,
    xrpl.ledger_object, evm.code_hash. The binding only needs: a stable id a consumer can recompute."""
    a = {"anchor_type": anchor_type, "value": value}
    if account is not None:
        a["account"] = account
    if network_id is not None:
        a["network_id"] = network_id
    return a


def hook_hash_of(wasm: bytes) -> str:
    """Xahau HookHash of a hook's bytecode: SHA-512Half (first 32 bytes of SHA-512), upper hex."""
    return hashlib.sha512(wasm).digest()[:32].hex().upper()


def wasm_sha256_of(wasm: bytes) -> str:
    """A plain content checksum of the WASM file (audit aid; distinct from the on-chain HookHash)."""
    return hashlib.sha256(wasm).hexdigest().upper()


def _prover_commit() -> Optional[str]:
    """Best-effort short git commit of the prover checkout (None if unavailable)."""
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=5)
        return out.stdout.strip() or None
    except Exception:
        return None


@dataclass
class ProofManifest:
    invariant: str                       # e.g. "guardrail"
    verdict: str                         # human verdict string, e.g. "PROVEN [spend-limit, dst-lock]"
    exit_code: int                       # the prover's exit code (0 = PROVEN)
    hook_hash: str                       # Xahau HookHash (SHA-512Half) of the proven bytecode
    wasm_sha256: str                     # file checksum (audit aid)
    params: dict = field(default_factory=dict)        # e.g. {"LIM": 5000000, "DST": "<20-byte hex>"}
    prover_args: list = field(default_factory=list)    # exact prover driver args (e.g. ["--field","01:0:8"]) — replay for reverify
    smt_sha256: Optional[str] = None                    # bundle hash of the exported SMT obligations — recheck binding
    proof_object_sha256: Optional[str] = None           # bundle hash of the verified solver-free DRAT proof objects — checkproof binding
    # Domain-neutral deployment anchor {anchor_type, value, account?, network_id?}. For Xahau this is
    # {xahau.hook_hash, <hook_hash>}; for a non-Xahau artifact (e.g. Ward's resolver) it carries that
    # artifact's id. `hook_hash` stays the registry key (= the anchor value); this makes the manifest
    # self-describing + cross-domain. (v3.)
    artifact_anchor: Optional[dict] = None
    scope_caveats: list = field(default_factory=list)  # e.g. ["cbak present", "INCONCLUSIVE region: ..."]
    hook_account: Optional[str] = None   # bound r-address (optional until bound to a deployment)
    network_id: Optional[int] = None     # e.g. 21338 (testnet)
    prover_commit: Optional[str] = None
    created_at: Optional[str] = None
    manifest_version: int = MANIFEST_VERSION

    def is_proven(self) -> bool:
        return self.exit_code == PROVEN_EXIT


def build_manifest(*, wasm: bytes, invariant: str, verdict: str, exit_code: int,
                   params: Optional[dict] = None, scope_caveats: Optional[list] = None,
                   hook_account: Optional[str] = None, network_id: Optional[int] = None,
                   prover_args: Optional[list] = None, smt_sha256: Optional[str] = None,
                   proof_object_sha256: Optional[str] = None,
                   created_at: Optional[str] = None) -> ProofManifest:
    hh = hook_hash_of(wasm)
    return ProofManifest(
        invariant=invariant,
        verdict=verdict,
        exit_code=exit_code,
        hook_hash=hh,
        wasm_sha256=wasm_sha256_of(wasm),
        params=dict(params or {}),
        prover_args=list(prover_args or []),
        smt_sha256=smt_sha256,
        proof_object_sha256=proof_object_sha256,
        artifact_anchor=make_anchor("xahau.hook_hash", hh, hook_account, network_id),
        scope_caveats=list(scope_caveats or []),
        hook_account=hook_account,
        network_id=network_id,
        prover_commit=_prover_commit(),
        created_at=created_at,
    )


def build_anchor_manifest(*, anchor_type: str, anchor_value: str, invariant: str, verdict: str,
                          exit_code: int, params: Optional[dict] = None,
                          scope_caveats: Optional[list] = None, account: Optional[str] = None,
                          network_id: Optional[int] = None, prover_args: Optional[list] = None,
                          smt_sha256: Optional[str] = None, proof_object_sha256: Optional[str] = None,
                          reducer: Optional[str] = None, created_at: Optional[str] = None) -> ProofManifest:
    """Build a manifest for a NON-WASM artifact (cross-domain — e.g. Ward's resolver code hash, an
    on-ledger object id). `hook_hash` is set to `anchor_value` so the SAME registry keys/looks it up;
    `artifact_anchor.anchor_type` says what KIND of anchor it is. The verifier recomputes anchor_value
    from the deployed artifact and compares — identical re-check discipline, different domain."""
    return ProofManifest(
        invariant=invariant,
        verdict=verdict,
        exit_code=exit_code,
        hook_hash=anchor_value.upper() if anchor_type == "xahau.hook_hash" else anchor_value,
        wasm_sha256="",                       # no WASM file for a non-Hook artifact
        params=dict(params or {}),
        prover_args=list(prover_args or ([] if reducer is None else [f"reducer={reducer}"])),
        smt_sha256=smt_sha256,
        proof_object_sha256=proof_object_sha256,
        artifact_anchor=make_anchor(
            anchor_type,
            anchor_value.upper() if anchor_type == "xahau.hook_hash" else anchor_value,
            account, network_id),
        scope_caveats=list(scope_caveats or []),
        hook_account=account,
        network_id=network_id,
        prover_commit=_prover_commit(),
        created_at=created_at,
    )


def write_manifest(m: ProofManifest, path: str) -> None:
    """Persist a manifest as JSON.

    FAIL CLOSED: a non-PROVEN verdict (exit_code != 0) cannot be written as a manifest — a
    watcher must never bind to a proof that was never established. Raises ValueError instead.
    """
    if not m.is_proven():
        raise ValueError(
            f"refusing to write a proof manifest for a non-PROVEN verdict "
            f"(exit_code={m.exit_code}); only a PROVEN (exit 0) run may emit a manifest.")
    with open(path, "w") as f:
        json.dump(asdict(m), f, indent=2, sort_keys=True)
        f.write("\n")


def load_manifest(path: str) -> ProofManifest:
    with open(path) as f:
        data = json.load(f)
    known = {f.name for f in dataclasses.fields(ProofManifest)}
    return ProofManifest(**{k: v for k, v in data.items() if k in known})
