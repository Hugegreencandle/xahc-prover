"""Proof Registry — a tamper-evident, append-only log of PROVEN proof manifests.

The fifth leg of the toolchain: **write → simulate → prove → watch → REGISTER**.

Where `watch` binds ONE proof to ONE deployed hook at runtime, the registry is the
durable, queryable record: "for HookHash X, which invariants were proven, under what
params, with what residual, by which prover commit — and is that record intact?"
Anyone holding a hook's bytecode can look up its proof status without re-running the
engine, and a deployer can ship the proof *with* the hook (proof-carrying hooks).

Design (deliberately dependency-free — stdlib `hashlib`/`json`, like manifest.py):

  • Append-only JSONL transparency log. Each line is one RegistryEntry.
  • Each entry is HASH-CHAINED to the previous one (Certificate-Transparency style):
    entry_hash = SHA-256( canonical({index, prev_hash, manifest, attestation_pubkey}) ).
    Altering, reordering, or dropping any past entry breaks the chain from that point
    on — `verify_chain` finds the exact break. The current head hash is a single
    commitment to the whole history, suitable for anchoring on-chain (a Xahau tx memo).
  • Optional Ed25519 attestation per entry (only if `cryptography` is importable and a
    key is supplied). Absent crypto ⇒ entry is unsigned-but-tamper-evident, never a
    hard failure. See signing.py.

Fail-closed posture (the one rule that matters here, mirroring the prover):
  • `add` REFUSES a non-PROVEN manifest — the registry can only ever hold established
    proofs. A non-PROVEN verdict cannot be laundered into a registry record.
  • A lookup for an unknown HookHash returns status UNPROVEN (loud), NEVER an implicit
    "ok". Absence of proof is not proof of safety.
  • A broken chain or a bad signature is a loud FAIL, never silently skipped.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
from dataclasses import dataclass, field, asdict
from typing import Optional

# src/ is on sys.path (see tests + watch); import the prove->watch seam.
from watch.manifest import ProofManifest, hook_hash_of, wasm_sha256_of, PROVEN_EXIT

from registry.signing import Signer, load_signer, verify_signature

REGISTRY_VERSION = 1
GENESIS_PREV = "0" * 64                      # prev_hash of the first entry
DEFAULT_STORE = os.environ.get("XAHC_REGISTRY", "proof-registry.jsonl")

# Lookup statuses — UNPROVEN is loud, the absence-≠-safety guard.
PROVEN = "PROVEN"          # ≥1 intact, (optionally) signed PROVEN entry for this HookHash
UNPROVEN = "UNPROVEN"      # no record for this HookHash — NOT a pass
TAMPERED = "TAMPERED"      # an entry exists but the chain or a signature failed to verify


def _canonical(obj: dict) -> bytes:
    """Deterministic JSON bytes for hashing/signing (stable across hosts)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _contains_float(obj) -> bool:
    """True if any nested value is a float (bool is not a float here)."""
    if isinstance(obj, float):
        return True
    if isinstance(obj, dict):
        return any(_contains_float(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return any(_contains_float(v) for v in obj)
    return False


def _entry_hash(index: int, prev_hash: str, manifest: dict, pubkey: Optional[str],
                recorded_at: Optional[str]) -> str:
    """The chain link. Binds position + history + the full manifest + key + timestamp."""
    return hashlib.sha256(_canonical({
        "index": index,
        "prev_hash": prev_hash,
        "manifest": manifest,
        "pubkey": pubkey,
        "recorded_at": recorded_at,
    })).hexdigest()


@dataclass
class RegistryEntry:
    index: int                              # 0-based position in the log
    prev_hash: str                          # entry_hash of index-1 (GENESIS_PREV at index 0)
    manifest: dict                          # a PROVEN ProofManifest, asdict()
    entry_hash: str                         # SHA-256 chain link (see _entry_hash)
    pubkey: Optional[str] = None            # attester ed25519 public key (hex), if signed
    sig: Optional[str] = None               # ed25519 signature over entry_hash (hex), if signed
    recorded_at: Optional[str] = None       # caller-supplied timestamp; bound into entry_hash
    registry_version: int = REGISTRY_VERSION

    @property
    def hook_hash(self) -> str:
        return str(self.manifest.get("hook_hash", "")).upper()

    @property
    def invariant(self) -> str:
        return str(self.manifest.get("invariant", ""))

    @property
    def signed(self) -> bool:
        return bool(self.pubkey and self.sig)


def read_log(store: str) -> list[RegistryEntry]:
    """Load all entries. Missing file ⇒ empty log (a fresh registry)."""
    if not os.path.exists(store):
        return []
    entries: list[RegistryEntry] = []
    known = {f.name for f in dataclasses.fields(RegistryEntry)}
    with open(store) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            entries.append(RegistryEntry(**{k: v for k, v in data.items() if k in known}))
    return entries


def head(store: str) -> str:
    """The current head hash — a single commitment to the whole log (on-chain anchorable)."""
    entries = read_log(store)
    return entries[-1].entry_hash if entries else GENESIS_PREV


def add(manifest: ProofManifest, store: str = DEFAULT_STORE, *,
        signer: Optional[Signer] = None, recorded_at: Optional[str] = None) -> RegistryEntry:
    """Append a PROVEN manifest to the log as a new hash-chained entry.

    FAIL CLOSED: refuses any non-PROVEN manifest (exit_code != 0). The registry is a
    record of established proofs only.
    """
    if not manifest.is_proven():
        raise ValueError(
            f"refusing to register a non-PROVEN manifest (invariant={manifest.invariant!r}, "
            f"exit_code={manifest.exit_code}); only a PROVEN (exit 0) proof may be registered.")
    # Floats have no stable cross-host JSON repr, which would make the canonical hash
    # fragile (honest entries could later fail to verify). The prover's manifests are
    # integer/string/JSON only; refuse anything carrying a float rather than record a
    # weakly-bound entry.
    if _contains_float(asdict(manifest)):
        raise ValueError("refusing to register a manifest containing a float "
                         "(non-deterministic hash domain); use integers/strings only.")

    entries = read_log(store)
    index = len(entries)
    prev_hash = entries[-1].entry_hash if entries else GENESIS_PREV
    m = asdict(manifest)
    pubkey = signer.public_hex() if signer else None
    eh = _entry_hash(index, prev_hash, m, pubkey, recorded_at)
    sig = signer.sign(eh) if signer else None

    entry = RegistryEntry(index=index, prev_hash=prev_hash, manifest=m, entry_hash=eh,
                          pubkey=pubkey, sig=sig, recorded_at=recorded_at)
    with open(store, "a") as f:
        f.write(json.dumps(asdict(entry), sort_keys=True) + "\n")
    return entry


def verify_chain(store: str, pin_pubkey: Optional[str] = None) -> tuple[bool, Optional[str]]:
    """Recompute the hash chain from genesis. Returns (ok, reason_if_broken).

    Detects any altered manifest, swapped key, reordered/removed entry, or bad signature.

    If `pin_pubkey` is given, ENFORCE that every entry is signed by exactly that key.
    This closes the "rebuild the whole chain under the attacker's own key" gap: a
    re-signed chain is internally consistent, so plain verification passes — but it is
    signed by the wrong key, which pinning rejects. Pin the attester you trust, or
    compare `head` to an externally anchored value (see docs/PROOF-REGISTRY.md).
    """
    pin = pin_pubkey.lower() if pin_pubkey else None
    entries = read_log(store)
    expected_prev = GENESIS_PREV
    for i, e in enumerate(entries):
        if e.index != i:
            return False, f"entry {i}: index field is {e.index} (out of order / dropped)"
        if e.prev_hash != expected_prev:
            return False, f"entry {i}: prev_hash {e.prev_hash[:8]}… ≠ expected {expected_prev[:8]}…"
        recomputed = _entry_hash(e.index, e.prev_hash, e.manifest, e.pubkey, e.recorded_at)
        if recomputed != e.entry_hash:
            return False, f"entry {i}: entry_hash mismatch — manifest or key was altered"
        # Fail closed on READ too, not just on add(): a well-formed registry can only
        # ever hold PROVEN manifests. A correctly-chained but non-PROVEN entry means the
        # file was hand-authored around add() — treat the whole log as compromised rather
        # than ever letting status_of report PROVEN off it.
        if int(e.manifest.get("exit_code", -1)) != PROVEN_EXIT:
            return False, (f"entry {i}: non-PROVEN manifest in log "
                           f"(exit_code={e.manifest.get('exit_code')!r}); only PROVEN may be registered")
        if e.signed and not verify_signature(e.pubkey, e.entry_hash, e.sig):
            return False, f"entry {i}: ed25519 signature does not verify"
        if pin is not None:
            if not e.signed:
                return False, f"entry {i}: unsigned under key-pinning (--pin requires every entry signed)"
            if (e.pubkey or "").lower() != pin:
                return False, f"entry {i}: signed by an unpinned key {e.pubkey[:8]}… ≠ pinned {pin[:8]}…"
        expected_prev = e.entry_hash
    return True, None


def entries_for(hook_hash: str, store: str = DEFAULT_STORE) -> list[RegistryEntry]:
    """All entries whose proven HookHash matches (a hook may have many proven invariants)."""
    hh = hook_hash.upper()
    return [e for e in read_log(store) if e.hook_hash == hh]


def status_of(hook_hash: str, store: str = DEFAULT_STORE,
              pin_pubkey: Optional[str] = None) -> dict:
    """The verdict for a HookHash: PROVEN (with the invariant set + residual) / UNPROVEN / TAMPERED.

    A query for an unknown hook is UNPROVEN — loud, never an implicit pass.
    With `pin_pubkey`, the chain must also be signed entirely by that attester.
    """
    chain_ok, reason = verify_chain(store, pin_pubkey)
    matches = entries_for(hook_hash, store)
    if not matches:
        return {"status": UNPROVEN, "hook_hash": hook_hash.upper(),
                "detail": "no proof on record for this HookHash (absence of proof is not safety)",
                "invariants": [], "chain_ok": chain_ok}
    if not chain_ok:
        return {"status": TAMPERED, "hook_hash": hook_hash.upper(),
                "detail": f"registry chain failed to verify: {reason}",
                "invariants": [], "chain_ok": False}

    invariants = sorted({e.invariant for e in matches})
    caveats = sorted({c for e in matches for c in e.manifest.get("scope_caveats", [])})
    signed = all(e.signed for e in matches)
    accounts = sorted({e.manifest.get("hook_account") for e in matches if e.manifest.get("hook_account")})
    # Per-proof detail so a verifier can REPLAY each proof (invariant + the exact prover args).
    proofs = [{"invariant": e.invariant,
               "prover_args": list(e.manifest.get("prover_args", [])),
               "entry": e.index}
              for e in matches]
    return {
        "status": PROVEN,
        "hook_hash": hook_hash.upper(),
        "invariants": invariants,
        "proofs": proofs,                    # [{invariant, prover_args, entry}] — for reverify replay
        "residual": caveats,                 # stated residual — the honesty surface
        "signed": signed,                    # all matching entries carry a verified signature
        "hook_accounts": accounts,
        "entries": [e.index for e in matches],
        "chain_ok": True,
    }


def status_of_wasm(wasm_path: str, store: str = DEFAULT_STORE,
                   pin_pubkey: Optional[str] = None) -> dict:
    """Resolve a .wasm file to its HookHash, then look up its registry status.

    This is the proof-carrying lookup: hold the bytecode, learn what's proven about it.
    """
    with open(wasm_path, "rb") as f:
        wasm = f.read()
    out = status_of(hook_hash_of(wasm), store, pin_pubkey)
    out["wasm_sha256"] = wasm_sha256_of(wasm)
    out["wasm_path"] = wasm_path
    return out


def summary(store: str = DEFAULT_STORE) -> dict:
    """Per-HookHash rollup of the whole registry, plus chain integrity + head."""
    chain_ok, reason = verify_chain(store)
    by_hook: dict[str, dict] = {}
    for e in read_log(store):
        h = by_hook.setdefault(e.hook_hash, {"hook_hash": e.hook_hash, "invariants": [],
                                             "residual": set(), "signed": True, "entries": 0})
        h["invariants"].append(e.invariant)
        h["residual"].update(e.manifest.get("scope_caveats", []))
        h["signed"] = h["signed"] and e.signed
        h["entries"] += 1
    hooks = []
    for h in by_hook.values():
        h["invariants"] = sorted(set(h["invariants"]))
        h["residual"] = sorted(h["residual"])
        hooks.append(h)
    hooks.sort(key=lambda x: x["hook_hash"])
    return {"chain_ok": chain_ok, "chain_break": reason, "head": head(store),
            "hooks": hooks, "registry_version": REGISTRY_VERSION}
