"""Proof Registry — tamper-evident, queryable record of PROVEN hook proofs.

The fifth leg: write → simulate → prove → watch → REGISTER.
"""
from registry.registry import (  # noqa: F401
    PROVEN, UNPROVEN, TAMPERED, REGISTRY_VERSION, DEFAULT_STORE,
    RegistryEntry, add, read_log, head, verify_chain, entries_for,
    status_of, status_of_wasm, summary,
)
from registry.signing import Signer, load_signer, verify_signature, crypto_available  # noqa: F401
