"""Optional Ed25519 attestation for registry entries.

The registry is tamper-evident WITHOUT signatures (the hash chain alone detects any
edit/reorder/drop). Signatures add *attester authenticity*: "this proof was registered
by the holder of key K", which is what turns a private log into a credible public
registry others can trust.

Dependency-light by design: signing is only available if the `cryptography` package is
importable. Absent it, `load_signer` returns None and entries are unsigned-but-tamper-
evident — never a hard failure. Verification of an already-signed entry likewise degrades
to a loud failure (cannot verify ⇒ not verified) rather than a false pass.

Key format: a 32-byte Ed25519 private seed, stored as 64 hex chars in a keyfile, or via
the XAHC_REGISTRY_KEY env var. Generate one with `python -m registry keygen`.
"""
from __future__ import annotations

import os
from typing import Optional

try:  # optional dependency
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover - exercised only where cryptography is absent
    _HAVE_CRYPTO = False


def crypto_available() -> bool:
    return _HAVE_CRYPTO


class Signer:
    """Wraps an Ed25519 private key. Construct via load_signer / generate."""

    def __init__(self, private_key):
        self._sk = private_key

    @classmethod
    def generate(cls) -> "Signer":
        if not _HAVE_CRYPTO:
            raise RuntimeError("cannot generate a key: `cryptography` is not installed")
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed_hex(cls, seed_hex: str) -> "Signer":
        if not _HAVE_CRYPTO:
            raise RuntimeError("cannot load a key: `cryptography` is not installed")
        seed = bytes.fromhex(seed_hex.strip())
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be exactly 32 bytes (64 hex chars)")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    def seed_hex(self) -> str:
        raw = self._sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption())
        return raw.hex()

    def public_hex(self) -> str:
        raw = self._sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        return raw.hex()

    def sign(self, message_hex: str) -> str:
        # The message is the entry_hash hex string; we sign its ASCII/UTF-8 bytes.
        # verify_signature uses the identical encoding, so signatures are consistent.
        return self._sk.sign(message_hex.encode("utf-8")).hex()


def load_signer(key: Optional[str] = None) -> Optional[Signer]:
    """Best-effort signer from an explicit keyfile path, else XAHC_REGISTRY_KEY env.

    Returns None (unsigned mode) if crypto is unavailable or no key is configured.
    """
    if not _HAVE_CRYPTO:
        return None
    seed_hex = None
    if key and os.path.exists(key):
        with open(key) as f:
            seed_hex = f.read().strip()
    elif key:
        seed_hex = key.strip()                  # allow passing the seed hex directly
    elif os.environ.get("XAHC_REGISTRY_KEY"):
        seed_hex = os.environ["XAHC_REGISTRY_KEY"].strip()
    if not seed_hex:
        return None
    return Signer.from_seed_hex(seed_hex)


def verify_signature(pubkey_hex: Optional[str], message_hex: str, sig_hex: Optional[str]) -> bool:
    """Verify an Ed25519 signature. FAIL CLOSED: unverifiable ⇒ False (never a false pass)."""
    if not (pubkey_hex and sig_hex):
        return False
    if not _HAVE_CRYPTO:
        # An entry is signed but we cannot check it here — do NOT report it as verified.
        return False
    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        pk.verify(bytes.fromhex(sig_hex), message_hex.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False
