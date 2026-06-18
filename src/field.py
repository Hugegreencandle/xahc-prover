"""Targeting a named BYTE SUB-FIELD of a packed HookState value.

Real next_state layouts pack several logically-distinct fields into one state slot — e.g. Arena
Vanguard's kernel where one 16-byte slot holds [tick:u64 | resource:u64], with DIFFERENT invariants
per field (tick is monotonic-up, resource is conserved-down). The invariant drivers default to the
whole slot value; `--field SLOTHEX:OFF:LEN` lets a driver target just one sub-field.

  SLOTHEX  the state key as hex (e.g. "01" for the 1-byte key 0x01)
  OFF      byte offset of the sub-field within the slot value (0 = first/most-significant byte)
  LEN      sub-field length in bytes

Big-endian throughout (matches the engine's Concat byte order and the hooks' be64 decode).
"""
from __future__ import annotations

import z3


class FieldSpec:
    __slots__ = ("key", "off", "length")

    def __init__(self, key: str, off: int, length: int):
        self.key = key        # latin1-decoded state key (e.g. "\x01")
        self.off = off
        self.length = length

    def __repr__(self):
        return f"FieldSpec(key=0x{ord(self.key):02x}, off={self.off}, len={self.length})"


def parse_field(spec: str) -> FieldSpec:
    """Parse 'SLOTHEX:OFF:LEN' (e.g. '01:0:8') -> FieldSpec. Raises ValueError on a bad spec."""
    parts = spec.split(":")
    if len(parts) != 3:
        raise ValueError(f"--field must be SLOTHEX:OFF:LEN (e.g. 01:0:8), got {spec!r}")
    slot_hex, off_s, len_s = parts
    raw = bytes.fromhex(slot_hex)          # the state key bytes
    off, length = int(off_s), int(len_s)
    if length <= 0 or off < 0:
        raise ValueError(f"--field OFF must be >=0 and LEN >0, got off={off} len={length}")
    return FieldSpec(raw.decode("latin1"), off, length)


def bv_byte_slice(bv, off: int, length: int):
    """Extract big-endian bytes [off, off+length) of a BitVec whose width is a whole number of
    bytes. Byte 0 is the most-significant. Returns a BitVec of length*8 bits, or raises if the
    range exceeds the value width (the caller turns that into INCONCLUSIVE)."""
    total = bv.size() // 8
    if off + length > total:
        raise ValueError(f"field [{off}:{off + length}) exceeds the {total}-byte value")
    hi = (total - off) * 8 - 1
    lo = (total - (off + length)) * 8
    return z3.Extract(hi, lo, bv)
