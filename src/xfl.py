"""XFL — Xahau/XRPL Hook 64-bit base-10 float ("enbase-10"), implemented exactly.

This is a direct, line-for-line port of xahau-mcp/src/xfl.ts (the chain-validated
reference). DO NOT re-derive the math from memory — every constant and rounding
choice here was matched against on-ledger behaviour in the TS reference.

A WRONG XFL model is the catastrophic failure mode for a money-hook prover: a
false `PROVEN`. So this module is pure concrete reference arithmetic (Python int =
arbitrary precision, the analogue of the TS BigInt), with NO symbolic content. The
Z3 models in prover.py call into this ONLY when every operand of an op is concrete
("fold-to-literal"); any symbolic operand forces an over-approximation there, never
a call here.

Layout (verified: float_one() == 6089866696204910592):
  bit 63      : not-a-number flag (0 for normal numbers; =1 "is-issued" in a
                serialized STAmount value word, which XFL clears)
  bit 62      : sign (1 = positive, 0 = negative) — inverted vs IEEE
  bits 61..54 : exponent, biased by +97 (8 bits)
  bits 53..0  : mantissa, normalized to [1e15, 1e16)
value = sign * mantissa * 10^exponent ; canonical zero is the integer 0.
"""
from __future__ import annotations

MANT_MASK = (1 << 54) - 1
MIN_MANT = 1_000_000_000_000_000   # 1e15
MAX_MANT = 10_000_000_000_000_000  # 1e16 (exclusive)
SCALE = 1_000_000_000_000_000

FLOAT_ONE = 6089866696204910592

# real hook-api error codes (hooks-rs c/error.h)
INVALID_FLOAT = -10024
INVALID_ARGUMENT = -7         # hooks-rs c/error.h
CANT_RETURN_NEGATIVE = -33    # float_int cannot return a negative when absolute=0
DIVISION_BY_ZERO = -25
NOT_AN_AMOUNT = -32
TOO_SMALL = -4


class Xfl:
    __slots__ = ("zero", "sign", "mant", "exp")

    def __init__(self, zero: bool, sign: int, mant: int, exp: int):
        self.zero = zero
        self.sign = sign   # +1 / -1
        self.mant = mant
        self.exp = exp

    def __repr__(self):
        return f"Xfl(zero={self.zero}, sign={self.sign}, mant={self.mant}, exp={self.exp})"


def decode(x: int) -> Xfl:
    if x == 0:
        return Xfl(True, 1, 0, 0)
    sign = 1 if ((x >> 62) & 1) == 1 else -1
    exp = ((x >> 54) & 0xFF) - 97
    mant = x & MANT_MASK
    return Xfl(False, sign, mant, exp)


def encode(sign: int, mant: int, exp: int) -> int:
    if mant == 0:
        return 0
    m = -mant if mant < 0 else mant
    e = exp
    while m >= MAX_MANT:
        m //= 10
        e += 1
    while m < MIN_MANT:
        m *= 10
        e -= 1
    if e < -96 or e > 80:
        return INVALID_FLOAT  # out of representable range
    sign_bit = 1 if sign > 0 else 0
    return (sign_bit << 62) | ((e + 97) << 54) | m


def floatSet(exp: int, mant: int) -> int:
    """float_set(exponent, mantissa) -> XFL"""
    if mant == 0:
        return 0
    sign = -1 if mant < 0 else 1
    return encode(sign, -mant if mant < 0 else mant, exp)


def floatInt(x: int, dp: int, absolute: bool) -> int:
    """float_int(xfl, decimalPlaces, absolute) -> integer (e.g. drops). Floors toward zero."""
    f = decode(x)
    if f.zero:
        return 0
    if not isinstance(dp, int) or dp < 0 or dp > 15:
        return INVALID_ARGUMENT
    if f.sign < 0 and not absolute:
        return CANT_RETURN_NEGATIVE
    shift = f.exp + dp
    if shift >= 0:
        return f.mant * 10 ** shift
    return f.mant // 10 ** (-shift)


def _cmpMag(a: Xfl, b: Xfl) -> int:
    # compare positive magnitudes a,b (both non-zero)
    ea, eb = a.exp, b.exp
    ma, mb = a.mant, b.mant
    if ea > eb:
        ma *= 10 ** (ea - eb)
    elif eb > ea:
        mb *= 10 ** (eb - ea)
    return 0 if ma == mb else (1 if ma > mb else -1)


def floatCmp(xa: int, xb: int) -> int:
    """signed comparison: -1 if a<b, 0 if equal, 1 if a>b"""
    a, b = decode(xa), decode(xb)
    va = 0 if a.zero else a.sign
    vb = 0 if b.zero else b.sign
    if va != vb:
        return -1 if va < vb else 1
    if a.zero and b.zero:
        return 0
    mag = _cmpMag(a, b)
    return -mag if a.sign < 0 else mag  # for negatives, larger magnitude = smaller value


# VERIFIED against hooks-rs c/hookapi.h: COMPARE_EQUAL=1, COMPARE_LESS=2, COMPARE_GREATER=4.
EQ_FLAG = 1
LT_FLAG = 2
GT_FLAG = 4


def floatCompare(xa: int, xb: int, mode: int) -> int:
    """float_compare(a,b,mode) — flags 1=EQ, 2=LT, 4=GT. Returns 1/0."""
    c = floatCmp(xa, xb)  # -1,0,1
    truth = False
    if mode & EQ_FLAG and c == 0:
        truth = True
    if mode & LT_FLAG and c < 0:
        truth = True
    if mode & GT_FLAG and c > 0:
        truth = True
    return 1 if truth else 0


def floatNegate(x: int) -> int:
    if x == 0:
        return 0
    return x ^ (1 << 62)


def floatMantissa(x: int) -> int:
    return decode(x).mant


def floatSign(x: int) -> int:
    f = decode(x)
    return 0 if f.zero else (1 if f.sign < 0 else 0)


def floatSum(xa: int, xb: int) -> int:
    a, b = decode(xa), decode(xb)
    if a.zero:
        return xb
    if b.zero:
        return xa
    e = min(a.exp, b.exp)
    ma = (-1 if a.sign < 0 else 1) * a.mant * 10 ** (a.exp - e)
    mb = (-1 if b.sign < 0 else 1) * b.mant * 10 ** (b.exp - e)
    s = ma + mb
    if s == 0:
        return 0
    return encode(-1 if s < 0 else 1, -s if s < 0 else s, e)


def floatMultiply(xa: int, xb: int) -> int:
    a, b = decode(xa), decode(xb)
    if a.zero or b.zero:
        return 0
    sign = 1 if a.sign == b.sign else -1
    return encode(sign, a.mant * b.mant, a.exp + b.exp)


def floatDivide(xa: int, xb: int) -> int:
    a, b = decode(xa), decode(xb)
    if b.zero:
        return DIVISION_BY_ZERO
    if a.zero:
        return 0
    sign = 1 if a.sign == b.sign else -1
    scaled = (a.mant * 10 ** 17) // b.mant
    return encode(sign, scaled, a.exp - b.exp - 17)


def floatInvert(x: int) -> int:
    return floatDivide(FLOAT_ONE, x)


# NOTE: all ops here TRUNCATE on normalization (encode); they do NOT round-half-up
# like xahaud, so float_mulratio's round_up flag is NOT modeled. Documented gap.
def floatMulratio(x: int, _round_up: int, num: int, den: int) -> int:
    if den == 0:
        return DIVISION_BY_ZERO
    f = decode(x)
    if f.zero or num == 0:
        return 0
    scaled = (f.mant * num * 10 ** 17) // den
    return encode(f.sign, scaled, f.exp - 17)


def floatOne() -> int:
    return FLOAT_ONE
