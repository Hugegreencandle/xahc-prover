"""Shared agent_guardrail invariant predicate — the NO-FORK rule.

SOUNDNESS-CRITICAL. The guardrail's two rules (spend-limit + destination-lock) are expressed
ONCE here, against an abstract `Ops` backend, so the SAME rule has two evaluators that cannot
drift:
  • the symbolic prover (`prove_guardrail.py`) evaluates them with `Z3Ops` (z3 bit-vectors),
  • the concrete watcher (`watch.py`) evaluates them with `ConcreteOps` (Python ints/bytes).

If the watcher re-implemented "drops <= LIM" by hand and it diverged from the driver, the
watcher would certify a lie. So both sides import these functions; neither forks the rule.
`tests/test_watch.py` additionally asserts predicate parity on sampled inputs.

The decode is the guardrail's own: sfAmount byte 0 masked with 0x3F (strips the not-XRP +
sign flag bits), big-endian — exactly what `prove_guardrail` proved and what
`docs/XAHAU-DEV-REFERENCE.md` documents.
"""


class Z3Ops:
    """Backend for the symbolic prover: operands are z3 BitVec(8) / BitVec(64)."""

    @staticmethod
    def mask(b, m):
        return b & m                      # z3 BitVec & int -> BitVec

    @staticmethod
    def be64(byte_list):
        import z3
        return z3.Concat(*byte_list)      # 8x BitVec(8) -> BitVec(64), big-endian

    @staticmethod
    def ugt(a, b):
        import z3
        return z3.UGT(a, b)               # unsigned >

    @staticmethod
    def any_ne(xs, ys):
        import z3
        return z3.Or(*[xs[i] != ys[i] for i in range(len(xs))])


class ConcreteOps:
    """Backend for the watcher: operands are Python ints (0..255 bytes, 64-bit values)."""

    @staticmethod
    def mask(b, m):
        return b & m

    @staticmethod
    def be64(byte_list):
        v = 0
        for x in byte_list:
            v = (v << 8) | (x & 0xFF)
        return v

    @staticmethod
    def ugt(a, b):
        return a > b                      # non-negative ints: unsigned semantics

    @staticmethod
    def any_ne(xs, ys):
        return any(xs[i] != ys[i] for i in range(len(xs)))


# ── the shared rule (one definition, evaluated by either backend) ──────────────────────────

def decode_drops(amt8, ops):
    """The guardrail's native amount decode: byte0 masked 0x3F (strip not-XRP/sign flag bits),
    big-endian over the 8 sfAmount bytes. amt8 = list of 8 byte-operands (BitVec(8) or int)."""
    return ops.be64([ops.mask(amt8[0], 0x3F)] + list(amt8[1:]))


def over_limit(drops, lim64, ops):
    """Spend-limit violation: drops strictly greater than LIM (unsigned)."""
    return ops.ugt(drops, lim64)


def dest_not_allowed(dest20, allowed20, ops):
    """Destination-lock violation: any of the 20 destination bytes differs from the allowed
    account (checked only when a DST policy is set)."""
    return ops.any_ne(dest20, allowed20)


# ── concrete expected verdict, for the watcher ─────────────────────────────────────────────

ACCEPT_OK = "ACCEPT_OK"        # the guardrail should ACCEPT this tx
SHOULD_REJECT = "SHOULD_REJECT"  # the guardrail should ROLL BACK this tx
UNVERIFIED = "UNVERIFIED"      # out of the guardrail's model — cannot decide (fail closed)


def guardrail_expected(fields, params):
    """The expected guardrail verdict for ONE concrete transaction, from the SAME rules the
    prover proved. Returns ACCEPT_OK / SHOULD_REJECT / UNVERIFIED.

    fields:
      tx_type:      int   (0 = Payment)
      account:      bytes(20)   originating account
      hook_account: bytes(20)   the account the guardrail is installed on
      amount8:      bytes(8) | None   native sfAmount bytes; None if IOU/non-native/undecodable
      destination:  bytes(20) | None
    params:
      LIM:  int           per-tx drops cap (required)
      DST:  bytes(20) | None   destination allowlist (optional)

    Fail-closed: anything we cannot fully decode within the guardrail's model -> UNVERIFIED,
    NEVER ACCEPT_OK.
    """
    # Scope: the guardrail only polices OUTGOING native Payments from its own account.
    if fields.get("tx_type") != 0:
        return ACCEPT_OK                          # not a Payment -> guardrail passes it
    if fields.get("account") != fields.get("hook_account"):
        return ACCEPT_OK                          # incoming -> guardrail passes it

    amt8 = fields.get("amount8")
    if amt8 is None or len(amt8) != 8:
        return UNVERIFIED                         # IOU / non-native / undecodable -> out of model
    lim = params.get("LIM")
    if lim is None:
        return UNVERIFIED

    drops = decode_drops(list(amt8), ConcreteOps)
    if over_limit(drops, lim, ConcreteOps):
        return SHOULD_REJECT

    dst = params.get("DST")
    if dst is not None:
        dest = fields.get("destination")
        if dest is None or len(dest) != 20:
            return UNVERIFIED
        if dest_not_allowed(list(dest), list(dst), ConcreteOps):
            return SHOULD_REJECT

    return ACCEPT_OK
