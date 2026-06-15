"""The Prover — symbolic execution of a Hook's WASM with a Z3 backend.

Executes hook() over SYMBOLIC inputs (otxn fields, hook params, account), forking
at every branch and unrolling guard-bounded loops, then checks an invariant on
every path that reaches `accept`. Output is a proof (no accepting path violates
the invariant) or a concrete counterexample transaction.

Hooks are NOT Turing-complete and are guard-bounded, so the path space is finite
and the byte-level decode is pure bit-vector arithmetic — exactly what an SMT
solver decides. This is the property that makes Xahau Hooks provable where
arbitrary EVM contracts are not.
"""
from __future__ import annotations
import z3
from wasm import parse
import xfl

# Hook API field ids the models recognize
SF_AMOUNT = 0x60001
SF_ACCOUNT = 0x80001
SF_DESTINATION = 0x80003

# XFL bit layout (see xfl.py — verified float_one()==6089866696204910592)
XFL_SIGN_BIT = 62          # 1 = positive, 0 = negative (inverted vs IEEE)
XFL_NAN_BIT = 63           # set in a serialized issued STAmount value word; XFL clears it
XFL_MANT_MASK = (1 << 54) - 1
XFL_EXP_BIAS = 97

# float_compare mode flags — HARD-CODED, verified vs hooks-rs c/hookapi.h.
# A wrong flag map => a false PROVEN, so these are NOT to be "corrected".
FCMP_EQ = 1
FCMP_LT = 2
FCMP_GT = 4

# float_* host error sentinels (negative => error / rollback trigger in hooks)
FE_INVALID_FLOAT = xfl.INVALID_FLOAT       # -10024
FE_INVALID_ARGUMENT = xfl.INVALID_ARGUMENT # -7
FE_CANT_RETURN_NEGATIVE = xfl.CANT_RETURN_NEGATIVE  # -33
FE_DIVISION_BY_ZERO = xfl.DIVISION_BY_ZERO # -25
FE_NOT_AN_AMOUNT = xfl.NOT_AN_AMOUNT       # -32

LOOP_UNROLL = 64  # generous finite bound; guard maxiter is <= this for real hooks
STACK_PTR_INIT = 0x10000  # global 0 (clang __stack_pointer) — concrete


def conc(bv) -> int:
    s = z3.simplify(bv)
    if z3.is_bv_value(s):
        return s.as_long()
    raise RuntimeError(f"symbolic value where concrete required: {bv}")


class Terminal(Exception):
    pass


class Path:
    __slots__ = ("stack", "locals", "globals", "mem", "cons", "guards", "writes",
                 "writes_bytes",
                 "emit_count", "emits", "emits_iou", "fees", "fsets",
                 "reserve_n", "reserve_calls")

    def __init__(self):
        self.stack: list = []
        self.locals: list = []
        self.globals: dict = {}
        self.mem: dict = {}     # concrete addr -> BitVec(8)
        self.cons: list = []    # path constraints (z3 Bool)
        self.guards: dict = {}  # guard id -> crossings so far on this path
        self.writes: dict = {}  # state key (str) -> last value written (BitVec) on this path
        # Same writes, kept as the EXACT big-endian byte list (BitVec(8) per byte) staged on
        # this path. `state` read-after-write returns these bytes byte-for-byte so a partial
        # / width-mismatched read of a staged value is faithful (writes[] is only the whole-
        # value Concat that monotonic / time_nonce consume). Mirrors `writes` 1:1.
        self.writes_bytes: dict = {}  # state key (str) -> list[BitVec(8)] big-endian (byte0=MSB)
        self.emit_count: int = 0  # number of emit() calls on this path
        self.emits: list = []     # emitted native drops (BitVec64) or None if unparseable
        self.emits_iou: list = [] # emitted IOU value as (xfl_bv, cur, iss) or None per emit
        self.fees: list = []      # per-emit base fee (BitVec64) charged to the emitting acct
        self.fsets: list = []     # foreign-state-set events: (acct_bytes|None, granted:Bool, ret)
        # ---- #7 emission-burden (etxn_reserve count) ----
        # The emit budget the hook DECLARED via etxn_reserve(n). xahaud semantics: the FIRST
        # successful etxn_reserve(n) binds the budget; a second call returns -8 ALREADY_SET and
        # binds nothing. emit() fails -13 TOO_MANY_EMITTED_TXN once emit_count would exceed it.
        # reserve_n = the BitVec64 `n` from the FIRST etxn_reserve on the path, or None if the
        # hook never reserved (budget 0 -> any emit overflows). reserve_calls counts the calls
        # so the driver can fail closed on a second (symbolic-binding-ambiguous) reservation.
        self.reserve_n = None     # BitVec64 declared emit budget (first etxn_reserve), or None
        self.reserve_calls: int = 0  # how many etxn_reserve calls occurred on this path

    def clone(self) -> "Path":
        p = Path()
        p.stack = list(self.stack)
        p.locals = list(self.locals)
        p.globals = dict(self.globals)
        p.mem = dict(self.mem)
        p.cons = list(self.cons)
        p.guards = dict(self.guards)
        p.writes = dict(self.writes)
        p.writes_bytes = {k: list(v) for k, v in self.writes_bytes.items()}
        p.emit_count = self.emit_count
        p.emits = list(self.emits)
        p.emits_iou = list(self.emits_iou)
        p.fees = list(self.fees)
        p.fsets = list(self.fsets)
        p.reserve_n = self.reserve_n
        p.reserve_calls = self.reserve_calls
        return p


def feasible(cons) -> bool:
    """Is this path's constraint set satisfiable?

    SOUNDNESS: `feasible` is used both to PRUNE paths in the engine and to SKIP
    paths in some drivers. In BOTH directions the conservative answer to a Z3
    `unknown` (timeout/incompleteness) is True — keep the path. Treating `unknown`
    as infeasible would silently drop a possibly-real path (and with it a possibly
    -real counterexample), which is exactly the false-PROVEN failure mode. So only
    a definitive `unsat` is allowed to discard a path; `sat` and `unknown` both
    keep it (the eventual violation check re-runs the solver and reports `unknown`
    as INCONCLUSIVE there).
    """
    s = z3.Solver()
    s.add(*cons)
    return s.check() != z3.unsat


class Engine:
    def __init__(self, wasm: bytes):
        self.imports, self.funcs, self.datas, self.globals_init, self.indirect = parse(wasm)
        self.inputs: dict = {}       # name -> list[BitVec(8)] symbolic input bytes
        self.accepts: list = []      # (code:int|None, cons) per accepting path
        self.accepts_full: list = [] # (code, cons, writes) — same paths, with state writes
        self.rollbacks: list = []    # (code, cons)
        self.guard_viols: list = []  # (guard_id, maxiter, cons) per GUARD_VIOLATION path
        self.state_old: dict = {}    # state key (str) -> symbolic old value bytes (list[BitVec8])
        self.emits_on_accept: list = []  # (cons, emits, emit_count) per accepting path
        self.iou_emits_on_accept: list = []  # (cons, emits_iou, emit_count) per accepting path
        # ---- #7 emission-burden ----
        # Per accepting path: (cons, emit_count:int, reserve_n:BitVec64|None, reserve_calls:int).
        # reserve_n is the declared emit budget from the FIRST etxn_reserve(n) (None = the hook
        # never reserved -> budget 0). The driver proves accept => emit_count <= reserved.
        self.emission_on_accept: list = []
        self.hook = next(f for f in self.funcs if f.name == "hook")
        # #7 emission-burden: does this module EXPORT a callback (`cbak`)? A cbak runs when an
        # emitted txn settles and can itself emit / set hook_again, so the emission burden can
        # grow across re-entries the engine does NOT model. The emission driver uses this to
        # fail closed (INCONCLUSIVE) — it only proves the STATIC per-invocation reserve bound.
        self.has_cbak = any(getattr(f, "name", None) == "cbak" for f in self.funcs)
        self._g_idx = self.imports.index("_g") if "_g" in self.imports else -1
        # SOUNDNESS: set when a still-feasible loop back-edge is dropped at the
        # unroll bound. If True, the analysis is INCOMPLETE and must NOT claim
        # PROVEN — deeper iterations were not explored.
        self.hit_bound = False
        # SOUNDNESS: opcodes the decoder accepts but the interpreter cannot model
        # (e.g. clang's `switch` -> br_table, call_indirect). Reaching one means the
        # analysis is INCOMPLETE for that path; the verdict must be INCONCLUSIVE,
        # never PROVEN. Recorded here (rather than crashing with a confusing stack
        # underflow) so drivers can fail closed.
        self.unsupported = set()
        # SOUNDNESS (XFL/money): ops whose RESULT VALUE we could not compute soundly
        # (any symbolic operand to a nonlinear float op) and replaced with a FRESH
        # over-approximating symbolic. The value carries NO equality to the true XFL
        # result. A driver MUST return INCONCLUSIVE (never PROVEN) if a value tainted
        # by one of these can reach the invariant. Surfaced like self.unsupported.
        self.float_overapprox = set()
        # ---- #8 time/nonce dependence ----
        # ledger_nonce / ledger_last_time are SYMBOLIC (an attacker can influence which
        # ledger their tx lands in, and the nonce is host-grindable predictable bytes —
        # NOT secure randomness). Every BitVec symbol produced by a ledger_nonce read is
        # registered here; the time-nonce driver checks whether any ACCEPT path's decision
        # depends on one of these (a security decision gated on a grindable value = exploit).
        # ledger_seq is ALSO symbolic now (was a concrete 1000, which silently made every
        # seq-gated branch decidable one way — a latent vacuous/false result).
        self.nonce_syms: list = []   # z3 BitVec(8) symbols returned by ledger_nonce
        self.time_syms: list = []    # z3 BitVec symbols for ledger_last_time / ledger_seq
        self.ledger_seq_sym = None   # the symbolic ledger_seq (shared per run)
        self.ledger_time_sym = None  # the symbolic ledger_last_time (shared per run)
        # ---- #6 foreign-state authorization ----
        # Each state_foreign_set call records (cons, target_account_bytes, authorized:Bool).
        # `authorized` is True only if a HookGrant covering that account is MODELED on the
        # path. With NO grant model wired (the default), every foreign-set is UNauthorized
        # -> a counterexample. If foreign-state modeling is incomplete for a path we set
        # foreign_unsound so the driver fails closed (INCONCLUSIVE), never PROVEN.
        self.foreign_sets_on_accept: list = []  # (cons, [(acct,granted,ret)...]) per accept path
        self.foreign_unsound = set()     # tags for foreign-state ops we couldn't model soundly
        # ---- #5 reserve safety ----
        # Symbolic standing account balance + reserve params (base + owner_count*inc), all
        # bitvecs. Populated lazily the first time a reserve-aware host fn is read so an
        # ordinary hook is untouched. Used by prove_reserve to check no accept leaves
        # balance - (emitted + fees) below the reserve.
        self.acct_balance = None     # BitVec64 standing XAH balance (drops)
        self.reserve_base = None     # BitVec64 reserve base (drops)
        self.reserve_inc = None      # BitVec64 reserve increment (drops)
        self.owner_count = None      # BitVec64 owner count
        self.fees_on_accept: list = []   # (cons, total_fee_bv) per accepting path (emit fees)
        # SOUNDNESS (reserve): the per-emit base fee charged to the emitting account is the
        # network-dependent `etxn_fee_base` value, which ESCALATES under load and is only
        # bounded BELOW by the host base fee (10 drops). Pinning it at concrete 10 would
        # UNDER-COUNT outflow under fee escalation -> a false PROVEN for reserve safety. We
        # model it as ONE shared symbolic value `>= 10` (the host floor), returned by BOTH
        # `etxn_fee_base` (what the hook reads) and charged in `emit` (what the host deducts),
        # so the proof must hold for EVERY fee >= base. Lazily created the first time a fee is
        # needed (see _base_fee) so a non-emitting hook is untouched.
        self.emit_base_fee = None    # BitVec64 symbolic per-emit base fee (>= 10), shared per run
        self.HOST_BASE_FEE = 10      # host base-fee floor in drops (etxn_fee_base lower bound)
        self._undef = 0              # counter for fresh uninitialized-memory bytes
        self._float_fresh = 0        # counter for fresh over-approx float results
        self._extra_forks = []       # error-sentinel sibling paths from the current host_call
        self._depth = 0              # call-inlining depth (recursion guard)

    def fresh_bytes(self, name: str, n: int):
        bs = [z3.BitVec(f"{name}_{i}", 8) for i in range(n)]
        self.inputs[name] = bs
        return bs

    # ---- memory (concrete addressing) ----
    def store_bytes(self, p: Path, addr: int, bs: list):
        for k, b in enumerate(bs):
            p.mem[addr + k] = b

    def load_byte(self, p: Path, addr: int):
        b = p.mem.get(addr)
        if b is None:
            # SOUND: an unwritten byte is the WORST CASE — a fresh symbolic, not 0.
            # Stable per (address) so repeated reads agree within a path.
            b = z3.BitVec(f"memundef_{addr}", 8)
            p.mem[addr] = b
        return b

    def load(self, p: Path, addr: int, n: int, signed: bool, to64: bool):
        # little-endian assemble n bytes
        parts = [self.load_byte(p, addr + k) for k in range(n)]  # parts[0] = low
        val = parts[-1]
        for b in reversed(parts[:-1]):
            val = z3.Concat(val, b)  # high..low
        bits = n * 8
        target = 64 if to64 else 32
        if signed:
            val = z3.SignExt(target - bits, val)
        else:
            val = z3.ZeroExt(target - bits, val)
        return val

    def store(self, p: Path, addr: int, n: int, val):
        for k in range(n):
            p.mem[addr + k] = z3.Extract(8 * k + 7, 8 * k, val)

    def _base_fee(self, p: Path):
        """The symbolic per-emit base fee (>= host floor), shared across the run.

        SOUNDNESS: a single shared BitVec64 returned by `etxn_fee_base` and charged by `emit`,
        constrained `UGE(fee, HOST_BASE_FEE)`. The floor constraint is appended to the path's
        constraints the first time the fee is used on that path, so it flows into
        `fees_on_accept`/`cons` and every consumer (e.g. prove_reserve) sees `fee in [10, INF)`.
        Modeling the fee as `>= base` (not concrete 10) means outflow is never UNDER-counted
        under fee escalation, closing the reserve-safety false-PROVEN.
        """
        if self.emit_base_fee is None:
            self.emit_base_fee = z3.BitVec("emit_base_fee", 64)
        fee = self.emit_base_fee
        floor = z3.UGE(fee, z3.BitVecVal(self.HOST_BASE_FEE, 64))
        # Add the floor to THIS path once (avoid duplicate identical constraints).
        if not any(c is floor or z3.eq(c, floor) for c in p.cons):
            p.cons.append(floor)
        return fee

    # ---- XFL (issued-amount float) modeling helpers ----
    @staticmethod
    def _is_concrete(bv) -> bool:
        return z3.is_bv_value(z3.simplify(bv))

    @staticmethod
    def _val(bv) -> int:
        return z3.simplify(bv).as_long()

    def _fresh_float(self, tag: str):
        """A fresh, unconstrained 64-bit symbolic XFL — the SOUND over-approximation
        for an op whose value we cannot compute (any symbolic nonlinear operand).
        Unique per call-site so two over-approximated results are never forced equal."""
        self._float_fresh += 1
        return z3.BitVec(f"floatoa_{tag}_{self._float_fresh}", 64)

    def _xfl_components(self, x):
        """Decode an XFL bitvec into (is_zero:Bool, sign01:BV1[bit62],
        exp_unbiased:BV(signed-ish int as BV16), mant:BV64). EXACT bit ops only —
        no 10^exp. mant is zero-extended; exp is the biased field minus 97 as a
        signed 16-bit value (range comfortably fits exp in [-97,158])."""
        is_zero = (x == z3.BitVecVal(0, 64))
        sign01 = z3.Extract(XFL_SIGN_BIT, XFL_SIGN_BIT, x)              # BV1: 1=positive
        exp_field = z3.ZeroExt(8, z3.Extract(61, 54, x))               # BV16: biased exp 0..255
        exp = exp_field - z3.BitVecVal(XFL_EXP_BIAS, 16)               # BV16 signed: unbiased
        mant = z3.ZeroExt(10, z3.Extract(53, 0, x))                    # BV64: 54-bit mantissa
        return is_zero, sign01, exp, mant

    def _float_cmp_c(self, a, b):
        """Build c in {-1,0,1} (as BV8) = signed XFL comparison, using ONLY linear
        BV inequalities — NO 10^exp. Mirrors xfl.floatCmp EXACTLY.

        Soundness of lexicographic (exp,mant) magnitude compare: every normal XFL
        mantissa is normalized to [1e15,1e16) — a FIXED 16-decimal-digit width — so a
        strictly larger exponent ALWAYS means a strictly larger magnitude regardless
        of mantissa, and equal exponents compare by mantissa. That is exactly what
        cmpMag computes via scaling, without needing the 10^ scale. For inputs that
        are NOT normalized (an adversary hand-crafting a denormal XFL) this could
        differ from xahaud; see _float_normalized() guard below — when a compared XFL
        is symbolic we additionally constrain it to the normalized mantissa range so
        the lexicographic compare is faithful, and over-approx otherwise.
        """
        za, sa, ea, ma = self._xfl_components(a)
        zb, sb, eb, mb = self._xfl_components(b)
        # value-sign: 0 if zero else (+1 if sign01==1 else -1)
        one8, zero8, neg8 = z3.BitVecVal(1, 8), z3.BitVecVal(0, 8), z3.BitVecVal(-1, 8)
        va = z3.If(za, zero8, z3.If(sa == z3.BitVecVal(1, 1), one8, neg8))
        vb = z3.If(zb, zero8, z3.If(sb == z3.BitVecVal(1, 1), one8, neg8))
        # magnitude compare (both non-zero, same sign): lexicographic (exp, mant)
        mag = z3.If(ea > eb, one8,
              z3.If(ea < eb, neg8,
              z3.If(z3.UGT(ma, mb), one8,
              z3.If(z3.ULT(ma, mb), neg8, zero8))))
        # for negatives, larger magnitude = smaller value (flip)
        signed_mag = z3.If(sa == z3.BitVecVal(1, 1), mag, -mag)
        c = z3.If(va != vb,
                  z3.If(va < vb, neg8, one8),       # different value-signs decide directly
                  z3.If(z3.And(za, zb), zero8, signed_mag))
        return c

    def _float_normalized(self, x):
        """Constraint that a symbolic XFL is either canonical zero OR has a mantissa
        in the normalized range [1e15,1e16) and a representable exponent. Asserting
        this on symbolic XFL operands of float_compare keeps the lexicographic
        magnitude compare faithful to xahaud (which only ever produces normalized
        XFLs). Sound: every XFL the host can hand a hook satisfies this; constraining
        to it cannot invent a counterexample, only avoids a spurious one from an
        unreachable denormal encoding."""
        za, sa, ea, ma = self._xfl_components(x)
        norm = z3.And(z3.UGE(ma, z3.BitVecVal(xfl.MIN_MANT, 64)),
                      z3.ULT(ma, z3.BitVecVal(xfl.MAX_MANT, 64)),
                      ea >= z3.BitVecVal(-96, 16), ea <= z3.BitVecVal(80, 16))
        return z3.Or(x == z3.BitVecVal(0, 64), norm)

    # ---- host functions ----
    def host_call(self, name: str, p: Path):
        st = p.stack
        if name == "_g":
            maxiter = conc(st.pop()); gid = conc(st.pop()); st.append(z3.BitVecVal(1, 32))
            # Model the on-chain guard rule EXACTLY: _g(id, maxiter) may be crossed
            # at most `maxiter` times per hook call; crossing it more is a runtime
            # GUARD_VIOLATION (the hook is killed -> rollback). Counting crossings
            # 1:1 with the host (no unroll slack) is what makes guard-termination
            # provable: a fixed-bound loop trips nothing; a data-dependent loop an
            # attacker can drive past its budget terminates this path as a violation.
            p.guards[gid] = p.guards.get(gid, 0) + 1
            if p.guards[gid] > maxiter:
                self.guard_viols.append((gid, maxiter, list(p.cons)))
                raise Terminal()
            return
        if name == "otxn_type":
            t = z3.BitVec("otxn_type", 64)
            self.inputs.setdefault("otxn_type", t)
            st.append(t); return
        if name == "hook_account":
            wlen = conc(st.pop()); wptr = conc(st.pop())
            bs = self.inputs.get("hookacc") or self.fresh_bytes("hookacc", 20)
            self.store_bytes(p, wptr, bs[:min(20, wlen)])
            st.append(z3.BitVecVal(20, 64)); return
        if name == "otxn_field":
            fid = conc(st.pop()); wlen = conc(st.pop()); wptr = conc(st.pop())
            if fid == SF_AMOUNT:
                # sfAmount is EITHER native (8-byte value word, bit63=0) OR issued
                # (48-byte STAmount: 8-byte XFL value word with bit63=1, + 20 currency
                # + 20 issuer). The hook signals which by the write-buffer size it
                # passes: a 48-byte read wants the issued layout. Native stays the
                # default 8-byte path so existing drivers are untouched.
                if wlen >= 48:
                    bs = self.fresh_bytes("amt48", 48)
                    self.store_bytes(p, wptr, bs)
                    # bit63 of byte0 = is-issued. The XFL value word (bytes 0..7) is the
                    # serialized value with bit63 set; XFL clears it. Expose a clean
                    # 64-bit XFL for IOU drivers AND constrain the read to a valid issued
                    # STAmount (bit63=1) so the decode is faithful (sound: a native
                    # amount wouldn't have been read with a 48-byte buffer).
                    word = z3.Concat(*bs[:8])                      # big-endian 8-byte value word
                    p.cons.append(z3.Extract(63, 63, word) == z3.BitVecVal(1, 1))
                    xflv = word & z3.BitVecVal(~(1 << XFL_NAN_BIT) & ((1 << 64) - 1), 64)
                    # SOUND: an on-ledger issued STAmount is always a CANONICAL (normalized)
                    # XFL (mantissa in [1e15,1e16), exponent in range). Constrain the symbolic
                    # incoming amount to normalized AT THE SOURCE so the engine's lexicographic
                    # XFL ordering (_float_cmp_c) is valid for EVERY consumer — including the DSL
                    # `_cmp`, which otherwise compared un-normalized symbolic XFLs (latent
                    # false-PROVEN on denormals). Hand drivers already add this per-path; doing
                    # it here makes it unconditional.
                    p.cons.append(self._float_normalized(xflv))
                    self.inputs["amt_xfl"] = xflv
                    self.inputs["amt48"] = bs
                    st.append(z3.BitVecVal(48, 64))
                else:
                    bs = self.fresh_bytes("amt", 8); self.store_bytes(p, wptr, bs); st.append(z3.BitVecVal(8, 64))
            elif fid == SF_ACCOUNT:
                bs = self.fresh_bytes("origin", 20); self.store_bytes(p, wptr, bs); st.append(z3.BitVecVal(20, 64))
            elif fid == SF_DESTINATION:
                bs = self.fresh_bytes("dest", 20); self.store_bytes(p, wptr, bs); st.append(z3.BitVecVal(20, 64))
            else:
                # SOUND generalization (was: always-absent -29). Any other otxn field
                # is modeled with SYMBOLIC content AND a symbolic return length, so a
                # hook gating accept/rollback on this field's presence or value is
                # actually explored. The old always-absent could SKIP a real accepting
                # path (field present) -> a latent vacuous proof. Mirrors hook_param.
                n = max(1, min(wlen, 256))
                key = f"otxn_field:{fid:x}"
                bs = self.inputs.get(key)
                if bs is None or len(bs) < n:
                    bs = self.fresh_bytes(key, n)
                self.store_bytes(p, wptr, bs[:n])
                ret = z3.BitVec(f"otxn_field_ret:{fid:x}", 64)
                self.inputs[f"otxn_field_ret:{fid:x}"] = ret  # expose for invariant scoping
                st.append(ret)
            return
        if name == "hook_param":
            klen = conc(st.pop()); kptr = conc(st.pop()); wlen = conc(st.pop()); wptr = conc(st.pop())
            # key bytes (concrete, from the data section) name the parameter
            key = bytes(conc(self.load_byte(p, kptr + i)) for i in range(klen))
            kn = key.decode("latin1")
            n = max(1, min(wlen, 256))
            bs = self.inputs.get(f"param:{kn}")
            if bs is None or len(bs) < n:
                bs = self.fresh_bytes(f"param:{kn}", n)
            self.store_bytes(p, wptr, bs[:n])
            # SOUND: the host's return (param length, or negative if absent) is
            # SYMBOLIC, so every length-gated branch — e.g. the guardrail's
            # `hook_param(DST) == 20` destination lock — is actually explored.
            ret = z3.BitVec(f"hook_param_ret:{kn}", 64)
            self.inputs[f"hook_param_ret:{kn}"] = ret    # expose for invariant scoping
            st.append(ret); return
        if name == "state":
            # state(write_ptr, write_len, kread_ptr, kread_len) -> bytes read
            klen = conc(st.pop()); kptr = conc(st.pop()); wlen = conc(st.pop()); wptr = conc(st.pop())
            kn = bytes(conc(self.load_byte(p, kptr + i)) for i in range(klen)).decode("latin1")
            n = max(1, min(wlen, 256))
            # SAME-INVOCATION READ-AFTER-WRITE (faithful to xahaud): a `state` read sees the
            # value just STAGED by an earlier `state_set` in THIS invocation. If this key was
            # written on this path, return the staged bytes (byte-exact); otherwise fall back
            # to the SOUND worst case — a FRESH symbolic prior value (the slot pre-exists with
            # an unknown value; you can only "decrease" something already there).
            #
            # SOUNDNESS for prove_monotonic (the shared consumer): monotonic compares the
            # FINAL staged write against `state_old:<key>` — the PRIOR value. A correct
            # replay-guard reads the prior FIRST (writes==empty -> gets state_old), checks, then
            # writes; that read-before-write path is UNCHANGED, so state_old is still populated
            # and the prior-vs-written comparison is intact. A read-AFTER-write returns the
            # staged value, which is only ever a value the hook itself chose to persist — it can
            # never fabricate a smaller `state_old` (the prior), so it cannot make a backwards
            # write look forward. (See test_monotonic_read_after_write_violation_still_caught.)
            staged = p.writes_bytes.get(kn)
            if staged is not None:
                bs = list(staged)
                if len(bs) < n:
                    # read wants MORE bytes than were staged: xahaud returns only the slot's
                    # actual length, but to stay byte-faithful AND fail-closed we back-fill the
                    # unstaged tail with a fresh symbolic prior (worst case for those bytes).
                    old = self.state_old.get(kn)
                    if old is None or len(old) < n:
                        old = [z3.BitVec(f"state_old:{kn}_{i}", 8) for i in range(n)]
                        self.state_old[kn] = old
                    bs = bs + old[len(bs):n]
                self.store_bytes(p, wptr, bs[:n])
                st.append(z3.BitVecVal(n, 64)); return
            old = self.state_old.get(kn)
            if old is None or len(old) < n:
                old = [z3.BitVec(f"state_old:{kn}_{i}", 8) for i in range(n)]
                self.state_old[kn] = old
            self.store_bytes(p, wptr, old[:n])
            st.append(z3.BitVecVal(n, 64)); return
        if name == "state_set":
            # state_set(read_ptr, read_len, kread_ptr, kread_len) -> bytes written
            klen = conc(st.pop()); kptr = conc(st.pop()); rlen = conc(st.pop()); rptr = conc(st.pop())
            kn = bytes(conc(self.load_byte(p, kptr + i)) for i in range(klen)).decode("latin1")
            n = max(1, min(rlen, 256))
            vbytes = [self.load_byte(p, rptr + i) for i in range(n)]   # big-endian value
            p.writes[kn] = z3.Concat(*vbytes) if n > 1 else vbytes[0]
            p.writes_bytes[kn] = list(vbytes)   # byte-exact, for same-invocation read-after-write
            st.append(z3.BitVecVal(n, 64)); return
        # ---- foreign-state host fns (#6 foreign-state authorization) ----
        if name == "state_foreign":
            # state_foreign(write_ptr,wlen, kread_ptr,klen, nread_ptr,nlen, aread_ptr,alen)
            # Read another account's state. Args (8): pop in reverse. We model the read as
            # SYMBOLIC content with a SYMBOLIC return (could be absent < 0). The account is
            # (aread_ptr, alen).
            # args pushed L->R; stack top is the LAST arg (aread_len). Pop in reverse order.
            alen = conc(st.pop()); aptr = conc(st.pop())
            nlen = conc(st.pop()); nptr = conc(st.pop())
            klen = conc(st.pop()); kptr = conc(st.pop())
            wlen = conc(st.pop()); wptr = conc(st.pop())
            n = max(1, min(wlen, 256))
            idx = len(self.foreign_sets_on_accept) + len(p.fsets)
            bs = self.fresh_bytes(f"foreign_state:{idx}", n)
            self.store_bytes(p, wptr, bs[:n])
            st.append(z3.BitVec(f"state_foreign_ret:{idx}", 64)); return
        if name == "state_foreign_set":
            # state_foreign_set(read_ptr,rlen, kread_ptr,klen, nread_ptr,nlen, aread_ptr,alen)
            # Write another account's state. The HOST returns NOT_AUTHORIZED (-34) when the
            # target account A has NOT published a matching HookGrant authorizing this hook;
            # a non-negative return means a grant exists and the write succeeded.
            #
            # SOUND FORMALIZATION of "#6 foreign-state authorization": rather than (unsoundly)
            # guessing which grants exist on-ledger, we model the host return as a SYMBOLIC
            # 64-bit value that MAY be the unauthorized sentinel. A hook is authorized for
            # this write iff it DID NOT proceed-to-accept on the -34 branch — i.e. a correct
            # hook checks the return and rolls back when it's negative (XAHC_TRY / a `< 0`
            # guard). We record (path-cons, target-account-bytes, granted-flag) where
            # `granted := (ret >= 0)`. The driver then asserts: every accept path proves the
            # foreign-set was granted. Fails CLOSED: if we cannot identify the target account
            # (non-concrete alen) we tag foreign_unsound -> INCONCLUSIVE, never PROVEN.
            # args pushed L->R; stack top is the LAST arg (aread_len). Pop in reverse order.
            alen = conc(st.pop()); aptr = conc(st.pop())
            nlen = conc(st.pop()); nptr = conc(st.pop())
            klen = conc(st.pop()); kptr = conc(st.pop())
            rlen = conc(st.pop()); rptr = conc(st.pop())
            idx = len(p.fsets)
            ret = z3.BitVec(f"state_foreign_set_ret:{idx}", 64)
            self.inputs[f"state_foreign_set_ret:{idx}"] = ret
            if alen == 20:
                acct = [self.load_byte(p, aptr + i) for i in range(20)]
            else:
                # can't soundly pin the target account -> fail closed for this op
                acct = None
                self.foreign_unsound.add("state_foreign_set:account_len")
            # `granted` := the host returned success (>= 0), which on Xahau happens iff a
            # matching HookGrant authorized the write (else NOT_AUTHORIZED -34). Recorded on
            # the path so the accept handler can snapshot every foreign-set on this trace.
            granted = (ret >= z3.BitVecVal(0, 64))   # signed BV >= (z3 default)
            p.fsets.append((acct, granted, ret))
            st.append(ret); return
        # ---- emitted-transaction host fns (for balance / double-spend invariants) ----
        if name == "ledger_seq":
            # SYMBOLIC (was a concrete 1000). A submitter can choose / wait for the ledger
            # their tx is included in, so seq is attacker-influenceable within a range. A
            # legitimate escrow-style deadline (`seq >= DEADLINE`) is fine; the time/nonce
            # driver only flags NONCE dependence, never plain seq. Shared per run.
            if self.ledger_seq_sym is None:
                self.ledger_seq_sym = z3.BitVec("ledger_seq", 64)
                self.time_syms.append(self.ledger_seq_sym)
                self.inputs["ledger_seq"] = self.ledger_seq_sym
            st.append(self.ledger_seq_sym); return
        if name == "ledger_last_time":
            # SYMBOLIC close time (seconds). Attacker can nudge which ledger they land in.
            if self.ledger_time_sym is None:
                self.ledger_time_sym = z3.BitVec("ledger_last_time", 64)
                self.time_syms.append(self.ledger_time_sym)
                self.inputs["ledger_last_time"] = self.ledger_time_sym
            st.append(self.ledger_time_sym); return
        if name == "ledger_nonce":
            # ledger_nonce(write_ptr, write_len) -> 32 bytes of "randomness" + length.
            # CRITICAL SOUNDNESS NOTE: the nonce is NOT secure randomness — it is derived
            # from ledger/seed material that a determined submitter can predict or grind.
            # We model it as FRESH SYMBOLIC bytes AND register every byte symbol so the
            # time/nonce driver can detect any accept decision that hinges on it. Each call
            # gets distinct bytes (a hook reading the nonce twice gets two reads).
            wlen = conc(st.pop()); wptr = conc(st.pop())
            n = min(wlen, 32)
            bs = [z3.BitVec(f"ledger_nonce_{len(self.nonce_syms)+i}", 8) for i in range(n)]
            self.nonce_syms.extend(bs)
            self.store_bytes(p, wptr, bs)
            self.inputs.setdefault("ledger_nonce", []).extend(bs)
            st.append(z3.BitVecVal(n, 64)); return
        if name == "etxn_reserve":
            # etxn_reserve(count) declares the emit budget. xahaud: the FIRST call binds the
            # budget and returns the count; a SECOND call returns -8 ALREADY_SET and binds
            # nothing (once-per-execution). We CAPTURE the first call's `n` (concrete or
            # symbolic, widened to 64-bit) so the emission-burden driver can check
            # emit_count <= reserved per accepting path. Modeling the -8 on a re-call lets a
            # hook that does `if (etxn_reserve(2) < 0) rollback;` after an earlier reserve
            # branch correctly.
            n = st.pop()
            if n.size() != 64:
                n = z3.ZeroExt(64 - n.size(), n) if n.size() < 64 else z3.Extract(63, 0, n)
            p.reserve_calls += 1
            if p.reserve_calls == 1:
                p.reserve_n = n
                st.append(n)                                         # returns the count (>=0)
            else:
                # ALREADY_SET (-8): the binding budget is still the first call's value.
                st.append(z3.BitVecVal((-8) & ((1 << 64) - 1), 64))
            return
        if name == "etxn_details":
            wlen = conc(st.pop()); wptr = conc(st.pop())
            n = min(wlen, 138)                                       # emit-details blob
            for i in range(n):
                p.mem[wptr + i] = z3.BitVecVal(0, 8)
            st.append(z3.BitVecVal(n, 64)); return
        if name == "etxn_fee_base":
            # Return the SYMBOLIC per-emit base fee (>= host floor). xahaud computes this from
            # the network base fee, which ESCALATES under load — modeling it concrete (10) would
            # let a fee-escalation breach slip past as a false PROVEN for reserve safety.
            st.pop(); st.pop(); st.append(self._base_fee(p)); return
        if name == "emit":
            rlen = conc(st.pop()); rptr = conc(st.pop()); st.pop(); st.pop()
            p.emit_count += 1
            p.emits.append(self._emit_drops(p, rptr))
            p.emits_iou.append(self._emit_iou_xfl(p, rptr))
            # The emitting account also pays the emitted txn's base fee. We charge the SAME
            # SYMBOLIC value `etxn_fee_base` returns (>= host floor 10) — exactly the fee the
            # host deducts and the hook reads/pays. Because the fee ranges over [10, INF), the
            # reserve proof must hold for EVERY fee >= base, so outflow is never UNDER-counted
            # under fee escalation (an under-count would be a false PROVEN for reserve safety).
            # `etxn_fee_base` and `emit` share ONE symbol via _base_fee — they cannot diverge.
            p.fees.append(self._base_fee(p))
            st.append(z3.BitVecVal(32, 64)); return                 # >=0 = emitted hash len
        # ================= XFL (issued-amount) float host fns =================
        # DISCIPLINE (money-hooks): EXACT bit-ops where possible; FOLD-TO-LITERAL via
        # xfl.py for fully-concrete ops; FRESH SYMBOLIC over-approx (+ float_overapprox)
        # for any symbolic nonlinear op; mark unsupported for the truly unmodelable.
        if name == "float_one":
            st.append(z3.BitVecVal(xfl.FLOAT_ONE, 64)); return
        if name == "float_negate":
            x = st.pop()
            # EXACT: zero stays zero; else flip the sign bit (bit62)
            st.append(z3.If(x == z3.BitVecVal(0, 64), x, x ^ z3.BitVecVal(1 << XFL_SIGN_BIT, 64)))
            return
        if name == "float_mantissa":
            x = st.pop()
            # EXACT: 0 -> 0; else low 54 bits, zero-extended to 64
            mant = z3.ZeroExt(10, z3.Extract(53, 0, x))
            st.append(z3.If(x == z3.BitVecVal(0, 64), z3.BitVecVal(0, 64), mant))
            return
        if name == "float_sign":
            x = st.pop()
            # EXACT: 0 -> 0; bit62==1 (positive) -> 0; else 1 (negative). Mirrors xfl.floatSign.
            sign01 = z3.Extract(XFL_SIGN_BIT, XFL_SIGN_BIT, x)
            st.append(z3.If(x == z3.BitVecVal(0, 64), z3.BitVecVal(0, 64),
                            z3.If(sign01 == z3.BitVecVal(1, 1),
                                  z3.BitVecVal(0, 64), z3.BitVecVal(1, 64))))
            return
        if name == "float_set":
            mant = st.pop(); exp = st.pop()
            if self._is_concrete(exp) and self._is_concrete(mant):
                # FOLD: both concrete -> exact literal XFL via xfl.py
                e = z3.simplify(z3.SignExt(32, exp) if exp.size() == 32 else exp).as_long()
                e = e - (1 << 64) if e >= (1 << 63) else e         # interpret as signed
                m = self._val(mant); m = m - (1 << 64) if m >= (1 << 63) else m
                st.append(z3.BitVecVal(xfl.floatSet(e, m) & ((1 << 64) - 1), 64)); return
            # symbolic exp/mant: over-approx (encode normalization is nonlinear in 10^exp)
            self.float_overapprox.add("float_set")
            st.append(self._fresh_float("set")); return
        if name == "float_compare":
            mode = conc(st.pop()); b = st.pop(); a = st.pop()
            # EXACT ordering via linear BV compare. Constrain symbolic operands to the
            # normalized XFL range so the lexicographic magnitude compare is faithful.
            if not self._is_concrete(a):
                p.cons.append(self._float_normalized(a))
            if not self._is_concrete(b):
                p.cons.append(self._float_normalized(b))
            c = self._float_cmp_c(a, b)                            # BV8 in {-1,0,1}
            cond = z3.BoolVal(False)
            if mode & FCMP_EQ:
                cond = z3.Or(cond, c == z3.BitVecVal(0, 8))
            if mode & FCMP_LT:
                cond = z3.Or(cond, c == z3.BitVecVal(-1, 8))
            if mode & FCMP_GT:
                cond = z3.Or(cond, c == z3.BitVecVal(1, 8))
            st.append(z3.If(cond, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))); return
        if name == "float_int":
            absflag = conc(st.pop()); dp = st.pop(); x = st.pop()
            dpc = self._val(dp) if self._is_concrete(dp) else None
            # error forks: dp out of [0,15] -> -7. We need dp concrete to fold the
            # value; a symbolic dp also can't be range-checked soundly -> over-approx.
            if dpc is not None and self._is_concrete(x):
                # FOLD fully-concrete via xfl.py (exact, incl. error sentinels)
                xc = self._val(x)
                r = xfl.floatInt(xc, dpc, absflag != 0)
                st.append(z3.BitVecVal(r & ((1 << 64) - 1), 64)); return
            # symbolic value (and/or dp): fork the error/value paths SOUNDLY.
            # error: sign<0 && !abs -> -33 ; (dp range handled below if symbolic)
            za, sa, ea, ma = self._xfl_components(x)
            neg = z3.And(z3.Not(za), sa == z3.BitVecVal(0, 1))     # sign bit 0 = negative
            out_stack = st
            if absflag == 0:
                # fork: negative-input error path returns -33
                pe = p.clone(); pe.cons.append(neg); pe.stack.append(z3.BitVecVal(FE_CANT_RETURN_NEGATIVE & ((1<<64)-1), 64))
                self._extra_forks.append(pe)
                p.cons.append(z3.Not(neg))
            # value path: over-approx (mant*10^exp is nonlinear in symbolic exp)
            self.float_overapprox.add("float_int")
            r = self._fresh_float("int")
            # sound non-negativity fact: a successful float_int result is >= 0
            p.cons.append(r >= z3.BitVecVal(0, 64))   # signed BV >= (z3 default)
            out_stack.append(r); return
        if name in ("float_sum", "float_multiply", "float_divide", "float_mulratio"):
            if name == "float_mulratio":
                den = st.pop(); num = st.pop(); rnd = st.pop(); a = st.pop(); b = None
            else:
                b = st.pop(); a = st.pop()
            concrete = self._is_concrete(a) and (b is None or self._is_concrete(b))
            if name == "float_mulratio":
                concrete = concrete and self._is_concrete(num) and self._is_concrete(den)
            if concrete:
                av = self._val(a)
                if name == "float_sum":
                    r = xfl.floatSum(av, self._val(b))
                elif name == "float_multiply":
                    r = xfl.floatMultiply(av, self._val(b))
                elif name == "float_divide":
                    r = xfl.floatDivide(av, self._val(b))
                else:
                    nv = self._val(num); dv = self._val(den)
                    nv = nv - (1 << 32) if nv >= (1 << 31) else nv
                    dv = dv - (1 << 32) if dv >= (1 << 31) else dv
                    r = xfl.floatMulratio(av, self._val(rnd), nv, dv)
                st.append(z3.BitVecVal(r & ((1 << 64) - 1), 64)); return
            # SYMBOLIC: fresh over-approx + ONLY sound facts.
            self.float_overapprox.add(name)
            if name in ("float_divide", "float_mulratio"):
                # model den/divisor == 0 -> DIVISION_BY_ZERO (-25) fork, so a hook's
                # `if (q < 0) rollback` over a div-by-zero is explored. Collapsing it
                # could SKIP a rollback = false PROVEN.
                divisor = b if name == "float_divide" else den
                zb, _, _, _ = self._xfl_components(divisor)
                pe = p.clone(); pe.cons.append(zb)
                pe.stack.append(z3.BitVecVal(FE_DIVISION_BY_ZERO & ((1 << 64) - 1), 64))
                self._extra_forks.append(pe)
                p.cons.append(z3.Not(zb))
            res = self._fresh_float(name.split("_")[1])
            if name == "float_multiply" and b is not None:
                # SOUND fact: result sign bit = (sign_a XNOR sign_b) when both nonzero;
                # result is zero iff either operand is zero. (No value/magnitude claim.)
                za, sa, _, _ = self._xfl_components(a)
                zb, sb, _, _ = self._xfl_components(b)
                anyzero = z3.Or(za, zb)
                rsign = z3.Extract(XFL_SIGN_BIT, XFL_SIGN_BIT, res)
                same = (sa == sb)  # same sign bit -> positive product
                p.cons.append(z3.If(anyzero, res == z3.BitVecVal(0, 64),
                                    rsign == z3.If(same, z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))))
            st.append(res); return
        if name == "float_invert":
            x = st.pop()
            if self._is_concrete(x):
                st.append(z3.BitVecVal(xfl.floatInvert(self._val(x)) & ((1 << 64) - 1), 64)); return
            # symbolic: x==0 -> DIVISION_BY_ZERO fork (float_invert = 1/x)
            self.float_overapprox.add("float_invert")
            zx, _, _, _ = self._xfl_components(x)
            pe = p.clone(); pe.cons.append(zx)
            pe.stack.append(z3.BitVecVal(FE_DIVISION_BY_ZERO & ((1 << 64) - 1), 64))
            self._extra_forks.append(pe)
            p.cons.append(z3.Not(zx))
            st.append(self._fresh_float("invert")); return
        if name in ("float_log", "float_root"):
            # No sound model -> ALWAYS unsupported (forces INCONCLUSIVE), plus a fresh
            # symbolic so execution can continue without a stack underflow.
            if name == "float_root":
                st.pop()  # float_root(x, n) takes 2 args
            st.pop()
            self.unsupported.add(name)
            st.append(self._fresh_float(name.split("_")[1])); return
        if name == "float_sto":
            # float_sto(wp, wl, cp, cl, ip, il, xfl, field_code) -> length written.
            # STRUCTURAL per sandbox.ts: write the 48-byte issued STAmount value so a
            # conservation re-read sees real bytes. We also model x<0 -> -7 fork.
            fieldcode = conc(st.pop()); xv = st.pop()
            il = conc(st.pop()); ip = conc(st.pop())
            cl = conc(st.pop()); cp = conc(st.pop())
            wlen = conc(st.pop()); wptr = conc(st.pop())
            # x < 0 (top NaN/sign pattern) is INVALID_ARGUMENT. Fork it so a hook that
            # checks `if (alen < 0) rollback` explores the failure.
            neg = xv < z3.BitVecVal(0, 64)   # signed BV compare (z3 default for <)
            pe = p.clone(); pe.cons.append(neg); pe.stack.append(z3.BitVecVal(FE_INVALID_ARGUMENT & ((1<<64)-1), 64))
            self._extra_forks.append(pe)
            p.cons.append(z3.Not(neg))
            # issued value word = (1<<63) | xfl  (set the is-issued bit), big-endian 8 bytes
            valword = xv | z3.BitVecVal(1 << XFL_NAN_BIT, 64)
            cur = [self.load_byte(p, cp + i) for i in range(20)] if cl == 20 else [z3.BitVecVal(0, 8)] * 20
            iss = [self.load_byte(p, ip + i) for i in range(20)] if il == 20 else [z3.BitVecVal(0, 8)] * 20
            off = wptr
            if fieldcode != 0:
                # field header for sfAmount (type 6 / nth 1) is a single byte 0x61
                p.mem[off] = z3.BitVecVal(0x61, 8); off += 1
            # 8-byte big-endian value word
            for i in range(8):
                p.mem[off + i] = z3.Extract(8 * (7 - i) + 7, 8 * (7 - i), valword)
            off += 8
            for i in range(20):
                p.mem[off + i] = cur[i]
            off += 20
            for i in range(20):
                p.mem[off + i] = iss[i]
            off += 20
            st.append(z3.BitVecVal(off - wptr, 64)); return
        if name == "etxn_nonce":
            self.unsupported.add("etxn_nonce"); st.pop(); st.pop()
            st.append(z3.BitVecVal(32, 64)); return
        if name in ("accept", "rollback"):
            code = conc(st.pop()); st.pop(); st.pop()
            if name == "accept":
                self.accepts.append((code, list(p.cons)))
                self.accepts_full.append((code, list(p.cons), dict(p.writes)))
                self.emits_on_accept.append((list(p.cons), list(p.emits), p.emit_count))
                self.iou_emits_on_accept.append((list(p.cons), list(p.emits_iou), p.emit_count))
                self.fees_on_accept.append((list(p.cons), list(p.fees), p.emit_count))
                self.foreign_sets_on_accept.append((list(p.cons), list(p.fsets)))
                self.emission_on_accept.append(
                    (list(p.cons), p.emit_count, p.reserve_n, p.reserve_calls))
            else:
                self.rollbacks.append((code, list(p.cons)))
            raise Terminal()
        raise NotImplementedError(f"host fn {name} not modeled")

    def _call_local(self, local_idx, p):
        """Inline a call to a DEFINED (local) function. WASM is non-recursive in
        practice for hooks, so we execute the callee's body in a fresh frame that
        shares memory/globals/path-constraints/guards with the caller. The callee
        may fork (multiple return paths); each becomes a caller continuation with
        the callee's result value(s) pushed. A depth cap fails loud on recursion."""
        func = self.funcs[local_idx]
        self._depth += 1
        if self._depth > 256:
            raise NotImplementedError("call depth > 256 — recursion not supported (fails loud)")
        try:
            npar = func.nparams
            args = [p.stack.pop() for _ in range(npar)][::-1]
            saved_locals = p.locals
            saved_stack = list(p.stack)
            wbits = lambda vt: 64 if vt in (0x7E, 0x7C) else 32
            p.locals = list(args) + [z3.BitVecVal(0, wbits(vt)) for vt in func.localtypes]
            p.stack = []
            out = []
            for _sig, rp in self._exec_seq(func.body, [p]):
                # any escaping signal (fall-through None / return / br past body) = function return
                retvals = rp.stack[-func.nresults:] if func.nresults else []
                rp.locals = list(saved_locals)
                rp.stack = list(saved_stack) + retvals
                out.append((None, rp))
            return out
        finally:
            self._depth -= 1

    def _emit_drops(self, p, rptr):
        """Extract native drops from an emitted Payment blob (xahc payment template:
        byte0=0x12 TT, Amount field 0x61 at offset 35, 8 drops bytes at 36..43, top
        byte masked 0x3F). Returns BitVec64, or None if the blob isn't this shape —
        in which case balance proofs must treat the amount as unknown (fail closed).

        NOTE: an ISSUED (IOU) emit has bit63 of the Amount value word SET. Native
        drops do not apply to it, so this returns None for an IOU emit (fail-closed
        for native-conservation). The IOU value word is captured separately by
        _emit_iou_xfl for IOU-aware drivers."""
        try:
            if conc(self.load_byte(p, rptr)) != 0x12:
                return None
            if conc(self.load_byte(p, rptr + 35)) != 0x61:
                return None
            # native Amount is an 8-byte value word => the Fee field id (0x68) sits at
            # offset 44. An issued (48-byte) Amount pushes Fee far later, so a non-0x68
            # byte at 44 means this is an IOU emit, not native drops -> fail closed.
            after = self.load_byte(p, rptr + 44)
            if not self._is_concrete(after) or self._val(after) != 0x68:
                return None
        except RuntimeError:
            return None
        bs = [self.load_byte(p, rptr + 36 + i) for i in range(8)]
        return z3.Concat(bs[0] & 0x3F, *bs[1:])

    def _emit_iou_xfl(self, p, rptr):
        """Extract the emitted IOU value as a clean 64-bit XFL (bit63 cleared) from an
        emitted Payment blob whose Amount field is an issued STAmount (0x61 at offset
        35, 8-byte value word at 36..43 with bit63 set). Returns (xfl_bv, currency20,
        issuer20) or None if the blob isn't an issued-amount payment."""
        try:
            if conc(self.load_byte(p, rptr)) != 0x12:
                return None
            if conc(self.load_byte(p, rptr + 35)) != 0x61:
                return None
            # issued (48-byte) Amount => the byte at offset 44 is NOT the Fee field id
            # (0x68); for a native 8-byte Amount it IS 0x68. So an issued emit is
            # exactly the case where offset 44 != 0x68.
            after = self.load_byte(p, rptr + 44)
            if self._is_concrete(after) and self._val(after) == 0x68:
                return None  # native, not issued
        except RuntimeError:
            return None
        word = z3.Concat(*[self.load_byte(p, rptr + 36 + i) for i in range(8)])
        xflv = word & z3.BitVecVal(~(1 << XFL_NAN_BIT) & ((1 << 64) - 1), 64)
        cur = [self.load_byte(p, rptr + 44 + i) for i in range(20)]
        iss = [self.load_byte(p, rptr + 64 + i) for i in range(20)]
        return (xflv, cur, iss)

    # ---- the interpreter ----
    def run(self):
        f = self.hook
        p = Path()
        # params + locals at their DECLARED widths (i64 locals must init 64-bit, or a
        # read-before-write would be a wrong-width 0).
        wbits = lambda vt: 64 if vt in (0x7E, 0x7C) else 32
        ptypes = f.paramtypes or [0x7F] * f.nparams
        p.locals = [z3.BitVec(f"arg_{i}", wbits(vt)) for i, vt in enumerate(ptypes)]
        p.locals += [z3.BitVecVal(0, wbits(vt)) for vt in f.localtypes]
        # globals at their real init values (the decoder parses the global section);
        # fall back to a concrete stack pointer only if the module declared none.
        if self.globals_init:
            for idx, (val, w) in enumerate(self.globals_init):
                p.globals[idx] = z3.BitVecVal(val & ((1 << w) - 1), w)
        else:
            p.globals[0] = z3.BitVecVal(STACK_PTR_INIT, 32)
        for off, data in self.datas:
            for k, b in enumerate(data):
                p.mem[off + k] = z3.BitVecVal(b, 8)
        self._exec_seq(f.body, [p])

    def _exec_seq(self, instrs, paths):
        """Execute a sequence over a list of live paths. Returns list of
        (signal, path): signal None=fell through, ('br',d), ('return',). Terminal
        (accept/rollback) paths are recorded in self.accepts/rollbacks and dropped."""
        results = []
        live = list(paths)
        for ins in instrs:
            nxt = []
            for p in live:
                for sig, pp in self._exec(ins, p):
                    if sig is None:
                        nxt.append(pp)
                    else:
                        results.append((sig, pp))
            live = nxt
            if not live:
                break
        results.extend((None, p) for p in live)
        return results

    def _block_like(self, body, p):
        # block/if-body: a br to depth 0 targets the END (fall through after)
        out = []
        for sig, pp in self._exec_seq(body, [p]):
            if sig is None:
                out.append((None, pp))
            elif sig[0] == "br":
                d = sig[1]
                out.append((None, pp) if d == 0 else (("br", d - 1), pp))
            else:
                out.append((sig, pp))
        return out

    def _loop_budget(self, body) -> int:
        # XAHC_GUARD(n) compiles (after reposition) to `const id; const (n+1);
        # call _g` at the loop head. Unroll to the declared bound so no feasible
        # iteration is ever dropped; a loop that exceeds its guard is a runtime
        # GUARD_VIOLATION (rollback), never a hidden accept.
        consts = []
        for ins in body:
            if ins.op in ("i32.const", "i64.const"):
                consts.append(ins.imm)
            elif ins.op == "call":
                if ins.imm == self._g_idx and len(consts) >= 1 and isinstance(consts[-1], int):
                    m = consts[-1] & 0xFFFFFFFF
                    if 0 < m < (1 << 20):
                        return min(m + 2, 8192)
                consts = []
            else:
                consts = []
        return LOOP_UNROLL

    def _loop(self, body, p, budget):
        # ITERATIVE unroll (no Python recursion per iteration). The recursive form
        # blew the CPython recursionlimit (~1000) long before the advertised
        # min(maxiter+2, 8192) cap, throwing RecursionError on perfectly legitimate
        # high-iteration hooks. A worklist of (path, remaining-budget) frames honors
        # the real bound without growing the call stack with the iteration count.
        out = []
        work = [(p, budget)]
        while work:
            cur, b = work.pop()
            for sig, pp in self._exec_seq(body, [cur]):
                if sig is None:
                    out.append((None, pp))            # fell through loop body -> exit loop
                elif sig[0] == "br":
                    d = sig[1]
                    if d == 0:                         # branch to loop top -> iterate
                        if b > 0:
                            work.append((pp, b - 1))
                        else:
                            # A still-feasible back-edge dropped at the bound. The
                            # analysis is now INCOMPLETE — record it so the verdict
                            # cannot claim PROVEN (soundness over convenience).
                            self.hit_bound = True
                    else:
                        out.append((("br", d - 1), pp))
                else:
                    out.append((sig, pp))
        return out

    def _exec(self, ins, p):
        op = ins.op
        try:
            # ---- control ----
            if op == "block":
                return self._block_like(ins.body, p)
            if op == "loop":
                return self._loop(ins.body, p, self._loop_budget(ins.body))
            if op == "if":
                cond = p.stack.pop()
                out = []
                pt = p.clone(); pt.cons.append(cond != 0)
                if feasible(pt.cons):
                    out += self._block_like(ins.body, pt)
                pe = p.clone(); pe.cons.append(cond == 0)
                if feasible(pe.cons):
                    out += self._block_like(ins.alt, pe) if ins.alt else [(None, pe)]
                return out
            if op == "br":
                return [(("br", ins.imm), p)]
            if op == "br_if":
                cond = p.stack.pop()
                out = []
                pt = p.clone(); pt.cons.append(cond != 0)
                if feasible(pt.cons):
                    out.append((("br", ins.imm), pt))
                pe = p.clone(); pe.cons.append(cond == 0)
                if feasible(pe.cons):
                    out.append((None, pe))
                return out
            if op == "return":
                return [(("return",), p)]
            if op in ("unreachable", "nop"):
                return [] if op == "unreachable" else [(None, p)]
            # br_table (clang's `switch`): pop the index and fork to each labelled
            # target under `idx == k`, plus the default under `idx >= n` (unsigned).
            # The forks are exhaustive (0..n-1 and >=n cover all u32) and mutually
            # exclusive, so no reachable target is dropped — SOUND: a real accepting
            # case can't be skipped, and an infeasible case is pruned by `feasible`.
            if op == "br_table":
                tgts, deflt = ins.imm
                idx = p.stack.pop()
                w = idx.size()
                out = []
                for k, depth in enumerate(tgts):
                    pk = p.clone(); pk.cons.append(idx == z3.BitVecVal(k, w))
                    if feasible(pk.cons):
                        out.append((("br", depth), pk))
                pd = p.clone(); pd.cons.append(z3.UGE(idx, z3.BitVecVal(len(tgts), w)))
                if feasible(pd.cons):
                    out.append((("br", deflt), pd))
                return out
            # call_indirect (function-table dispatch). Sound model:
            #   - resolve the table (decoder); unresolved -> fail closed (INCONCLUSIVE)
            #   - fork over every type-matching DEFINED target under (i == its table slot),
            #     inlining it exactly like a direct call
            #   - every other index (out-of-bounds, empty slot, or type-mismatch) TRAPS in
            #     WASM -> model as a rollback (a trap can never flow a value to accept)
            #   - a table slot pointing at an IMPORT can't be inlined as a host fn -> fail
            #     closed. SOUND: every reachable callee is explored; nothing un-modelable
            #     reaches PROVEN.
            if op == "call_indirect":
                ind = self.indirect
                table = ind["table"]
                type_sigs = ind["type_sigs"]
                typeidx = ins.imm[0] if isinstance(ins.imm, tuple) else None
                tableidx = ins.imm[1] if isinstance(ins.imm, tuple) else None
                # SINGLE-TABLE assumption made explicit: the engine resolves only table 0
                # (`ind["table"]`). A dispatch through any other table index is NOT modeled —
                # fail closed (INCONCLUSIVE), never silently dispatch on table 0.
                if tableidx != 0:
                    self.unsupported.add(op); return []
                if table is None or typeidx is None or typeidx >= len(type_sigs):
                    self.unsupported.add(op); return []
                impc = ind["import_count"]
                # an import in the table => host-fn dispatch we don't model => fail closed
                if any(g < impc for g in table.values()):
                    self.unsupported.add(op); return []
                exp = (tuple(type_sigs[typeidx][0]), tuple(type_sigs[typeidx][1]))
                idx = p.stack.pop()                      # the table index (i32)
                w = idx.size()
                out = []
                matching = []                            # all type-matching defined slots
                for tidx, g in sorted(table.items()):
                    li = g - impc
                    if li < 0 or li >= len(self.funcs):
                        continue                         # out-of-range slot -> trap region
                    fti = ind["func_type_idx"][li]
                    sig = (tuple(type_sigs[fti][0]), tuple(type_sigs[fti][1]))
                    if sig != exp:
                        continue                         # type mismatch -> trap region
                    matching.append(tidx)
                    pk = p.clone(); pk.cons.append(idx == z3.BitVecVal(tidx, w))
                    if feasible(pk.cons):
                        out.extend(self._call_local(li, pk))
                # trap region: idx is not any valid type-matching slot -> WASM traps -> rollback
                pt = p.clone()
                for tidx in matching:
                    pt.cons.append(idx != z3.BitVecVal(tidx, w))
                if feasible(pt.cons):
                    self.rollbacks.append((None, list(pt.cons)))
                return out
            if op == "call":
                if ins.imm < len(self.imports):
                    name = self.imports[ins.imm]
                    self._extra_forks = []  # error-sentinel forks produced by host_call
                    try:
                        self.host_call(name, p)
                        # the primary path continues; any error-sentinel forks (e.g.
                        # div-by-zero -> -25, x<0 -> -7) continue as siblings so a hook
                        # that branches on the negative result is fully explored. A path
                        # whose constraints just became unsat is pruned by `feasible`.
                        out = [(None, p)] if feasible(p.cons) else []
                        for ep in self._extra_forks:
                            if feasible(ep.cons):
                                out.append((None, ep))
                        return out
                    except Terminal:
                        # primary path took accept/rollback; error-sentinel siblings
                        # (forked BEFORE the terminal) still need to run.
                        out = []
                        for ep in getattr(self, "_extra_forks", []):
                            if feasible(ep.cons):
                                out.append((None, ep))
                        return out
                return self._call_local(ins.imm - len(self.imports), p)
            if op == "drop":
                p.stack.pop(); return [(None, p)]
            if op == "select":
                c = p.stack.pop(); b = p.stack.pop(); a = p.stack.pop()
                p.stack.append(z3.If(c != 0, a, b)); return [(None, p)]
            # ---- locals / globals ----
            if op == "local.get":
                p.stack.append(p.locals[ins.imm]); return [(None, p)]
            if op == "local.set":
                p.locals[ins.imm] = p.stack.pop(); return [(None, p)]
            if op == "local.tee":
                p.locals[ins.imm] = p.stack[-1]; return [(None, p)]
            if op == "global.get":
                p.stack.append(p.globals[ins.imm]); return [(None, p)]
            if op == "global.set":
                p.globals[ins.imm] = p.stack.pop(); return [(None, p)]
            # ---- consts ----
            if op == "i32.const":
                p.stack.append(z3.BitVecVal(ins.imm & 0xFFFFFFFF, 32)); return [(None, p)]
            if op == "i64.const":
                p.stack.append(z3.BitVecVal(ins.imm & ((1 << 64) - 1), 64)); return [(None, p)]
            # ---- memory ----
            if op.endswith(".load") or ".load" in op:
                base = conc(p.stack.pop()); addr = base + ins.imm
                n, signed, to64 = self._loadspec(op)
                p.stack.append(self.load(p, addr, n, signed, to64)); return [(None, p)]
            if ".store" in op:
                val = p.stack.pop(); base = conc(p.stack.pop()); addr = base + ins.imm
                n = self._storesize(op)
                self.store(p, addr, n, val); return [(None, p)]
            # ---- div/rem: WASM TRAPS on /0 and INT_MIN/-1; a trap is a rollback
            #      (reject), never a value that flows on to accept ----
            if op in ("i32.div_s", "i32.div_u", "i32.rem_s", "i32.rem_u",
                      "i64.div_s", "i64.div_u", "i64.rem_s", "i64.rem_u"):
                return self._divrem(op, p)
            # ---- arithmetic / comparison ----
            return [(None, self._alu(op, p))]
        except IndexError:
            raise RuntimeError(f"stack underflow at {op}")

    @staticmethod
    def _loadspec(op):
        table = {
            "i32.load": (4, False, False), "i64.load": (8, False, True),
            "i32.load8_u": (1, False, False), "i32.load8_s": (1, True, False),
            "i32.load16_u": (2, False, False), "i32.load16_s": (2, True, False),
            "i64.load8_u": (1, False, True), "i64.load8_s": (1, True, True),
            "i64.load16_u": (2, False, True), "i64.load16_s": (2, True, True),
            "i64.load32_u": (4, False, True), "i64.load32_s": (4, True, True),
        }
        return table[op]

    @staticmethod
    def _storesize(op):
        return {"i32.store": 4, "i64.store": 8, "i32.store8": 1, "i32.store16": 2,
                "i64.store8": 1, "i64.store16": 2, "i64.store32": 4}[op]

    def _divrem(self, op, p):
        b = p.stack[-1]
        a = p.stack[-2]
        sz = a.size()
        trap = (b == 0)
        if op.endswith("div_s") or op.endswith("rem_s"):
            minv = z3.BitVecVal(1 << (sz - 1), sz)
            neg1 = z3.BitVecVal((1 << sz) - 1, sz)
            trap = z3.Or(trap, z3.And(a == minv, b == neg1))
        out = []
        # trap -> the hook aborts and the transaction is REJECTED (record as a
        # rollback terminal; the path does not continue to any accept).
        pt = p.clone(); pt.cons.append(trap)
        if feasible(pt.cons):
            self.rollbacks.append((None, list(pt.cons)))
        # no trap -> the value flows on
        pv = p.clone(); pv.cons.append(z3.Not(trap))
        if feasible(pv.cons):
            pv.stack.pop(); pv.stack.pop()
            pv.stack.append(self._binop(op, a, b))
            out.append((None, pv))
        return out

    def _alu(self, op, p):
        st = p.stack
        # unary
        if op == "i32.eqz":
            a = st.pop(); st.append(self._b32(a == 0)); return p
        if op == "i64.eqz":
            a = st.pop(); st.append(self._b32(a == 0)); return p
        if op in ("i32.wrap_i64",):
            a = st.pop(); st.append(z3.Extract(31, 0, a)); return p
        if op == "i64.extend_i32_s":
            a = st.pop(); st.append(z3.SignExt(32, a)); return p
        if op == "i64.extend_i32_u":
            a = st.pop(); st.append(z3.ZeroExt(32, a)); return p
        if op in ("i32.clz", "i32.ctz", "i32.popcnt", "i64.clz", "i64.ctz", "i64.popcnt"):
            # Over-approximate to a FRESH symbolic (unique per occurrence — a shared
            # name would wrongly force two independent results equal, hiding bugs).
            st.pop()
            self._undef += 1
            w = 64 if op.startswith("i64") else 32
            st.append(z3.BitVec(f"{op}_{self._undef}", w)); return p
        # binary
        b = st.pop(); a = st.pop()
        st.append(self._binop(op, a, b))
        return p

    def _binop(self, op, a, b):
        f = {
            "add": lambda: a + b, "sub": lambda: a - b, "mul": lambda: a * b,
            "and": lambda: a & b, "or": lambda: a | b, "xor": lambda: a ^ b,
            # WASM masks the shift count mod width (k & 31 / k & 63); Z3 does not.
            "shl": lambda: a << (b & (a.size() - 1)),
            "shr_u": lambda: z3.LShR(a, b & (a.size() - 1)),
            "shr_s": lambda: a >> (b & (a.size() - 1)),
            "div_u": lambda: z3.UDiv(a, b), "div_s": lambda: a / b,
            "rem_u": lambda: z3.URem(a, b), "rem_s": lambda: z3.SRem(a, b),
            "rotl": lambda: z3.RotateLeft(a, b), "rotr": lambda: z3.RotateRight(a, b),
        }
        cmp = {
            "eq": lambda: a == b, "ne": lambda: a != b,
            "lt_u": lambda: z3.ULT(a, b), "lt_s": lambda: a < b,
            "gt_u": lambda: z3.UGT(a, b), "gt_s": lambda: a > b,
            "le_u": lambda: z3.ULE(a, b), "le_s": lambda: a <= b,
            "ge_u": lambda: z3.UGE(a, b), "ge_s": lambda: a >= b,
        }
        _, mn = op.split(".")
        if mn in f:
            return f[mn]()
        if mn in cmp:
            return self._b32(cmp[mn]())
        raise NotImplementedError(f"alu {op}")

    @staticmethod
    def _b32(boolexpr):
        return z3.If(boolexpr, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
