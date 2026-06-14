"""A minimal, SOUND invariant DSL for xahc-prover.

State a property over accepting paths in one line instead of a Python driver:

    accept implies emitted_total <= incoming_drops

The cardinal rule: the predicate is translated COMPLETELY and EXACTLY to the engine's
existing sound representations (the same ones the hand drivers use). If an expression
references any quantity or operator the engine can't model soundly, translation
HARD-REJECTS (DSLError) — it never silently drops a term, treats an unknown as true, or
weakens the predicate. A weakened invariant would be a false PROVEN; reject-unknown-loudly
is the whole game.

The checker (prove_dsl.py) asserts the NEGATION of the predicate on each accepting path:
all-UNSAT -> PROVEN, any-SAT -> COUNTEREXAMPLE, Z3 unknown / engine taint -> INCONCLUSIVE.
"""
from __future__ import annotations
import re
import z3
import xfl

W = 128  # integer working width (drops domain; 128 bits so `+` can't wrap realistically)


class DSLError(Exception):
    """Raised on any parse/translate failure — an unknown identifier, an unsupported
    operator, an XFL arithmetic attempt, or a referenced quantity the hook never produces.
    Always a HARD reject (the driver exits nonzero), never a silent pass."""


# ---- tokenizer ---------------------------------------------------------------
_TOKEN = re.compile(r"""
    \s*(?:
      (?P<num>0x[0-9A-Fa-f]+|\d+)
    | (?P<op><=|>=|==|!=|<|>|\+|-)
    | (?P<lb>\[) | (?P<rb>\]) | (?P<lp>\() | (?P<rp>\))
    | (?P<id>[A-Za-z_][A-Za-z0-9_]*)
    )""", re.VERBOSE)
_KEYWORDS = {"and", "or", "not", "implies", "accept", "xfl"}


def _tokenize(s: str):
    toks, i = [], 0
    while i < len(s):
        if s[i].isspace():
            i += 1; continue
        m = _TOKEN.match(s, i)
        if not m or m.end() == i:
            raise DSLError(f"unexpected character at: {s[i:].strip()[:24]!r}")
        i = m.end()
        if m.group("num") is not None:
            toks.append(("num", int(m.group("num"), 0)))
        elif m.group("op") is not None:
            toks.append(("op", m.group("op")))
        elif m.group("lb"): toks.append(("[", "["))
        elif m.group("rb"): toks.append(("]", "]"))
        elif m.group("lp"): toks.append(("(", "("))
        elif m.group("rp"): toks.append((")", ")"))
        else:
            w = m.group("id")
            toks.append(("kw", w) if w in _KEYWORDS else ("id", w))
    toks.append(("eof", None))
    return toks


# ---- parser (precedence: implies < or < and < not < cmp < add < primary) -----
class _P:
    def __init__(self, toks): self.t = toks; self.i = 0
    def peek(self): return self.t[self.i]
    def next(self): tok = self.t[self.i]; self.i += 1; return tok
    def expect(self, kind):
        tok = self.next()
        if tok[0] != kind:
            raise DSLError(f"expected {kind}, got {tok[1]!r}")
        return tok

    def parse(self):
        node = self.p_implies()
        if self.peek()[0] != "eof":
            raise DSLError(f"trailing tokens: {self.peek()[1]!r}")
        return node

    def p_implies(self):
        l = self.p_or()
        if self.peek() == ("kw", "implies"):
            self.next(); return ("implies", l, self.p_implies())
        return l

    def p_or(self):
        l = self.p_and()
        while self.peek() == ("kw", "or"):
            self.next(); l = ("or", l, self.p_and())
        return l

    def p_and(self):
        l = self.p_not()
        while self.peek() == ("kw", "and"):
            self.next(); l = ("and", l, self.p_not())
        return l

    def p_not(self):
        if self.peek() == ("kw", "not"):
            self.next(); return ("not", self.p_not())
        return self.p_cmp()

    def p_cmp(self):
        l = self.p_add()
        if self.peek()[0] == "op" and self.peek()[1] in ("<=", "<", "==", "!=", ">=", ">"):
            op = self.next()[1]
            return ("cmp", op, l, self.p_add())
        return l

    def p_add(self):
        l = self.p_primary()
        while self.peek()[0] == "op" and self.peek()[1] in ("+", "-"):
            op = self.next()[1]; l = ("bin", op, l, self.p_primary())
        return l

    def p_primary(self):
        tok = self.next()
        if tok[0] == "num":
            return ("num", tok[1])
        if tok == ("(", "("):
            node = self.p_implies(); self.expect(")"); return node
        if tok == ("kw", "accept"):
            return ("accept",)                       # bool atom == true (we're on accept paths)
        if tok == ("kw", "xfl"):
            self.expect("("); n = self.expect("num")[1]; self.expect(")")
            return ("xfl", n)
        if tok[0] == "id":
            name = tok[1]
            if self.peek() == ("[", "["):
                self.next(); key = self.expect("id")[1]; self.expect("]")
                return ("sub", name, key)
            return ("id", name)
        raise DSLError(f"unexpected token {tok[1]!r}")


def parse(text: str):
    return _P(_tokenize(text)).parse()


_KNOWN_IDS = {"incoming_drops", "emitted_total", "emit_count", "accept_code", "dest", "iou_amount"}
_KNOWN_SUBS = {"param", "state_old", "state_new"}


# node kinds that DENOTE A BOOLEAN at the root of the AST. Everything else (num/xfl/id/
# sub/bin) is a value term — never a predicate. This is purely structural (engine-independent).
_BOOL_NODES = {"cmp", "and", "or", "not", "implies", "accept"}


def is_bool_root(node) -> bool:
    """Static, engine-independent: True iff the top-level expression denotes a bool (a
    predicate), False if it is a value term (an integer/XFL/byte quantity)."""
    return node[0] in _BOOL_NODES


def require_bool_root(node):
    """Hard-reject a non-boolean top-level predicate BEFORE any PROVEN can be returned —
    independent of accept-path count. On a zero-accept hook the per-path translation (which is
    the only other place the bool kind is enforced) never fires, so a value term like
    `incoming_drops` or `emitted_total + 1` would otherwise fall through to a vacuous PROVEN.
    A predicate that is not boolean at the root is a malformed invariant, never a proof."""
    if not is_bool_root(node):
        raise DSLError("predicate is not boolean at the top level — an invariant must be a "
                       "condition (e.g. `accept implies emitted_total <= incoming_drops`), "
                       "not a bare value")


def validate(node, _root=True):
    """Static, engine-independent structural check — runs once before the engine, so a bad
    expression is HARD-REJECTED even on a hook with zero accepting paths (where per-path
    translation would never fire). Rejects a non-boolean root predicate (vacuous-PROVEN guard),
    unknown identifiers, and XFL arithmetic."""
    if _root:
        require_bool_root(node)                  # bool-at-root BEFORE anything else can pass
    k = node[0]
    if k == "id":
        if node[1] not in _KNOWN_IDS:
            raise DSLError(f"unknown identifier {node[1]!r}")
    elif k == "sub":
        if node[1] not in _KNOWN_SUBS:
            raise DSLError(f"unknown quantity {node[1]!r}[…]")
    elif k == "bin":
        if uses_xfl(node[2]) or uses_xfl(node[3]):
            raise DSLError("XFL arithmetic is not supported — compare XFL values directly, "
                           "never add/subtract them")
    for c in node[1:]:
        if isinstance(c, tuple):
            validate(c, _root=False)


def uses_xfl(node) -> bool:
    if node[0] in ("xfl",):
        return True
    if node[0] == "id" and node[1] == "iou_amount":
        return True
    return any(uses_xfl(c) for c in node[1:] if isinstance(c, tuple))


# ---- typed values ------------------------------------------------------------
class TV:
    __slots__ = ("kind", "val")
    def __init__(self, kind, val): self.kind = kind; self.val = val   # kind: int|bytes|bool|xfl


def _concat_be(byte_list):
    return byte_list[0] if len(byte_list) == 1 else z3.Concat(*byte_list)


def _as_int(tv: TV):
    """Coerce to the W-bit unsigned integer domain. bytes -> big-endian value."""
    if tv.kind == "int":
        return tv.val
    if tv.kind == "bytes":
        if len(tv.val) * 8 > W:
            raise DSLError(f"byte quantity too wide ({len(tv.val)} bytes) to use as an integer")
        bv = _concat_be(tv.val)
        return z3.ZeroExt(W - bv.size(), bv)
    raise DSLError(f"a {tv.kind} value can't be used as an integer")


class Translator:
    """Translate an AST to a z3 Bool for ONE accepting path. `ctx` carries that path's
    quantities. Any unmodelable reference raises DSLError (hard reject)."""

    def __init__(self, engine, ctx):
        self.e = engine; self.ctx = ctx

    def b(self, node) -> z3.BoolRef:
        v = self.v(node)
        if v.kind != "bool":
            raise DSLError("expression is not boolean where a condition is required")
        return v.val

    def v(self, node) -> TV:
        k = node[0]
        if k == "num":
            return TV("int", z3.BitVecVal(node[1] & ((1 << W) - 1), W))
        if k == "xfl":
            enc = xfl.floatSet(0, node[1])
            if enc < 0:
                raise DSLError(f"xfl({node[1]}) is not representable as an XFL value")
            return TV("xfl", z3.BitVecVal(enc & ((1 << 64) - 1), 64))
        if k == "accept":
            return TV("bool", z3.BoolVal(True))
        if k == "id":
            return self._ident(node[1])
        if k == "sub":
            return self._subscript(node[1], node[2])
        if k == "not":
            return TV("bool", z3.Not(self.b(node[1])))
        if k == "and":
            return TV("bool", z3.And(self.b(node[1]), self.b(node[2])))
        if k == "or":
            return TV("bool", z3.Or(self.b(node[1]), self.b(node[2])))
        if k == "implies":
            return TV("bool", z3.Or(z3.Not(self.b(node[1])), self.b(node[2])))
        if k == "bin":
            return self._arith(node[1], self.v(node[2]), self.v(node[3]))
        if k == "cmp":
            return self._cmp(node[1], self.v(node[2]), self.v(node[3]))
        raise DSLError(f"cannot translate node {k!r}")

    # -- arithmetic: integers only, never XFL (no raw XFL arithmetic in the DSL) --
    def _arith(self, op, l, r):
        if l.kind == "xfl" or r.kind == "xfl":
            raise DSLError("XFL arithmetic is not supported — compare XFL values directly "
                           "(<=, <, ==, …), never add/subtract them")
        a, b = _as_int(l), _as_int(r)
        return TV("int", a + b if op == "+" else a - b)

    def _cmp(self, op, l, r):
        # XFL ordering routes through the engine's SOUND float_compare (linear BV), never raw BV.
        if l.kind == "xfl" or r.kind == "xfl":
            if not (l.kind == "xfl" and r.kind == "xfl"):
                raise DSLError("an XFL value can only be compared to another XFL value")
            c = self.e._float_cmp_c(l.val, r.val)        # signed BV8 in {-1,0,1}
            z = z3.BitVecVal(0, c.size())
            m = {"<=": c <= z, "<": c < z, ">=": c >= z, ">": c > z,
                 "==": c == z, "!=": c != z}              # z3py BV </<= are SIGNED — correct here
            return TV("bool", m[op])
        # byte == / != : structural when same length (e.g. dest == param[DST])
        if op in ("==", "!=") and l.kind == "bytes" and r.kind == "bytes" and len(l.val) == len(r.val):
            eqs = [l.val[i] == r.val[i] for i in range(len(l.val))]
            eq = z3.And(*eqs)
            return TV("bool", eq if op == "==" else z3.Not(eq))
        a, b = _as_int(l), _as_int(r)                     # integer domain: UNSIGNED (drops)
        m = {"<=": z3.ULE(a, b), "<": z3.ULT(a, b), ">=": z3.UGE(a, b), ">": z3.UGT(a, b),
             "==": a == b, "!=": a != b}
        return TV("bool", m[op])

    # -- quantities: map each to the engine's existing sound representation ----
    def _ident(self, name):
        e, ctx = self.e, self.ctx
        if name == "incoming_drops":
            amt = e.inputs.get("amt")
            if not amt:
                raise DSLError("`incoming_drops` referenced but the hook never reads sfAmount")
            # masked native decode (byte0 & 0x3F strips the not-XRP/sign flag bits) — the TRUE
            # native drops, and <= the raw 8-byte read, so it never over-states the amount.
            bv = z3.Concat(amt[0] & 0x3F, *amt[1:])
            return TV("int", z3.ZeroExt(W - 64, bv))
        if name == "emitted_total":
            if ctx.get("emits") is None:
                raise DSLError("`emitted_total` referenced but the hook emits nothing the model tracks")
            emits = ctx["emits"]
            if any(x is None for x in emits):
                raise _Indeterminate("an emitted amount could not be parsed")  # -> INCONCLUSIVE
            total = z3.BitVecVal(0, W)
            for x in emits:
                total = total + z3.ZeroExt(W - x.size(), x)
            return TV("int", total)
        if name == "emit_count":
            return TV("int", z3.BitVecVal(int(ctx["count"]) & ((1 << W) - 1), W))
        if name == "accept_code":
            code = ctx.get("code")
            if code is None:
                raise _Indeterminate("accept_code is not concrete on this path")
            return TV("int", z3.BitVecVal(int(code) & ((1 << W) - 1), W))
        if name == "dest":
            d = e.inputs.get("dest")
            if not d:
                raise DSLError("`dest` referenced but the hook never reads sfDestination")
            return TV("bytes", d)
        if name == "iou_amount":
            x = e.inputs.get("amt_xfl")
            if x is None:
                raise DSLError("`iou_amount` referenced but the hook reads no issued (XFL) amount")
            return TV("xfl", x)
        raise DSLError(f"unknown identifier {name!r}")

    def _subscript(self, name, key):
        e, ctx = self.e, self.ctx
        if name == "param":
            bs = e.inputs.get(f"param:{key}")
            if not bs:
                raise DSLError(f"`param[{key}]` referenced but the hook never reads hook_param({key})")
            return TV("bytes", bs)
        if name == "state_old":
            bs = e.state_old.get(key)
            if not bs:
                raise DSLError(f"`state_old[{key}]` referenced but the hook never reads state[{key}]")
            return TV("bytes", bs)
        if name == "state_new":
            writes = ctx.get("writes") or {}
            if key not in writes:
                raise DSLError(f"`state_new[{key}]` referenced but the hook never writes state[{key}]")
            return TV("int", z3.ZeroExt(W - writes[key].size(), writes[key]))
        raise DSLError(f"unknown subscripted quantity {name!r}")


class _Indeterminate(Exception):
    """A path-local condition that means the verdict must be INCONCLUSIVE (not a hard
    reject and not a pass): an unparseable emit amount, a non-concrete accept code, etc."""
