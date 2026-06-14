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

# Hook API field ids the models recognize
SF_AMOUNT = 0x60001
SF_ACCOUNT = 0x80001
SF_DESTINATION = 0x80003

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
    __slots__ = ("stack", "locals", "globals", "mem", "cons")

    def __init__(self):
        self.stack: list = []
        self.locals: list = []
        self.globals: dict = {}
        self.mem: dict = {}     # concrete addr -> BitVec(8)
        self.cons: list = []    # path constraints (z3 Bool)

    def clone(self) -> "Path":
        p = Path()
        p.stack = list(self.stack)
        p.locals = list(self.locals)
        p.globals = dict(self.globals)
        p.mem = dict(self.mem)
        p.cons = list(self.cons)
        return p


def feasible(cons) -> bool:
    s = z3.Solver()
    s.add(*cons)
    return s.check() == z3.sat


class Engine:
    def __init__(self, wasm: bytes):
        self.imports, self.funcs, self.datas = parse(wasm)
        self.inputs: dict = {}       # name -> list[BitVec(8)] symbolic input bytes
        self.accepts: list = []      # (code:int|None, cons) per accepting path
        self.rollbacks: list = []    # (code, cons)
        self.hook = next(f for f in self.funcs if f.name == "hook")

    def fresh_bytes(self, name: str, n: int):
        bs = [z3.BitVec(f"{name}_{i}", 8) for i in range(n)]
        self.inputs[name] = bs
        return bs

    # ---- memory (concrete addressing) ----
    def store_bytes(self, p: Path, addr: int, bs: list):
        for k, b in enumerate(bs):
            p.mem[addr + k] = b

    def load_byte(self, p: Path, addr: int):
        return p.mem.get(addr, z3.BitVecVal(0, 8))

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

    # ---- host functions ----
    def host_call(self, name: str, p: Path):
        st = p.stack
        if name == "_g":
            st.pop(); st.pop(); st.append(z3.BitVecVal(1, 32)); return
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
                bs = self.fresh_bytes("amt", 8); self.store_bytes(p, wptr, bs); st.append(z3.BitVecVal(8, 64))
            elif fid == SF_ACCOUNT:
                bs = self.fresh_bytes("origin", 20); self.store_bytes(p, wptr, bs); st.append(z3.BitVecVal(20, 64))
            elif fid == SF_DESTINATION:
                bs = self.fresh_bytes("dest", 20); self.store_bytes(p, wptr, bs); st.append(z3.BitVecVal(20, 64))
            else:
                st.append(z3.BitVecVal(-29 & ((1 << 64) - 1), 64))  # DOESNT_EXIST
            return
        if name == "hook_param":
            klen = conc(st.pop()); kptr = conc(st.pop()); wlen = conc(st.pop()); wptr = conc(st.pop())
            # key bytes (concrete, from memory) name the parameter
            key = bytes(conc(self.load_byte(p, kptr + i)) for i in range(klen))
            kn = key.decode("latin1")
            bs = self.inputs.get(f"param:{kn}") or self.fresh_bytes(f"param:{kn}", 8)
            self.store_bytes(p, wptr, bs[:min(len(bs), wlen)])
            st.append(z3.BitVecVal(8, 64)); return
        if name in ("accept", "rollback"):
            code = conc(st.pop()); st.pop(); st.pop()
            (self.accepts if name == "accept" else self.rollbacks).append((code, list(p.cons)))
            raise Terminal()
        raise NotImplementedError(f"host fn {name} not modeled")

    # ---- the interpreter ----
    def run(self):
        f = self.hook
        p = Path()
        p.locals = [z3.BitVec("arg_reserved", 32)] + [z3.BitVecVal(0, 32)] * f.nlocals
        # note: locals after params default i32 0; i64 locals get widened lazily on first set
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

    def _loop(self, body, p, budget):
        out = []
        for sig, pp in self._exec_seq(body, [p]):
            if sig is None:
                out.append((None, pp))            # fell through loop body -> exit loop
            elif sig[0] == "br":
                d = sig[1]
                if d == 0:                         # branch to loop top -> iterate
                    if budget > 0:
                        out.extend(self._loop(body, pp, budget - 1))
                    # else: exceeded unroll bound -> prune (guard bounds real hooks)
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
                return self._loop(ins.body, p, LOOP_UNROLL)
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
            if op == "call":
                name = self.imports[ins.imm] if ins.imm < len(self.imports) else None
                if name is None:
                    raise NotImplementedError("local function calls not yet inlined")
                try:
                    self.host_call(name, p)
                    return [(None, p)]
                except Terminal:
                    return []  # accept/rollback recorded; path ends
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
        if op in ("i32.clz", "i32.ctz", "i32.popcnt"):
            st.pop(); st.append(z3.BitVec(op, 32)); return p  # rarely on hot path; abstract
        # binary
        b = st.pop(); a = st.pop()
        st.append(self._binop(op, a, b))
        return p

    def _binop(self, op, a, b):
        f = {
            "add": lambda: a + b, "sub": lambda: a - b, "mul": lambda: a * b,
            "and": lambda: a & b, "or": lambda: a | b, "xor": lambda: a ^ b,
            "shl": lambda: a << b, "shr_u": lambda: z3.LShR(a, b), "shr_s": lambda: a >> b,
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
