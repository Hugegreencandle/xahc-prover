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
    __slots__ = ("stack", "locals", "globals", "mem", "cons", "guards", "writes",
                 "emit_count", "emits")

    def __init__(self):
        self.stack: list = []
        self.locals: list = []
        self.globals: dict = {}
        self.mem: dict = {}     # concrete addr -> BitVec(8)
        self.cons: list = []    # path constraints (z3 Bool)
        self.guards: dict = {}  # guard id -> crossings so far on this path
        self.writes: dict = {}  # state key (str) -> last value written (BitVec) on this path
        self.emit_count: int = 0  # number of emit() calls on this path
        self.emits: list = []     # emitted native drops (BitVec64) or None if unparseable

    def clone(self) -> "Path":
        p = Path()
        p.stack = list(self.stack)
        p.locals = list(self.locals)
        p.globals = dict(self.globals)
        p.mem = dict(self.mem)
        p.cons = list(self.cons)
        p.guards = dict(self.guards)
        p.writes = dict(self.writes)
        p.emit_count = self.emit_count
        p.emits = list(self.emits)
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
        self.imports, self.funcs, self.datas, self.globals_init = parse(wasm)
        self.inputs: dict = {}       # name -> list[BitVec(8)] symbolic input bytes
        self.accepts: list = []      # (code:int|None, cons) per accepting path
        self.accepts_full: list = [] # (code, cons, writes) — same paths, with state writes
        self.rollbacks: list = []    # (code, cons)
        self.guard_viols: list = []  # (guard_id, maxiter, cons) per GUARD_VIOLATION path
        self.state_old: dict = {}    # state key (str) -> symbolic old value bytes (list[BitVec8])
        self.emits_on_accept: list = []  # (cons, emits, emit_count) per accepting path
        self.hook = next(f for f in self.funcs if f.name == "hook")
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
        self._undef = 0              # counter for fresh uninitialized-memory bytes
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
            # SOUND worst case for monotonicity: assume the slot EXISTS with a
            # symbolic prior value (you can only "decrease" something already there).
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
            st.append(z3.BitVecVal(n, 64)); return
        # ---- emitted-transaction host fns (for balance / double-spend invariants) ----
        if name == "ledger_seq":
            st.append(z3.BitVecVal(1000, 64)); return
        if name == "etxn_reserve":
            n = st.pop(); st.append(z3.BitVecVal(1, 64)); return     # success
        if name == "etxn_details":
            wlen = conc(st.pop()); wptr = conc(st.pop())
            n = min(wlen, 138)                                       # emit-details blob
            for i in range(n):
                p.mem[wptr + i] = z3.BitVecVal(0, 8)
            st.append(z3.BitVecVal(n, 64)); return
        if name == "etxn_fee_base":
            st.pop(); st.pop(); st.append(z3.BitVecVal(10, 64)); return  # small positive fee
        if name == "emit":
            rlen = conc(st.pop()); rptr = conc(st.pop()); st.pop(); st.pop()
            p.emit_count += 1
            p.emits.append(self._emit_drops(p, rptr))
            st.append(z3.BitVecVal(32, 64)); return                 # >=0 = emitted hash len
        if name in ("accept", "rollback"):
            code = conc(st.pop()); st.pop(); st.pop()
            if name == "accept":
                self.accepts.append((code, list(p.cons)))
                self.accepts_full.append((code, list(p.cons), dict(p.writes)))
                self.emits_on_accept.append((list(p.cons), list(p.emits), p.emit_count))
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
        in which case balance proofs must treat the amount as unknown (fail closed)."""
        try:
            if conc(self.load_byte(p, rptr)) != 0x12:
                return None
            if conc(self.load_byte(p, rptr + 35)) != 0x61:
                return None
        except RuntimeError:
            return None
        bs = [self.load_byte(p, rptr + 36 + i) for i in range(8)]
        return z3.Concat(bs[0] & 0x3F, *bs[1:])

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
            # ---- opcodes the decoder accepts but the interpreter cannot model ----
            # br_table (clang's `switch`) and call_indirect have no sound execution
            # here. Record the op so the verdict is forced to INCONCLUSIVE, and END
            # this path cleanly instead of falling through to a misleading stack
            # underflow / ValueError. SOUND: never PROVEN on an unmodeled op.
            if op in ("br_table", "call_indirect"):
                self.unsupported.add(op)
                return []
            if op == "call":
                if ins.imm < len(self.imports):
                    name = self.imports[ins.imm]
                    try:
                        self.host_call(name, p)
                        return [(None, p)]
                    except Terminal:
                        return []  # accept/rollback recorded; path ends
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
