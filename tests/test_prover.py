"""Regression tests for the prover engine — especially the soundness/semantics
fixes from the 3-lens audit. Run: python tests/test_prover.py  (or pytest)."""
import os
import sys
import z3

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
import struct                                         # noqa: E402
import prover                                         # noqa: E402
from prover import Engine, Path                      # noqa: E402
from wasm import Instr                                # noqa: E402
import prove_limit, prove_guardrail, prove_termination, prove_monotonic   # noqa: E402
import prove_nospend, prove_conservation                                  # noqa: E402

H = os.path.join(ROOT, "hooks")
ENG = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())  # any module, for method use


# --- tiny hand WASM builder (no toolchain needed) for soundness fixtures --------
def _uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)


def _sleb(n):
    out = bytearray()
    more = True
    while more:
        b = n & 0x7F
        n >>= 7
        if (n == 0 and not (b & 0x40)) or (n == -1 and (b & 0x40)):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)


def _sec(sid, payload):
    return bytes([sid]) + _uleb(len(payload)) + payload


def _vec(items):
    return _uleb(len(items)) + b"".join(items)


I32, I64 = 0x7F, 0x7E


def _ftype(params, results):
    return bytes([0x60]) + _vec([bytes([p]) for p in params]) + _vec([bytes([r]) for r in results])


def _module(types, imports, export_fn_idx, data_off, data_bytes, body):
    """Assemble a 1-function ('hook') module from raw parts."""
    sec_type = _sec(1, _vec(types))
    sec_import = _sec(2, _vec(imports))
    sec_func = _sec(3, _vec([_uleb(0)]))                       # hook uses type 0
    sec_mem = _sec(5, _vec([bytes([0x00]) + _uleb(1)]))
    glob = bytes([I32, 0x01, 0x41]) + _sleb(65536) + bytes([0x0B])
    sec_global = _sec(6, _vec([glob]))
    exp = _uleb(len("hook")) + b"hook" + bytes([0x00]) + _uleb(export_fn_idx)
    sec_export = _sec(7, _vec([exp]))
    sec_data = _sec(11, _vec([_uleb(0) + bytes([0x41]) + _sleb(data_off) +
                              bytes([0x0B]) + _uleb(len(data_bytes)) + data_bytes]))
    func_body = _uleb(0) + body
    sec_code = _sec(10, _vec([_uleb(len(func_body)) + func_body]))
    return (b"\x00asm" + struct.pack("<I", 1) + sec_type + sec_import + sec_func +
            sec_mem + sec_global + sec_export + sec_data + sec_code)


def _i32c(n):
    return bytes([0x41]) + _sleb(n)


def _i64c(n):
    return bytes([0x42]) + _sleb(n)


def test_shift_mask():
    # WASM masks the shift count mod width; Z3 alone gives 0 for k>=width.
    a, b = z3.BitVecVal(1, 32), z3.BitVecVal(32, 32)
    assert z3.simplify(ENG._binop("i32.shl", a, b)).as_long() == 1
    a64, b64 = z3.BitVecVal(1, 64), z3.BitVecVal(64, 64)
    assert z3.simplify(ENG._binop("i64.shl", a64, b64)).as_long() == 1


def test_clz_is_fresh():
    # two independent clz results must NOT be forced equal (the old shared-name bug)
    p = Path(); p.stack = [z3.BitVec("x", 32)]
    ENG._alu("i32.clz", p)
    p.stack.append(z3.BitVec("y", 32))
    ENG._alu("i32.clz", p)
    r2, r1 = p.stack[-1], p.stack[-2]
    s = z3.Solver(); s.add(r1 != r2)
    assert s.check() == z3.sat, "two clz results were wrongly unified"


def test_div_trap_is_rollback():
    # divide-by-zero must fork a rollback (trap), not flow a total value to accept
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    p = Path(); p.stack = [z3.BitVec("a", 64), z3.BitVec("b", 64)]
    before = len(e.rollbacks)
    out = e._divrem("i64.div_u", p)
    assert len(e.rollbacks) == before + 1, "div trap not recorded as rollback"
    assert len(out) == 1, "value path missing"


def test_matrix_verdicts():
    SUPPLY = 600_000_000_000_000_000
    assert prove_limit.main(os.path.join(H, "limit.wasm")) == 0            # PROVEN
    assert prove_limit.main(os.path.join(H, "limit_buggy.wasm")) == 2      # CEX (signed)
    assert prove_limit.main(os.path.join(H, "limit_inverted.wasm"), SUPPLY) == 2
    assert prove_guardrail.main(os.path.join(H, "agent_guardrail.wasm")) == 0       # both invariants PROVEN
    assert prove_guardrail.main(os.path.join(H, "agent_guardrail_buggy.wasm"), SUPPLY) == 2   # spend-limit CEX
    assert prove_guardrail.main(os.path.join(H, "agent_guardrail_dstbug.wasm")) == 2          # dst-lock CEX (off-by-one)
    # guard-termination
    assert prove_termination.main(os.path.join(H, "agent_guardrail.wasm")) == 0   # fixed loops -> PROVEN
    assert prove_termination.main(os.path.join(H, "termination_bug.wasm")) == 2   # data-dependent loop -> CEX
    # state-monotonicity
    assert prove_monotonic.main(os.path.join(H, "monotonic.wasm")) == 0           # strictly-increasing -> PROVEN
    assert prove_monotonic.main(os.path.join(H, "monotonic_bug.wasm")) == 2       # no check -> CEX (replay)
    # emitted-tx invariants (exercise call inlining + emit modeling)
    assert prove_nospend.main(os.path.join(H, "emit_forward.wasm")) == 0          # 1 emit -> PROVEN
    assert prove_nospend.main(os.path.join(H, "emit_double.wasm")) == 2           # 2 emits -> CEX
    assert prove_conservation.main(os.path.join(H, "emit_forward.wasm")) == 0     # half <= in -> PROVEN
    assert prove_conservation.main(os.path.join(H, "emit_double.wasm")) == 0      # half+half = in -> PROVEN
    assert prove_conservation.main(os.path.join(H, "emit_inflate.wasm")) == 2     # > in -> CEX


def test_decoder_tracks_types():
    from wasm import parse
    _, fs, _, g = parse(open(os.path.join(H, "agent_guardrail.wasm"), "rb").read())
    hook = next(f for f in fs if f.name == "hook")
    assert 0x7E in hook.localtypes, "i64 local valtype not tracked"
    assert g and g[0][0] == 65536, "global section (stack pointer) not parsed"


# --- SOUNDNESS regression tests (audit findings 1-4) ---------------------------

def _write_without_read_module():
    """A hook that state_set()s NONCE but never state()-reads it -> the canonical
    replay/rollback bug. Must NOT be reported PROVEN."""
    types = [_ftype([I32], [I64]),                       # 0 hook
             _ftype([I32, I32, I32, I32], [I64]),        # 1 state_set
             _ftype([I32, I32, I32], [I64])]             # 2 accept

    def _imp(mod, nm, t):
        return _uleb(len(mod)) + mod.encode() + _uleb(len(nm)) + nm.encode() + bytes([0x00]) + _uleb(t)
    imports = [_imp("env", "state_set", 1), _imp("env", "accept", 2)]   # idx 0,1
    KEY_PTR, VAL_PTR, MSG_PTR = 1024, 1029, 1037
    data = b"NONCE" + bytes([1, 2, 3, 4, 5, 6, 7, 8]) + b"ok\x00"
    body = b""
    body += _i32c(VAL_PTR) + _i32c(8) + _i32c(KEY_PTR) + _i32c(5) + bytes([0x10]) + _uleb(0) + bytes([0x1A])
    body += _i32c(MSG_PTR) + _i32c(2) + _i64c(0) + bytes([0x10]) + _uleb(1) + bytes([0x1A])
    body += _i64c(0) + bytes([0x0B])
    return _module(types, imports, export_fn_idx=2, data_off=1024, data_bytes=data, body=body)


def test_monotonic_write_without_read_is_not_proven(tmp_path=None):
    # FINDING 1: a write to a state key never read must be a counterexample (exit 2)
    # or at least inconclusive (exit 3) — NEVER a silent PROVEN (exit 0).
    wasm = _write_without_read_module()
    path = os.path.join(ROOT, "tests", "_tmp_write_no_read.wasm")
    open(path, "wb").write(wasm)
    try:
        rc = prove_monotonic.main(path)
    finally:
        os.remove(path)
    assert rc != 0, "write-without-read was falsely reported PROVEN (vacuous certificate)"
    assert rc in (2, 3), f"expected counterexample(2) or inconclusive(3), got {rc}"


def test_feasible_treats_unknown_as_feasible():
    # FINDING 2: feasible() must NOT discard a path on Z3 `unknown` (only on unsat).
    real = z3.Solver

    class Unknown:
        def add(self, *a): pass
        def check(self): return z3.unknown
    z3.Solver = Unknown
    try:
        assert prover.feasible([]) is True, "unknown wrongly treated as infeasible (path dropped)"
    finally:
        z3.Solver = real

    class Unsat:
        def add(self, *a): pass
        def check(self): return z3.unsat
    z3.Solver = Unsat
    try:
        assert prover.feasible([]) is False, "unsat must be infeasible"
    finally:
        z3.Solver = real


def test_unknown_check_maps_to_inconclusive():
    # FINDING 2: a Z3 `unknown` on a driver's violation check must yield exit 3
    # (INCONCLUSIVE), never fall through to exit 0 (PROVEN).
    real = z3.Solver
    state = {"after_run": False}

    class Wrap:
        def __init__(self): self._s = real()
        def add(self, *a): self._s.add(*a)
        def check(self): return z3.unknown if state["after_run"] else self._s.check()
        def model(self): return self._s.model()

    orig_run = prover.Engine.run

    def patched_run(self):
        orig_run(self)
        state["after_run"] = True

    prover.Engine.run = patched_run
    z3.Solver = Wrap
    try:
        rc = prove_limit.main(os.path.join(H, "limit.wasm"))
    finally:
        prover.Engine.run = orig_run
        z3.Solver = real
    assert rc == 3, f"unknown must map to INCONCLUSIVE (3), got {rc}"


def test_high_iteration_loop_no_recursionerror():
    # FINDING 3: _loop must be iterative — a budget beyond CPython's recursionlimit
    # (~1000) used to throw RecursionError. Drive a back-edge-only body past it.
    assert sys.getrecursionlimit() <= 2000  # sanity: the old bug was reachable
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    body = [Instr("br", imm=0)]                          # every iteration takes back-edge
    out = e._loop(body, Path(), 1500)                    # 1500 > recursionlimit
    assert e.hit_bound is True, "back-edge-only loop should exhaust budget and flag hit_bound"
    assert out == [], "no path should exit a back-edge-only loop"
    # an even larger budget must also survive
    e2 = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    e2._loop(body, Path(), 8000)
    assert e2.hit_bound is True


def _brtable_module():
    """A hook that reaches a br_table (clang's switch)."""
    types = [_ftype([I32], [I64]), _ftype([I32, I32, I32], [I64])]    # 0 hook, 1 accept

    def _imp(mod, nm, t):
        return _uleb(len(mod)) + mod.encode() + _uleb(len(nm)) + nm.encode() + bytes([0x00]) + _uleb(t)
    imports = [_imp("env", "accept", 1)]                              # idx 0
    br_table = bytes([0x0E]) + _uleb(1) + _uleb(0) + _uleb(0)         # targets [0], default 0
    block = bytes([0x02, 0x40]) + _i32c(0) + br_table + bytes([0x0B])  # block void ... end
    body = block + _i32c(1024) + _i32c(2) + _i64c(0) + bytes([0x10]) + _uleb(0) + bytes([0x1A])
    body += _i64c(0) + bytes([0x0B])
    return _module(types, imports, export_fn_idx=1, data_off=1024, data_bytes=b"ok\x00", body=body)


def test_brtable_is_executed_soundly():
    # br_table (clang's `switch`) is now EXECUTED — the engine forks over each
    # labelled target under `idx == k` plus the default under `idx >= n`. The fixture
    # switches (index 0 -> target 0 -> exits the block -> accept), so: br_table must
    # NOT be flagged unsupported, the path must reach accept, and the verdict is a
    # real PROVEN (no spend), never an unsupported-INCONCLUSIVE.
    wasm = _brtable_module()
    path = os.path.join(ROOT, "tests", "_tmp_brtable.wasm")
    open(path, "wb").write(wasm)
    try:
        e = Engine(wasm)
        e.run()                                          # must not raise
        assert "br_table" not in e.unsupported, "br_table should now be executed, not unsupported"
        assert len(e.accepts) == 1, "br_table switch should reach the accept path"
        rc = prove_termination.main(path)
    finally:
        os.remove(path)
    assert rc == 0, f"br_table hook should now PROVE (0), got {rc}"


# --- ADVERSARIAL br_table soundness (switch cannot drop an unsafe case) ---------

def _switch_emit_module(case0, case1, default):
    """3-way switch over arg0 (i32 index):
        idx==0 -> case0 ; idx==1 -> case1 ; idx>=2 -> default.
    Each `case` is raw bytes ending in its own accept (so no fallthrough); the
    default falls through to a final accept. Each case may call emit() zero or more
    times — the nospend invariant (<=1 emit per accept) is the probe: if br_table
    silently dropped a case, an unsafe (double-emit) case would not appear and the
    hook would FALSELY prove. emit=0, accept=1 in the import table."""
    emit_ft = _ftype([I32, I32, I32, I32], [I64])
    accept_ft = _ftype([I32, I32, I32], [I64])
    types = [_ftype([I32], [I64]), emit_ft, accept_ft]

    def _imp(mod, nm, t):
        return _uleb(len(mod)) + mod.encode() + _uleb(len(nm)) + nm.encode() + bytes([0x00]) + _uleb(t)
    imports = [_imp("env", "emit", 1), _imp("env", "accept", 2)]   # emit=0, accept=1

    blk = lambda inner: bytes([0x02, 0x40]) + inner + bytes([0x0B])   # block void
    brtab = lambda tgts, d: (bytes([0x0E]) + _uleb(len(tgts)) +
                             b"".join(_uleb(t) for t in tgts) + _uleb(d))
    lget0 = bytes([0x20]) + _uleb(0)                                  # local.get 0 (index)
    RET = bytes([0x0F])
    # nested blocks: depth 0 (innermost) -> case0, depth 1 -> case1, depth 2 -> default
    inner = lget0 + brtab([0, 1], 2)
    L0 = blk(inner)
    L1 = blk(L0 + case0 + RET)
    L2 = blk(L1 + case1 + RET)
    body = L2 + default + _i64c(0) + bytes([0x0B])
    return _module(types, imports, export_fn_idx=2, data_off=1024, data_bytes=b"ok\x00", body=body)


def _emit_call():    # emit(0,0,0,0)
    return _i32c(0) + _i32c(0) + _i32c(0) + _i32c(0) + bytes([0x10]) + _uleb(0) + bytes([0x1A])


def _accept_call():  # accept(0,0,0)
    return _i32c(0) + _i32c(0) + _i64c(0) + bytes([0x10]) + _uleb(1) + bytes([0x1A])


def _run_nospend(wasm):
    path = os.path.join(ROOT, "tests", "_tmp_switch.wasm")
    open(path, "wb").write(wasm)
    try:
        return prove_nospend.main(path)
    finally:
        os.remove(path)


def test_brtable_fork_is_exhaustive_and_exclusive():
    # ENGINE-LEVEL: the br_table fork must cover EVERY u32 index (0..n-1 and >=n)
    # with mutually-exclusive constraints — no reachable case silently dropped.
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    idx = z3.BitVec("idx32", 32)
    p = Path(); p.stack = [idx]
    out = e._exec(Instr("br_table", imm=([0, 1, 2], 3)), p)
    assert len(out) == 4, "expected 3 labelled + 1 default fork"
    union = z3.Or(*[z3.And(*pp.cons) for _, pp in out])
    s = z3.Solver(); s.add(z3.Not(union))
    assert s.check() == z3.unsat, "br_table fork leaves some u32 index uncovered (case could be dropped)"
    import itertools
    for (_, p1), (_, p2) in itertools.combinations(out, 2):
        ss = z3.Solver(); ss.add(*p1.cons, *p2.cons)
        assert ss.check() == z3.unsat, "br_table branches overlap (not mutually exclusive)"


def test_brtable_all_cases_safe_is_proven():
    # All three switch cases emit exactly once -> no double-spend -> real PROVEN(0).
    wasm = _switch_emit_module(
        _emit_call() + _accept_call(),
        _emit_call() + _accept_call(),
        _emit_call() + _accept_call())
    e = Engine(wasm); e.run()
    assert len(e.accepts) == 3, "all 3 switch branches (incl. default) must be explored"
    assert sorted({c for _, _, c in e.emits_on_accept}) == [1]
    assert _run_nospend(wasm) == 0, "all-safe switch must PROVE"


def test_brtable_one_unsafe_labelled_case_is_caught():
    # DECISIVE: exactly ONE labelled case (idx==1) double-emits. If br_table dropped
    # that case it would falsely PROVE; the prover must report CEX(2).
    wasm = _switch_emit_module(
        _emit_call() + _accept_call(),
        _emit_call() + _emit_call() + _accept_call(),     # UNSAFE
        _emit_call() + _accept_call())
    e = Engine(wasm); e.run()
    assert 2 in {c for _, _, c in e.emits_on_accept}, "the unsafe case path was dropped"
    assert _run_nospend(wasm) == 2, "unsafe labelled switch case must be a COUNTEREXAMPLE, not PROVEN"


def test_brtable_unsafe_default_case_is_caught():
    # The DEFAULT branch (idx>=2) must also be explored: only the default double-emits.
    wasm = _switch_emit_module(
        _emit_call() + _accept_call(),
        _emit_call() + _accept_call(),
        _emit_call() + _emit_call() + _accept_call())     # UNSAFE default
    e = Engine(wasm); e.run()
    assert 2 in {c for _, _, c in e.emits_on_accept}, "the default case was not explored"
    assert _run_nospend(wasm) == 2, "unsafe br_table DEFAULT must be a COUNTEREXAMPLE, not PROVEN"


def test_brtable_targeting_loop_backedge_propagates_depth():
    # NESTED: a br_table inside a block inside a loop. One target depth reaches the
    # loop back-edge (iterate), the other exits the block. With no _g guard the
    # back-edge iterates to the unroll bound -> hit_bound True (sound: INCONCLUSIVE,
    # never PROVEN). Confirms br_table's ('br', depth) decrements correctly through
    # _block_like AND _loop.
    types = [_ftype([I32], [I64]), _ftype([I32, I32, I32], [I64])]

    def _imp(mod, nm, t):
        return _uleb(len(mod)) + mod.encode() + _uleb(len(nm)) + nm.encode() + bytes([0x00]) + _uleb(t)
    imports = [_imp("env", "accept", 1)]
    loop = lambda inner: bytes([0x03, 0x40]) + inner + bytes([0x0B])
    blk = lambda inner: bytes([0x02, 0x40]) + inner + bytes([0x0B])
    brtab = lambda tgts, d: (bytes([0x0E]) + _uleb(len(tgts)) +
                             b"".join(_uleb(t) for t in tgts) + _uleb(d))
    lget0 = bytes([0x20]) + _uleb(0)
    # br_table [1,0] default 0: idx==0 -> depth1 -> loop back-edge; idx>=1 -> depth0 -> exit block
    B = blk(lget0 + brtab([1, 0], 0))
    L = loop(B)
    accept = _i32c(0) + _i32c(0) + _i64c(0) + bytes([0x10]) + _uleb(0) + bytes([0x1A])
    body = L + accept + _i64c(0) + bytes([0x0B])
    wasm = _module(types, imports, export_fn_idx=1, data_off=1024, data_bytes=b"ok\x00", body=body)
    e = Engine(wasm); e.run()
    assert e.hit_bound is True, "br_table back-edge target did not iterate the loop (depth misrouted)"
    assert "br_table" not in e.unsupported


# --- ADVERSARIAL symbolic otxn_field soundness (no skipped accept path) ----------

def _field_gated_module(accept_body, fid=0x50001):
    """Hook that gates accept on an UNMODELED otxn field's return:
        ret = otxn_field(buf, 8, fid);  if (ret == 8) { accept_body } else rollback
    Under the OLD always-absent (-29) modeling, ret==8 was unsat and the accept
    branch was pruned -> vacuous proof. With a SYMBOLIC return the accept path is
    explored. `accept_body` is raw bytes ending in accept().
    Imports: otxn_field=0, emit=1, accept=2, rollback=3."""
    otxn_ft = _ftype([I32, I32, I32], [I64])
    emit_ft = _ftype([I32, I32, I32, I32], [I64])
    accept_ft = _ftype([I32, I32, I32], [I64])
    types = [_ftype([I32], [I64]), otxn_ft, emit_ft, accept_ft]

    def _imp(mod, nm, t):
        return _uleb(len(mod)) + mod.encode() + _uleb(len(nm)) + nm.encode() + bytes([0x00]) + _uleb(t)
    imports = [_imp("env", "otxn_field", 1), _imp("env", "emit", 2),
               _imp("env", "accept", 3), _imp("env", "rollback", 3)]
    rollback_call = _i32c(0) + _i32c(0) + _i64c(0) + bytes([0x10]) + _uleb(3) + bytes([0x1A])
    iff = lambda thenb, elseb: bytes([0x04, 0x40]) + thenb + bytes([0x05]) + elseb + bytes([0x0B])
    # push wptr=1024, wlen=8, fid ; call otxn_field -> ret(i64) ; i64.const 8 ; i64.eq -> i32 ; if
    call = _i32c(1024) + _i32c(8) + _i32c(fid) + bytes([0x10]) + _uleb(0)
    cond = _i64c(8) + bytes([0x51])                                   # i64.eq
    body = call + cond + iff(accept_body, rollback_call) + _i64c(0) + bytes([0x0B])
    # 4 function imports -> local hook is function index 4
    return _module(types, imports, export_fn_idx=4, data_off=1024, data_bytes=bytes(64), body=body)


def _emit_call_idx1():   # emit(0,0,0,0) with emit at import index 1
    return _i32c(0) + _i32c(0) + _i32c(0) + _i32c(0) + bytes([0x10]) + _uleb(1) + bytes([0x1A])


def _accept_call_idx2():
    return _i32c(0) + _i32c(0) + _i64c(0) + bytes([0x10]) + _uleb(2) + bytes([0x1A])


def test_symbolic_field_accept_path_is_explored():
    # KEY soundness point: an accept gated on an unmodeled field MUST be reachable
    # now (previously always-absent forced rollback -> vacuous proof).
    wasm = _field_gated_module(_accept_call_idx2())
    e = Engine(wasm); e.run()
    assert len(e.accepts) >= 1, "field-gated accept path was skipped (vacuous proof returned)"
    assert any(k.startswith("otxn_field_ret") for k in e.inputs), "symbolic return length not exposed"


def test_symbolic_field_unsafe_accept_is_caught():
    # DECISIVE anti-vacuous: the field-gated accept path double-emits. Old code would
    # falsely PROVE (0 accepting paths); the prover must now report CEX(2).
    wasm = _field_gated_module(_emit_call_idx1() + _emit_call_idx1() + _accept_call_idx2())
    path = os.path.join(ROOT, "tests", "_tmp_field.wasm")
    open(path, "wb").write(wasm)
    try:
        rc = prove_nospend.main(path)
    finally:
        os.remove(path)
    assert rc == 2, f"unsafe field-gated accept must be a COUNTEREXAMPLE, got {rc} (vacuous PROVEN if 0)"


def test_symbolic_field_content_is_not_concretized():
    # Symbolic field CONTENT must stay symbolic: an accept gated on byte0 == 0x42 is
    # feasible (not forced false), and the rollback branch also exists.
    iff = lambda thenb, elseb: bytes([0x04, 0x40]) + thenb + bytes([0x05]) + elseb + bytes([0x0B])
    otxn_ft = _ftype([I32, I32, I32], [I64]); accept_ft = _ftype([I32, I32, I32], [I64])
    types = [_ftype([I32], [I64]), otxn_ft, accept_ft]

    def _imp(mod, nm, t):
        return _uleb(len(mod)) + mod.encode() + _uleb(len(nm)) + nm.encode() + bytes([0x00]) + _uleb(t)
    imports = [_imp("env", "otxn_field", 1), _imp("env", "accept", 2), _imp("env", "rollback", 2)]
    accept_call = _i32c(0) + _i32c(0) + _i64c(0) + bytes([0x10]) + _uleb(1) + bytes([0x1A])
    rollback_call = _i32c(0) + _i32c(0) + _i64c(0) + bytes([0x10]) + _uleb(2) + bytes([0x1A])
    body = (_i32c(1024) + _i32c(8) + _i32c(0x50001) + bytes([0x10]) + _uleb(0) + bytes([0x1A])  # call, drop ret
            + _i32c(1024) + bytes([0x2D]) + _uleb(0) + _uleb(0)                                 # i32.load8_u [1024]
            + _i32c(0x42) + bytes([0x46])                                                       # const 0x42; i32.eq
            + iff(accept_call, rollback_call) + _i64c(0) + bytes([0x0B]))
    wasm = _module(types, imports, export_fn_idx=3, data_off=1024, data_bytes=bytes(64), body=body)
    e = Engine(wasm); e.run()
    assert len(e.accepts) == 1 and len(e.rollbacks) == 1, "content-gated branches not both explored"
    s = z3.Solver(); s.add(*e.accepts[0][1])
    assert s.check() == z3.sat, "symbolic content accept wrongly concretized to infeasible"


def test_symbolic_field_retlen_into_memidx_fails_loud():
    # (c) the symbolic return length used as a memory ADDRESS must raise conc()
    # RuntimeError (fail loud -> exit 1), never silently flow on to a PROVEN.
    otxn_ft = _ftype([I32, I32, I32], [I64]); accept_ft = _ftype([I32, I32, I32], [I64])
    types = [_ftype([I32], [I64]), otxn_ft, accept_ft]

    def _imp(mod, nm, t):
        return _uleb(len(mod)) + mod.encode() + _uleb(len(nm)) + nm.encode() + bytes([0x00]) + _uleb(t)
    imports = [_imp("env", "otxn_field", 1), _imp("env", "accept", 2)]
    accept_call = _i32c(0) + _i32c(0) + _i64c(0) + bytes([0x10]) + _uleb(1) + bytes([0x1A])
    body = (_i32c(1024) + _i32c(8) + _i32c(0x50001) + bytes([0x10]) + _uleb(0)  # ret(i64) symbolic
            + bytes([0xA7])                                                     # i32.wrap_i64
            + bytes([0x28]) + _uleb(2) + _uleb(0)                              # i32.load (conc(symbolic addr)!)
            + bytes([0x1A]) + accept_call + _i64c(0) + bytes([0x0B]))
    wasm = _module(types, imports, export_fn_idx=2, data_off=1024, data_bytes=bytes(64), body=body)
    e = Engine(wasm)
    raised = False
    try:
        e.run()
    except RuntimeError:
        raised = True
    assert raised, "symbolic return length into a memory index must fail loud (conc RuntimeError)"
    assert not e.accepts, "must not reach an accept with a symbolic memory index"


def test_multivalue_blocktype_fails_loud():
    # FINDING 6: a multi-value blocktype (sLEB type index, high bit set) must raise
    # a clear NotImplementedError, not silently mis-align the decode.
    from wasm import parse
    # minimal module with a `block` whose blocktype byte has the high bit set
    types = [_ftype([I32], [I64])]

    def _imp(mod, nm, t):
        return _uleb(len(mod)) + mod.encode() + _uleb(len(nm)) + nm.encode() + bytes([0x00]) + _uleb(t)
    # block with blocktype 0x80 0x01 (a 2-byte sLEB type index) then end
    body = bytes([0x02, 0x80, 0x01, 0x0B]) + _i64c(0) + bytes([0x0B])
    wasm = _module(types, [], export_fn_idx=0, data_off=1024, data_bytes=b"\x00", body=body)
    raised = False
    try:
        parse(wasm)
    except NotImplementedError:
        raised = True
    assert raised, "multi-value blocktype should fail loud (NotImplementedError)"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
