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


def test_brtable_is_inconclusive_not_crash():
    # FINDING 4: br_table must record an unsupported op -> INCONCLUSIVE (exit 3),
    # not a confusing RuntimeError, and never PROVEN.
    wasm = _brtable_module()
    path = os.path.join(ROOT, "tests", "_tmp_brtable.wasm")
    open(path, "wb").write(wasm)
    try:
        e = Engine(wasm)
        e.run()                                          # must not raise
        assert "br_table" in e.unsupported, "br_table not flagged unsupported"
        rc = prove_termination.main(path)
    finally:
        os.remove(path)
    assert rc == 3, f"br_table must yield INCONCLUSIVE (3), got {rc}"


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
