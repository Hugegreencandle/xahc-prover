"""Regression tests for the prover engine — especially the soundness/semantics
fixes from the 3-lens audit. Run: python tests/test_prover.py  (or pytest)."""
import os
import sys
import z3

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
from prover import Engine, Path                      # noqa: E402
import prove_limit, prove_guardrail                  # noqa: E402

H = os.path.join(ROOT, "hooks")
ENG = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())  # any module, for method use


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
    assert prove_guardrail.main(os.path.join(H, "agent_guardrail.wasm")) == 0       # PROVEN
    assert prove_guardrail.main(os.path.join(H, "agent_guardrail_buggy.wasm"), SUPPLY) == 2


def test_decoder_tracks_types():
    from wasm import parse
    _, fs, _, g = parse(open(os.path.join(H, "agent_guardrail.wasm"), "rb").read())
    hook = next(f for f in fs if f.name == "hook")
    assert 0x7E in hook.localtypes, "i64 local valtype not tracked"
    assert g and g[0][0] == 65536, "global section (stack pointer) not parsed"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
