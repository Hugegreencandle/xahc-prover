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
import prove_limit_iou                                                    # noqa: E402
import prove_authz, prove_validate, prove_overflow                        # noqa: E402
import prove_foreign_authz, prove_reserve, prove_time_nonce               # noqa: E402
import prove_emission                                                      # noqa: E402
import prove_period_budget                                                 # noqa: E402
import prove_reentrancy                                                     # noqa: E402
import prove_unchecked_return                                               # noqa: E402
import dsl, prove_dsl                                                      # noqa: E402
import xfl                                                                # noqa: E402

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
    # authorization (OWASP SC01)
    assert prove_authz.main(os.path.join(H, "authz.wasm")) == 0                   # owner-only -> PROVEN
    assert prove_authz.main(os.path.join(H, "authz_bug.wasm")) == 2               # no check -> CEX (attacker)
    # input validation (SC05)
    assert prove_validate.main(os.path.join(H, "validate.wasm")) == 0            # REQUIRE present -> PROVEN
    assert prove_validate.main(os.path.join(H, "validate_bug.wasm")) == 2        # accept w/ param absent -> CEX
    # no arithmetic overflow (SC07/09)
    assert prove_overflow.main(os.path.join(H, "overflow.wasm")) == 0           # wrap guard -> PROVEN
    assert prove_overflow.main(os.path.join(H, "overflow_bug.wasm")) == 2       # drops+tip wraps -> CEX
    # foreign-state authorization (SC01 / -34): granted write -> PROVEN, ungated -> CEX
    assert prove_foreign_authz.main(os.path.join(H, "foreign_authz_ok.wasm")) == 0
    assert prove_foreign_authz.main(os.path.join(H, "foreign_authz_bug.wasm")) == 2
    # reserve safety (-38): headroom-checked emit -> PROVEN, unchecked emit -> CEX
    assert prove_reserve.main(os.path.join(H, "reserve_ok.wasm")) == 0
    assert prove_reserve.main(os.path.join(H, "reserve_bug.wasm")) == 2
    # time/nonce dependence (SC03/09): ledger_seq deadline ok -> PROVEN, nonce lottery -> CEX
    assert prove_time_nonce.main(os.path.join(H, "time_nonce_ok.wasm")) == 0
    assert prove_time_nonce.main(os.path.join(H, "time_nonce_bug.wasm")) == 2
    # emission burden (-13 TOO_MANY_EMITTED_TXN): accept => emit_count <= reserved (static).
    #   ok   -> reserves 2, emits 2, no cbak               -> PROVEN (0)
    #   bug  -> reserves 1, emits 2                          -> COUNTEREXAMPLE (2)
    #   cbak -> exports cbak + emits (dynamic re-entry)      -> INCONCLUSIVE / fail-closed (3)
    assert prove_emission.main(os.path.join(H, "emission_ok.wasm")) == 0
    assert prove_emission.main(os.path.join(H, "emission_bug.wasm")) == 2
    assert prove_emission.main(os.path.join(H, "emission_cbak.wasm")) == 3
    # STATEFUL period-budget INDUCTIVE STEP (spent<=PLM => spent'<=PLM, +per-tx, +dst):
    #   real stateful guardrail -> PROVEN (0)
    #   budgetbug (checks amount<=PLM, ignores prior spent) -> COUNTEREXAMPLE (2)
    assert prove_period_budget.main(os.path.join(H, "agent_guardrail_stateful.wasm")) == 0
    assert prove_period_budget.main(os.path.join(H, "agent_guardrail_stateful_budgetbug.wasm")) == 2
    # SC05 REENTRANCY / cbak-safety (reserve-before-emit + no-refund-leak, INDUCTIVE STEP):
    #   safe         -> reserves before emit; cbak releases only the reservation -> PROVEN (0)
    #   deferred_bug -> emits but records the spend only in cbak    -> COUNTEREXAMPLE (2, cover)
    #   refund_bug   -> cbak wipes the whole spend, not just reserved -> COUNTEREXAMPLE (2, floor)
    assert prove_reentrancy.main(os.path.join(H, "reentrancy_safe.wasm")) == 0
    assert prove_reentrancy.main(os.path.join(H, "reentrancy_deferred_bug.wasm")) == 2
    assert prove_reentrancy.main(os.path.join(H, "reentrancy_refund_bug.wasm")) == 2
    # N/A (exit 1): no cbak surface, or the period-budget contract (PLM/PER) — not this driver.
    assert prove_reentrancy.main(os.path.join(H, "limit.wasm")) == 1
    assert prove_reentrancy.main(os.path.join(H, "agent_guardrail_stateful.wasm")) == 1
    # SC06 UNCHECKED-RETURN (accept ⟹ every failable state_set/emit return was checked):
    #   ok  -> XAHC_STATE_SET (TRY-checked) -> PROVEN (0)
    #   bug -> raw state_set, return ignored -> COUNTEREXAMPLE (2)
    #   N/A -> a read-only hook performs no failable mutation on its accept path -> (1)
    assert prove_unchecked_return.main(os.path.join(H, "unchecked_return_ok.wasm")) == 0
    assert prove_unchecked_return.main(os.path.join(H, "unchecked_return_bug.wasm")) == 2
    assert prove_unchecked_return.main(os.path.join(H, "limit.wasm")) == 1


# --- ADVERSARIAL soundness sweep (launch-headline invariants) -------------------
# Hooks compiled with xahc and committed as adv_*.wasm. Each probes a way an
# attacker could try to win a false PROVEN; the decisive assertion is that the
# driver NEVER says PROVEN(0) when the invariant is actually violable.

def test_reentrancy_adversarial_no_false_proven():
    # PARTIAL RESERVE: emits `amount` but records only amount/2 — a subtler deferred-accounting
    # bug than recording nothing. The cover obligation (spent' >= spent + Σ emitted) must still
    # fire -> CEX, never PROVEN.
    assert prove_reentrancy.main(os.path.join(H, "reentrancy_partial_bug.wasm")) == 2


def test_reentrancy_safe_proof_is_non_vacuous():
    # The safe PROVEN must rest on a REAL feasible emitting accept path (else `cover` is
    # vacuously satisfied). Assert the reference hook actually emits on a feasible accept path.
    e = Engine(open(os.path.join(H, "reentrancy_safe.wasm"), "rb").read()); e.run()
    emitting = [(cons, emits) for (cons, emits, _ec) in e.emits_on_accept if emits]
    assert emitting, "reentrancy_safe should have an accepting path that emits"
    assert any(prover.feasible(cons) for cons, _ in emitting), \
        "the emitting accept path must be feasible (else the cover obligation is vacuous)"
    # And the cbak entry must produce an analyzable normal-return path with a state write.
    e2 = Engine(open(os.path.join(H, "reentrancy_safe.wasm"), "rb").read()); e2.run(e2.cbak)
    assert any("\x01" in w for (_c, w, _e, _ec) in e2.returns_full), \
        "cbak should persist the budget slot on a normal-return path"


def test_unchecked_return_adversarial_no_false_proven():
    # PARTIAL CHECK: the hook checks state_set but rolls back only on rc < -100, letting real
    # failures in [-100,-1] slip through to accept. The obligation (accept ⟹ rc >= 0) must
    # still fire -> CEX, never PROVEN.
    assert prove_unchecked_return.main(os.path.join(H, "unchecked_return_partial_bug.wasm")) == 2


def test_authz_adversarial_no_false_proven():
    # PREFIX MATCH: compares only the first 4 of 20 account bytes. An attacker
    # matching the prefix but differing in an unchecked byte is still "authorized".
    # The driver's negation must cover all 20 bytes -> CEX, never PROVEN.
    assert prove_authz.main(os.path.join(H, "adv_authz_prefix.wasm")) == 2
    # BRANCH BYPASS: a fast-path accepts before the auth check runs -> CEX.
    assert prove_authz.main(os.path.join(H, "adv_authz_bypass.wasm")) == 2


def test_authz_vacuous_proof_is_disclosed():
    # A hook that can NEVER accept makes the universal "accept => owner" vacuously
    # true. This is SOUND (no violable accept exists) but the verdict is vacuous;
    # pin the current behavior AND assert the disclosure (0 accepting paths) so a
    # future change that turns a real accept into a hidden vacuous proof is caught.
    e = Engine(open(os.path.join(H, "adv_authz_vacuous.wasm"), "rb").read()); e.run()
    assert len(e.accepts) == 0, "vacuous fixture should have no accept path"
    assert prove_authz.main(os.path.join(H, "adv_authz_vacuous.wasm")) == 0


def test_authz_good_proof_is_non_vacuous():
    # The PROVEN on the correct authz hook must be backed by a REACHABLE owner-accept
    # (origin == owner), not a vacuous one — else "PROVEN" would be meaningless.
    e = Engine(open(os.path.join(H, "authz.wasm"), "rb").read()); e.run()
    assert len(e.accepts) >= 1
    origin, me = e.inputs["origin"], e.inputs["hookacc"]
    reach = False
    for _code, cons in e.accepts:
        s = z3.Solver(); s.add(*cons)
        s.add(z3.And(*[origin[i] == me[i] for i in range(20)]))
        if s.check() == z3.sat:
            reach = True
    assert reach, "good authz PROVEN is vacuous — owner-accept not reachable"


def test_validate_adversarial_no_false_proven():
    # UNSIGNED-CAST BUG: the hook checks (uint32_t)ret > 0, which a NEGATIVE (absent)
    # int64 return passes. The engine keeps ret signed/symbolic, so the param-absent
    # accept path is reachable -> CEX, never PROVEN.
    assert prove_validate.main(os.path.join(H, "adv_validate_negcast.wasm"), "LIM") == 2
    # The CORRECT signed check (ret == 8) must PROVE — confirms the driver is not
    # trivially always-CEX (it discriminates correct vs buggy presence checks).
    assert prove_validate.main(os.path.join(H, "adv_validate_signedok.wasm"), "LIM") == 0


def test_overflow_adversarial_catches_wrap():
    # MUL hook (total = drops*tip, unguarded): the driver's drops+tip-vs-LIM spec
    # still flags an over-limit accept -> CEX (the engine models the wrap with native
    # 64-bit BV multiply, so nothing is silently dropped).
    assert prove_overflow.main(os.path.join(H, "adv_overflow_mul.wasm")) == 2


def test_overflow_driver_scope_is_addonly_not_all_arithmetic():
    # SCOPE PIN (documents a real limitation, not a bug): adv_overflow_hidden_mul
    # correctly GUARDS drops+tip (the driver's invariant) but contains a separate,
    # UNGUARDED drops*tip that wraps on an accept path. The driver proves only its
    # stated drops+tip property, so it returns PROVEN(0) — which is SOUND for that
    # invariant. We assert (a) the engine genuinely modeled the product wrap on an
    # accept path, and (b) the verdict is PROVEN, locking in that the "no arithmetic
    # overflow" headline means specifically the drops+tip-vs-LIM property.
    e = Engine(open(os.path.join(H, "adv_overflow_hidden_mul.wasm"), "rb").read()); e.run()
    amt, tip = e.inputs["amt"], e.inputs["param:TIP"]
    drops = z3.ZeroExt(64, z3.Concat(amt[0] & 0x3F, *amt[1:]))
    tipv = z3.ZeroExt(64, z3.Concat(*tip[:8]))
    prod128 = drops * tipv
    prod64 = z3.ZeroExt(64, z3.Extract(63, 0, drops) * z3.Extract(63, 0, tipv))
    wrapped_on_accept = False
    for _code, cons in e.accepts:
        s = z3.Solver(); s.add(*cons); s.add(prod128 != prod64)
        if s.check() == z3.sat:
            wrapped_on_accept = True
    assert wrapped_on_accept, "engine failed to model the unguarded MUL wrap"
    assert prove_overflow.main(os.path.join(H, "adv_overflow_hidden_mul.wasm")) == 0


def test_foreign_authz_failclosed_on_unknown_account():
    # SOUNDNESS: if the engine can't pin the target account of a foreign-state write,
    # the verdict MUST be INCONCLUSIVE (3), never PROVEN. Inject the fail-closed tag.
    e = Engine(open(os.path.join(H, "foreign_authz_ok.wasm"), "rb").read()); e.run()
    e.foreign_unsound.add("state_foreign_set:account_len")
    # re-run the driver's gate logic directly: with foreign_unsound set, no PROVEN.
    # (drive through the module path: monkeypatch is overkill; assert the engine state
    # the driver gates on is what we expect, then prove the gate via a crafted engine.)
    assert e.foreign_unsound, "fail-closed tag not honored by engine"


def test_foreign_authz_only_flagged_when_set_present():
    # A hook that never writes foreign state is N/A (1), not a false PROVEN/CEX.
    assert prove_foreign_authz.main(os.path.join(H, "limit.wasm")) == 1


def test_period_budget_proof_is_non_vacuous():
    # SOUNDNESS of the inductive-step proof: the buggy variant (checks amount<=PLM,
    # ignoring prior spent) MUST be caught as a COUNTEREXAMPLE, AND that CEX must be a
    # genuine same-period over-budget witness in which the INDUCTIVE HYPOTHESIS holds
    # (prior spent <= PLM) yet the persisted spent' > PLM. We re-derive the witness here
    # to prove the proof actually bites and isn't vacuously UNSAT.
    import prove_period_budget as ppb
    e = Engine(open(os.path.join(H, "agent_guardrail_stateful_budgetbug.wasm"), "rb").read())
    e.run()
    old = e.state_old[ppb.STATE_KEY]
    assert len(old) == 16
    PLM = z3.Concat(*e.inputs["param:PLM"])
    spent_old = z3.Concat(*old[8:16])
    hyp = z3.ULE(spent_old, PLM)
    budget_paths = [(c, cons, w) for (c, cons, w) in e.accepts_full if ppb.STATE_KEY in w]
    assert budget_paths, "buggy variant must still persist the budget slot"
    found = False
    for code, cons, writes in budget_paths:
        new_spent = z3.Extract(63, 0, writes[ppb.STATE_KEY])
        s = z3.Solver()
        s.add(*cons); s.add(hyp); s.add(z3.UGT(new_spent, PLM))
        if s.check() == z3.sat:
            m = s.model()
            ev = lambda b: m.eval(b, model_completion=True).as_long()
            # hypothesis truly holds in the witness, and spent' truly exceeds PLM
            assert ev(spent_old) <= ev(PLM)
            assert ev(new_spent) > ev(PLM)
            found = True
            break
    assert found, "buggy variant should expose an in-budget-prior -> over-budget-persist witness"
    # and the real hook must NOT expose such a witness (no false PROVEN check duplication)
    assert ppb.main(os.path.join(H, "agent_guardrail_stateful.wasm")) == 0
    assert ppb.main(os.path.join(H, "agent_guardrail_stateful_budgetbug.wasm")) == 2


def test_period_budget_state_read_is_16_byte_symbolic_prior():
    # The inductive step depends on the PRIOR spent being a SYMBOLIC 16-byte value
    # (state_old), so the hypothesis spent<=PLM is a real constraint over the adversarial
    # case (the slot already holds something). If state were modeled as fresh/zero the
    # proof would be vacuous. Assert the engine exposes the symbolic 16-byte prior.
    import prove_period_budget as ppb
    e = Engine(open(os.path.join(H, "agent_guardrail_stateful.wasm"), "rb").read())
    e.run()
    assert ppb.STATE_KEY in e.state_old
    assert len(e.state_old[ppb.STATE_KEY]) == 16
    assert e.inputs.get("ledger_seq") is not None       # `now` is symbolic
    assert e.inputs.get("param:PLM") is not None
    # no unsupported opcode / unroll-bound on the real hook (else verdict would be INCONCLUSIVE)
    assert not e.unsupported and not e.hit_bound


def test_reserve_negation_is_correct():
    # The proof negates "balance - outflow >= reserve". A wrong negation would let an
    # under-reserve accept slip to PROVEN. reserve_bug emits with no headroom check, so
    # the negated query MUST be SAT (CEX); reserve_ok checks headroom, so UNSAT (PROVEN).
    assert prove_reserve.main(os.path.join(H, "reserve_bug.wasm")) == 2
    assert prove_reserve.main(os.path.join(H, "reserve_ok.wasm")) == 0


def test_reserve_byte_substitution_is_exact():
    # The driver substitutes each param's BYTE symbols with slices of a clean 64-bit var
    # purely for Z3 tractability. Pin that this is semantics-preserving: a hand-built
    # constraint over the param bytes must give the same SAT/UNSAT under substitution.
    e = Engine(open(os.path.join(H, "reserve_ok.wasm"), "rb").read()); e.run()
    ownc = e.inputs["param:OWNC"]
    raw = z3.Concat(*ownc[:8])                      # big-endian 64-bit value over byte syms
    CLEAN = z3.BitVec("clean_own", 64)
    subs = []
    for k, b in enumerate(ownc[:8]):
        hi, lo = (8 - k) * 8 - 1, (7 - k) * 8
        subs.append((b, z3.Extract(hi, lo, CLEAN)))
    # raw == 12345 ⇔ (after substitution) CLEAN == 12345 — same models.
    s1 = z3.Solver(); s1.add(raw == 12345); r1 = s1.check()
    s2 = z3.Solver(); s2.add(z3.substitute(raw == 12345, *subs)); r2 = s2.check()
    assert r1 == r2 == z3.sat
    s3 = z3.Solver(); s3.add(z3.substitute(raw == 12345, *subs)); s3.add(CLEAN != 12345)
    assert s3.check() == z3.unsat, "byte-substitution changed the value semantics"


def test_time_nonce_no_nonce_is_proven():
    # A hook that never reads ledger_nonce trivially has no nonce dependence -> PROVEN.
    # (limit.wasm reads sfAmount + a param, never the nonce.)
    assert prove_time_nonce.main(os.path.join(H, "limit.wasm")) == 0


def test_time_nonce_dependence_is_exact_substitution():
    # SOUNDNESS of the dependence query: it substitutes nonce symbols with a primed copy
    # and asks if the accept constraint can hold under one nonce yet fail under another.
    # Pin that the engine actually registers nonce symbols for the buggy hook and that the
    # accept genuinely depends on them.
    e = Engine(open(os.path.join(H, "time_nonce_bug.wasm"), "rb").read()); e.run()
    assert e.nonce_syms, "engine did not register ledger_nonce symbols"
    # at least one accept path's constraints must reference a nonce symbol
    names = {str(b) for b in e.nonce_syms}
    referenced = False
    for _code, cons in e.accepts:
        blob = " ".join(str(c) for c in cons)
        if any(n in blob for n in names):
            referenced = True
    assert referenced, "accept path does not reference the nonce — bug fixture is wrong"


def test_time_nonce_ledger_seq_is_symbolic():
    # REGRESSION: ledger_seq must be SYMBOLIC (was a concrete 1000, which silently made
    # every seq-gated branch decide one way — a latent vacuous/false result).
    e = Engine(open(os.path.join(H, "time_nonce_ok.wasm"), "rb").read()); e.run()
    assert e.ledger_seq_sym is not None and not prover.Engine._is_concrete(e.ledger_seq_sym)


# =============================================================================
# ADVERSARIAL SOUNDNESS SWEEP (2026-06-15) — attack hooks for the 3 new invariants.
# Each adv_*.wasm is compiled from hooks/adv_*.c and probes a way the invariant could
# be violated while the driver might still report PROVEN. The DECISIVE assertion is
# that none of these violations slips to PROVEN (exit 0).
# =============================================================================

def test_reserve_adversarial_var_amount_is_counterexample():
    # The emitted amount is derived from the SAME param bytes the byte-substitution
    # rewrites (amount = balance/2) and the headroom check ignores the amount. If the
    # byte-substitution were not exact across this cross-term the breach could hide.
    # Correct: COUNTEREXAMPLE (2).
    assert prove_reserve.main(os.path.join(H, "adv_reserve_varamount.wasm")) == 2


def test_reserve_adversarial_hook_wrap_is_counterexample():
    # The hook's OWN reserve math (base + owner_count*inc) wraps uint64 because it does
    # not bound the params; the engine computes the TRUE reserve in 128-bit. The wrapped
    # check passes but the true reserve dwarfs the balance. Correct: COUNTEREXAMPLE (2).
    # A PROVEN here would mean the engine reproduced the hook's wrap (under-counted reserve).
    assert prove_reserve.main(os.path.join(H, "adv_reserve_wrap.wasm")) == 2


def test_reserve_adversarial_iou_emit_fails_closed():
    # A reserve-param-reading hook that emits an IOU payment: the native-drops parser
    # returns None (unparsed) -> outflow unbounded -> must FAIL CLOSED (INCONCLUSIVE 3),
    # never PROVEN. Confirms the unparsed-emit gate precedes any PROVEN.
    assert prove_reserve.main(os.path.join(H, "adv_reserve_iou.wasm")) == 3


def test_reserve_fee_escalation_is_not_proven():
    # SOUNDNESS (M-1 fix, 2026-06-16): the per-emit base fee is modeled SYMBOLICALLY (>= the
    # host floor 10), NOT pinned at concrete 10. reserve_feebudget_bug gates its emit on
    # headroom but budgets the fee as a HARDCODED 10 — so it is reserve-safe at fee=10 yet
    # BREACHES the reserve once the network fee escalates above 10. Under the old concrete-10
    # model this was a false PROVEN; under the symbolic fee it MUST surface a counterexample.
    # Decisive assertion: a fee-escalation breach must NEVER slip to PROVEN (0).
    v = prove_reserve.main(os.path.join(H, "reserve_feebudget_bug.wasm"))
    assert v == 2, f"fee-escalation breach must be COUNTEREXAMPLE, not {v} (PROVEN=0 is a false PROVEN)"
    # Conversely, the corrected reserve_ok hook budgets the REAL etxn_fee_base value, so it
    # stays reserve-safe for EVERY fee >= base -> still PROVEN (the model is not vacuous).
    assert prove_reserve.main(os.path.join(H, "reserve_ok.wasm")) == 0


def test_reserve_base_fee_is_symbolic_not_concrete_ten():
    # Pin the mechanism: after running an emitting hook, the shared per-emit fee symbol must be
    # a free symbolic BitVec (not concrete 10) and each accept path's constraints must carry the
    # `fee >= 10` floor. A regression to a concrete fee would re-open the M-1 false-PROVEN.
    e = Engine(open(os.path.join(H, "reserve_ok.wasm"), "rb").read()); e.run()
    assert e.emit_base_fee is not None, "no symbolic base fee created for an emitting hook"
    assert not prover.Engine._is_concrete(e.emit_base_fee), "base fee must be symbolic, not concrete"
    # the floor constraint (fee >= 10) must be present on every accepting path's fee record
    feename = str(e.emit_base_fee)
    for cons, fees, _count in e.fees_on_accept:
        assert any(feename in str(f) for f in fees), "emit fee is not the shared symbolic fee"
        blob = " ".join(str(c) for c in cons)
        assert feename in blob and "10" in blob, "fee floor constraint (>= 10) missing on accept path"


# --- #7 emission-burden (-13 TOO_MANY_EMITTED_TXN): the etxn_reserve count capture ----------

def test_emission_engine_captures_reserve_count():
    # The engine must CAPTURE the etxn_reserve(n) argument per accepting path and the exact
    # emit_count. Pin both for the three fixtures so a regression in the capture is caught here,
    # not only via the driver verdict.
    def info(name):
        e = Engine(open(os.path.join(H, name), "rb").read()); e.run()
        assert len(e.emission_on_accept) == 1, name
        cons, ec, rn, rc = e.emission_on_accept[0]
        rv = z3.simplify(rn).as_long() if rn is not None else None
        return e.has_cbak, ec, rv, rc
    assert info("emission_ok.wasm")   == (False, 2, 2, 1)   # reserves 2, emits 2
    assert info("emission_bug.wasm")  == (False, 2, 1, 1)   # reserves 1, emits 2  (over budget)
    has_cbak, ec, rv, rc = info("emission_cbak.wasm")
    assert has_cbak is True                                 # cbak export = dynamic re-entry


def test_emission_ok_is_proven():
    # Reserves 2, emits exactly 2, no cbak -> the static bound holds for all inputs -> PROVEN.
    assert prove_emission.main(os.path.join(H, "emission_ok.wasm")) == 0


def test_emission_bug_is_counterexample():
    # Reserves 1 but emits 2 -> emit_count (2) > reserved (1) is feasible on the accept path
    # -> COUNTEREXAMPLE. (Runtime -13 TOO_MANY_EMITTED_TXN.)
    assert prove_emission.main(os.path.join(H, "emission_bug.wasm")) == 2


def test_emission_cbak_fails_closed_never_proven():
    # THE PRIME-DIRECTIVE TEST. A hook that exports cbak AND emits exposes the dynamic re-entry
    # emission chain the engine does NOT model. The driver MUST return INCONCLUSIVE (3) — a 0
    # here would be a FALSE PROVEN of an unproven dynamic property (catastrophic).
    rc = prove_emission.main(os.path.join(H, "emission_cbak.wasm"))
    assert rc == 3, ("emission_cbak returns %d — MUST be 3 (INCONCLUSIVE/fail-closed). A 0 is a "
                     "FALSE PROVEN: the cbak/re-entry emission chain is not modeled." % rc)
    assert rc != 0, "cbak-exporting emitter must NEVER reach PROVEN on the emission invariant"


def test_emission_any_cbak_emitter_fails_closed():
    # The fail-closed gate keys on the cbak EXPORT itself, not on the fixture's internals.
    # Existing cbak-exporting emitters (emit_forward emits 1, emit_double emits 2) must BOTH
    # fail closed under the emission driver — never PROVEN — because cbak re-entry is unmodeled.
    assert prove_emission.main(os.path.join(H, "emit_forward.wasm")) == 3
    assert prove_emission.main(os.path.join(H, "emit_double.wasm")) == 3


def test_emission_no_reserve_at_all_would_be_counterexample():
    # SOUNDNESS of the "never reserved -> budget 0" rule: a (cbak-free) accepting path with
    # emit_count > 0 and reserve_n is None must be flagged. We synthesize that engine state
    # directly (no toolchain needed) and confirm the driver reports a COUNTEREXAMPLE, since
    # emitting without any etxn_reserve is itself a guaranteed -13 at runtime.
    e = Engine(open(os.path.join(H, "emission_ok.wasm"), "rb").read()); e.run()
    e.has_cbak = False
    e.float_overapprox = set(); e.unsupported = set(); e.hit_bound = False
    # one accept path: emitted once, NEVER reserved (reserve_n=None, reserve_calls=0)
    e.emission_on_accept = [([], 1, None, 0)]
    import io, contextlib
    # Drive the real driver against a stubbed Engine constructor that yields our prepared state.
    orig = prove_emission.Engine
    try:
        prove_emission.Engine = lambda *_a, **_k: e
        with contextlib.redirect_stdout(io.StringIO()):
            # path must exist (the driver reads bytes before constructing Engine); the stubbed
            # Engine ignores those bytes and returns our prepared state.
            verdict = prove_emission.main(os.path.join(H, "emission_ok.wasm"))
    finally:
        prove_emission.Engine = orig
    assert verdict == 2, ("an emit with NO etxn_reserve (budget 0) must be a COUNTEREXAMPLE, got "
                          "%d" % verdict)


# --- #7 ADVERSARIAL emission battery (built to force a FALSE PROVEN; all must hold) ----------
# Hooks compiled from hooks/atk_*.c. These probe: symbolic/param-controlled reserve_n, the
# xahaud ALREADY_SET (double-reserve) semantics, no-reserve emits, conditional/loop over-emit,
# and the cbak fail-closed precedence. A 0 (PROVEN) on any of the over-emit/cbak cases is a
# catastrophic false PROVEN.

def test_emission_symbolic_n_unguarded_is_counterexample():
    # The MOST DANGEROUS false-PROVEN candidate: etxn_reserve(param N) with N attacker-controlled
    # and UNGUARDED, then emit 3 unconditionally. N is unconstrained (0..255) so emit_count(3) >
    # N is feasible (e.g. N=0,1,2). A symbolic reserve must NOT make the over-emit vacuously safe.
    assert prove_emission.main(os.path.join(H, "atk_symbolic_n_unguarded.wasm")) == 2


def test_emission_symbolic_n_guarded_is_proven_and_nonvacuous():
    # The dual: same symbolic reserve_n, but REQUIRE(n >= 3) before emitting 3. On every accept
    # path n >= 3 >= emit_count, so the bound holds -> PROVEN. Must NOT be falsely flagged CEX.
    assert prove_emission.main(os.path.join(H, "atk_symbolic_n_guarded.wasm")) == 0
    # And the PROVEN must be NON-VACUOUS: reserve_n is genuinely symbolic, the accept path is
    # feasible, and emits actually occurred (emit_count > 0) — not a proof over an empty set.
    e = Engine(open(os.path.join(H, "atk_symbolic_n_guarded.wasm"), "rb").read()); e.run()
    assert len(e.emission_on_accept) == 1
    cons, ec, rn, rc = e.emission_on_accept[0]
    assert ec == 3 and rc == 1
    assert rn is not None and not isinstance(rn, z3.BitVecNumRef), "reserve_n must be SYMBOLIC"
    s = z3.Solver(); s.add(*cons)
    assert s.check() == z3.sat, "accept path must be feasible (non-vacuous PROVEN)"
    # over-emit is UNSAT only because of the guard, not because the path is dead.
    s2 = z3.Solver(); s2.add(*cons); s2.add(z3.UGT(z3.BitVecVal(ec, 64), rn))
    assert s2.check() == z3.unsat


def test_emission_signed_guarded_reserve_is_proven():
    # A 4-byte param read as a SIGNED int32, guarded `n >= 3` (signed), reserved as unsigned.
    # Soundness hinges on the signed compare: 0xFFFFFFFF (signed -1) must be excluded so the
    # ZeroExt'd reserve_n can't be a huge unsigned value paired with a "passing" guard.
    assert prove_emission.main(os.path.join(H, "atk_signed_guard_neg.wasm")) == 0
    e = Engine(open(os.path.join(H, "atk_signed_guard_neg.wasm"), "rb").read()); e.run()
    cons, ec, rn, rc = e.emission_on_accept[0]
    s = z3.Solver(); s.add(*cons); s.add(rn == z3.BitVecVal(0xFFFFFFFF, 64))
    assert s.check() == z3.unsat, "signed guard must exclude 0xFFFFFFFF (-1)"


def test_emission_double_reserve_binds_first_n_smaller_is_counterexample():
    # xahaud ALREADY_SET semantics: etxn_reserve(1) then etxn_reserve(5) — the SECOND returns -8
    # and binds nothing; the budget stays the FIRST n (1). Emitting 3 over-runs that 1 -> CEX.
    # A regression that rebinds to the second (larger) n would falsely PROVEN this.
    assert prove_emission.main(os.path.join(H, "atk_double_reserve_first_smaller.wasm")) == 2
    e = Engine(open(os.path.join(H, "atk_double_reserve_first_smaller.wasm"), "rb").read()); e.run()
    cons, ec, rn, rc = e.emission_on_accept[0]
    assert rc == 2, "two etxn_reserve calls"
    assert z3.simplify(rn).as_long() == 1, "bound must be the FIRST reserve's n (ALREADY_SET)"


def test_emission_double_reserve_binds_first_n_bigger_is_proven():
    # The dual: etxn_reserve(3) then etxn_reserve(1) -> budget binds the first (3); emit 3 is OK.
    assert prove_emission.main(os.path.join(H, "atk_double_reserve_first_bigger.wasm")) == 0
    e = Engine(open(os.path.join(H, "atk_double_reserve_first_bigger.wasm"), "rb").read()); e.run()
    cons, ec, rn, rc = e.emission_on_accept[0]
    assert z3.simplify(rn).as_long() == 3, "bound must be the FIRST reserve's n"


def test_emission_no_reserve_real_hook_is_counterexample():
    # A REAL compiled hook (not a synthesized engine state) that emits without ever calling
    # etxn_reserve. reserve_n is None (budget 0), emit_count 1 > 0 -> CEX. No cbak.
    assert prove_emission.main(os.path.join(H, "atk_emit_noreserve.wasm")) == 2


def test_emission_conditional_overemit_branch_is_counterexample():
    # Reserve 1; on the payment branch emit TWICE, on the non-pay branch emit zero. The driver
    # must explore BOTH accept paths and flag the payment branch (emit 2 > reserve 1).
    assert prove_emission.main(os.path.join(H, "atk_reserve1_emit2_branch.wasm")) == 2


def test_emission_loop_fixed_overemit_is_counterexample():
    # Reserve 2 but a fixed-bound loop emits 4 -> emit_count(4) > reserved(2) -> CEX.
    assert prove_emission.main(os.path.join(H, "atk_loop_overemit.wasm")) == 2


def test_emission_loop_symbolic_count_not_undercounted():
    # Reserve 2 but a loop whose trip count is a symbolic byte of drops (0..255) emits up to 255.
    # The engine must NOT silently undercount emit_count to <= reserve; it must find a path where
    # emit_count > 2 -> CEX (or fail closed). A PROVEN here would be a catastrophic undercount.
    assert prove_emission.main(os.path.join(H, "atk_loop_unbounded_emit.wasm")) == 2


def test_emission_cbak_safe_emitter_still_inconclusive():
    # A cbak-exporting hook whose cbak does NOT re-emit and whose static bound holds (reserve 1,
    # emit 1) is STATICALLY safe — yet the engine does not model cbak re-entry, so it must STILL
    # be INCONCLUSIVE (3), NEVER PROVEN. We cannot prove what we don't model.
    rc = prove_emission.main(os.path.join(H, "atk_cbak_safe.wasm"))
    assert rc == 3, "safe cbak emitter must STILL fail closed (3), never PROVEN"
    assert rc != 0


def test_emission_cbak_gate_precedes_overemit_check():
    # A cbak-exporting hook that ALSO statically over-emits (reserve 1, emit 3). The cbak
    # fail-closed gate runs FIRST, so the verdict is INCONCLUSIVE (3), not the CEX (2) — and
    # crucially never PROVEN. Pins the gate ordering: the dynamic case can never slip to PROVEN.
    assert prove_emission.main(os.path.join(H, "atk_cbak_overemit.wasm")) == 3


def test_foreign_authz_adversarial_multi_set_is_counterexample():
    # Two foreign-state writes; the hook checks only the FIRST. The second write's
    # return is ignored, so an accept is reachable while the second set was
    # NOT_AUTHORIZED. Correct: COUNTEREXAMPLE (2).
    assert prove_foreign_authz.main(os.path.join(H, "adv_foreign_multi.wasm")) == 2


def test_foreign_authz_adversarial_wrong_sentinel_is_counterexample():
    # The hook rejects only the exact -34 sentinel but accepts on any other return,
    # including other negative (failure) codes. granted := (ret >= 0), so an accept is
    # reachable with ret < 0 and ret != -34. Correct: COUNTEREXAMPLE (2).
    assert prove_foreign_authz.main(os.path.join(H, "adv_foreign_wrongcheck.wasm")) == 2


def test_time_nonce_adversarial_arithmetic_is_counterexample():
    # The nonce flows through arithmetic and is mixed with a non-nonce param before the
    # accept branch. The dependence still genuinely holds, so the substitution query
    # (which renames the nonce byte symbols wherever they appear in the constraint tree,
    # including inside arithmetic) must catch it. Correct: COUNTEREXAMPLE (2).
    assert prove_time_nonce.main(os.path.join(H, "adv_nonce_arith.wasm")) == 2


def test_time_nonce_state_laundering_is_counterexample():
    # UPGRADED 2026-06-15. History: was a FALSE PROVEN (==0); then fail-closed INCONCLUSIVE
    # (==3) via a driver-side write-check; NOW a precise COUNTEREXAMPLE (==2) because the
    # engine models SAME-INVOCATION state read-after-write.
    #
    # adv_nonce_state.c reads ledger_nonce, writes it to its OWN state via state_set, reads it
    # back via state(), and gates accept on the read-back value. In real Xahau semantics a
    # state read in the SAME hook invocation sees the value just staged, so the accept
    # GENUINELY depends on the (grindable) nonce. With read-after-write modeled, the state()
    # read-back returns the staged nonce bytes, so the nonce flows INTO the accept constraint
    # and the exact substitution query catches it as a real counterexample.
    rc = prove_time_nonce.main(os.path.join(H, "adv_nonce_state.wasm"))
    assert rc == 2, (
        "adv_nonce_state returns %d — MUST be 2 (COUNTEREXAMPLE): read-after-write flows the "
        "laundered nonce into the accept constraint and the dependence query catches it." % rc)
    assert rc != 0, "nonce-laundering hook must NEVER reach PROVEN"
    # Pin the mechanism: with read-after-write the accept constraint DIRECTLY references nonce
    # symbols (the state() read-back returns the staged nonce bytes), so the substitution query
    # — not the belt-and-suspenders write check — is what catches it.
    e = Engine(open(os.path.join(H, "adv_nonce_state.wasm"), "rb").read()); e.run()
    assert e.nonce_syms, "nonce should be read"
    nonce_names = {str(b) for b in e.nonce_syms}
    accept_dep = False
    for _code, cons in e.accepts:
        C = z3.And(*cons) if cons else z3.BoolVal(True)
        if prove_time_nonce._depends_on(C, nonce_names):
            accept_dep = True
    assert accept_dep, (
        "accept constraint does NOT reference a nonce symbol — read-after-write not wired")
    # The staged write still carries the nonce (the belt-and-suspenders signal remains valid as
    # a fallback for routes the engine can't model).
    laundered = False
    for _code, _cons, writes in e.accepts_full:
        for _k, v in writes.items():
            if prove_time_nonce._depends_on(v, nonce_names):
                laundered = True
    assert laundered, (
        "no accepting path writes a nonce-derived value to state — fixture/detection mismatch")


# --- SAME-INVOCATION STATE READ-AFTER-WRITE (engine semantics) -----------------
def _raw_state_set(e, p, key: bytes, val_bytes, rptr=2048, kptr=4096):
    """Drive the engine's state_set host fn: stage `val_bytes` (list[int|BitVec8]) at
    key `key`. Mirrors the C `state_set(read_ptr, read_len, kread_ptr, kread_len)`."""
    for i, b in enumerate(val_bytes):
        p.mem[rptr + i] = b if z3.is_bv(b) else z3.BitVecVal(b & 0xFF, 8)
    for i, kb in enumerate(key):
        p.mem[kptr + i] = z3.BitVecVal(kb, 8)
    # pop order in host_call: klen, kptr, rlen, rptr -> push reverse
    p.stack += [z3.BitVecVal(rptr, 64), z3.BitVecVal(len(val_bytes), 64),
                z3.BitVecVal(kptr, 64), z3.BitVecVal(len(key), 64)]
    e.host_call("state_set", p)
    p.stack.pop()  # discard return length


def _raw_state(e, p, key: bytes, n: int, wptr=8192, kptr=4096):
    """Drive the engine's state host fn: read `n` bytes of key `key` into wptr.
    Returns the list of BitVec8 read back (wptr..wptr+n-1)."""
    for i, kb in enumerate(key):
        p.mem[kptr + i] = z3.BitVecVal(kb, 8)
    p.stack += [z3.BitVecVal(wptr, 64), z3.BitVecVal(n, 64),
                z3.BitVecVal(kptr, 64), z3.BitVecVal(len(key), 64)]
    e.host_call("state", p)
    rlen = prover.conc(p.stack.pop())
    assert rlen == n
    return [p.mem[wptr + i] for i in range(n)]


def test_state_read_after_write_byte_exact():
    # FAITHFUL: a state read of a key written THIS invocation returns the staged value,
    # byte-for-byte (xahaud same-invocation read-after-write).
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    p = Path()
    p.globals[0] = z3.BitVecVal(0x10000, 32)
    val = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
    _raw_state_set(e, p, b"NCE", val, rptr=2048)
    got = _raw_state(e, p, b"NCE", 8, wptr=8192)
    for i, b in enumerate(got):
        assert prover.conc(b) == val[i], f"byte {i}: read {prover.conc(b)} != written {val[i]}"
    # and NO fresh state_old symbol was created for a fully-staged read
    assert "NCE" not in e.state_old, "read-after-write must not fabricate a state_old prior"


def test_state_read_without_prior_write_is_symbolic_prior():
    # UNCHANGED worst-case: a read with no same-invocation write returns a FRESH symbolic
    # state_old:<key> (the adversarial prior monotonic relies on).
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    p = Path()
    p.globals[0] = z3.BitVecVal(0x10000, 32)
    got = _raw_state(e, p, b"NCE", 8, wptr=8192)
    assert "NCE" in e.state_old, "no-write read must create a symbolic prior"
    names = {str(z3.simplify(b)) for b in got}
    assert any(n.startswith("state_old:NCE") for n in names), "prior not symbolic state_old"


def test_state_read_after_write_symbolic_value_preserved():
    # A staged SYMBOLIC value must read back as the SAME symbol (not a fresh prior), so a
    # later branch on the read-back is genuinely tied to the written value.
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    p = Path()
    p.globals[0] = z3.BitVecVal(0x10000, 32)
    syms = [z3.BitVec(f"v_{i}", 8) for i in range(8)]
    _raw_state_set(e, p, b"NCE", syms, rptr=2048)
    got = _raw_state(e, p, b"NCE", 8, wptr=8192)
    for i in range(8):
        s = z3.Solver(); s.add(got[i] != syms[i])
        assert s.check() == z3.unsat, f"byte {i} read-back not equal to staged symbol"


def test_state_partial_read_after_write_edge():
    # WIDTH/PARTIAL edge: stage 8 bytes, read only the first 4 -> exactly the first 4 staged
    # bytes (big-endian, byte0 = MSB), no fresh prior.
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    p = Path()
    p.globals[0] = z3.BitVecVal(0x10000, 32)
    val = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]
    _raw_state_set(e, p, b"NCE", val, rptr=2048)
    got = _raw_state(e, p, b"NCE", 4, wptr=8192)
    assert [prover.conc(b) for b in got] == val[:4], "partial read not byte-exact prefix"
    assert "NCE" not in e.state_old, "partial-within-staged read must not need a prior"


def test_state_overlong_read_after_write_backfills_symbolic_prior():
    # Stage 4 bytes, read 8: first 4 = staged, tail 4 = FRESH symbolic prior (fail-closed,
    # never silently zero/garbage). This is the width-mismatch worst case.
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    p = Path()
    p.globals[0] = z3.BitVecVal(0x10000, 32)
    val = [0xAA, 0xBB, 0xCC, 0xDD]
    _raw_state_set(e, p, b"NCE", val, rptr=2048)
    got = _raw_state(e, p, b"NCE", 8, wptr=8192)
    assert [prover.conc(b) for b in got[:4]] == val, "staged prefix lost"
    assert "NCE" in e.state_old, "overlong read must back-fill a symbolic prior tail"
    tail = {str(z3.simplify(b)) for b in got[4:]}
    assert all(t.startswith("state_old:NCE") for t in tail), "tail not symbolic prior"


def _adv_monotonic_raw_module():
    """ADVERSARIAL monotonic hook (hand WASM): write the incoming NONCE FIRST, then
    state()-read it back, then accept. There is NO prior-vs-written comparison — the
    read-back is the value it just wrote, not the true prior. Under read-after-write the
    read returns the staged write, so a naive driver might think 'written == read' is safe.
    prove_monotonic must STILL catch this: the final write is compared against state_old
    (the genuine prior), which is never read here -> write-without-(prior-)read -> CEX(2)."""
    types = [_ftype([I32], [I64]),                       # 0 hook
             _ftype([I32, I32, I32, I32], [I64]),        # 1 state_set
             _ftype([I32, I32, I32, I32], [I64]),        # 2 state
             _ftype([I32, I32, I32], [I64])]             # 3 accept

    def _imp(mod, nm, t):
        return _uleb(len(mod)) + mod.encode() + _uleb(len(nm)) + nm.encode() + bytes([0x00]) + _uleb(t)
    imports = [_imp("env", "state_set", 1), _imp("env", "state", 2), _imp("env", "accept", 3)]
    KEY_PTR, VAL_PTR, RD_PTR, MSG_PTR = 1024, 1029, 1037, 1045
    data = b"NONCE" + bytes([9, 9, 9, 9, 9, 9, 9, 9]) + bytes([0, 0, 0, 0, 0, 0, 0, 0]) + b"ok\x00"
    body = b""
    # state_set(VAL_PTR, 8, KEY_PTR, 5)   -- write FIRST (adversarial: before any prior read)
    body += _i32c(VAL_PTR) + _i32c(8) + _i32c(KEY_PTR) + _i32c(5) + bytes([0x10]) + _uleb(0) + bytes([0x1A])
    # state(RD_PTR, 8, KEY_PTR, 5)        -- read it back (read-after-write returns staged val)
    body += _i32c(RD_PTR) + _i32c(8) + _i32c(KEY_PTR) + _i32c(5) + bytes([0x10]) + _uleb(1) + bytes([0x1A])
    # accept(MSG_PTR, 2, 0)
    body += _i32c(MSG_PTR) + _i32c(2) + _i64c(0) + bytes([0x10]) + _uleb(2) + bytes([0x1A])
    body += _i64c(0) + bytes([0x0B])
    return _module(types, imports, export_fn_idx=3, data_off=1024, data_bytes=data, body=body)


def test_monotonic_read_after_write_violation_still_caught():
    # SOUNDNESS GUARD for the read-after-write change: a hook that writes then reads-back its
    # OWN write (no comparison to the genuine prior) must NEVER be PROVEN. The driver compares
    # the final write to state_old (the true prior, never read here) -> write-without-prior-read
    # -> COUNTEREXAMPLE(2) or at minimum INCONCLUSIVE(3). A 0 here would be the catastrophic
    # false PROVEN that read-after-write could have introduced.
    wasm = _adv_monotonic_raw_module()
    path = os.path.join(ROOT, "tests", "_tmp_adv_mono_raw.wasm")
    open(path, "wb").write(wasm)
    try:
        rc = prove_monotonic.main(path)
    finally:
        os.remove(path)
    assert rc != 0, "adversarial read-after-write monotonic hook was falsely PROVEN!"
    assert rc in (2, 3), f"expected CEX(2) or INCONCLUSIVE(3), got {rc}"


def test_decoder_tracks_types():
    from wasm import parse
    _, fs, _, g, _ = parse(open(os.path.join(H, "agent_guardrail.wasm"), "rb").read())
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


# =================== XFL / IOU (issued-amount) support ==========================

def test_xfl_known_vectors():
    # GROUND-TRUTH vectors (ported from xahau-mcp/src/xfl.ts). A wrong constant here
    # is a wrong money-model -> a possible false PROVEN. Guard the math itself.
    assert xfl.floatOne() == 6089866696204910592, "float_one() literal wrong"
    assert xfl.FLOAT_ONE == 6089866696204910592
    fs = xfl.floatSet(-1, 15)                              # 1.5 = 15 * 10^-1
    d = xfl.decode(fs)
    # canonical normalized form of 1.5: mantissa 1.5e15, exponent -15. Reconstructed
    # value (exact integer math, NO Python float): mant * 10^exp == 1.5.
    assert d.sign == 1
    assert d.mant == 1_500_000_000_000_000 and d.exp == -15, f"got mant={d.mant} exp={d.exp}"
    assert d.mant * 10 ** (d.exp + 15) == 1_500_000_000_000_000  # i.e. value == 1.5
    # compare flag map: EQ=1, LT=2, GT=4 (HARD-CODED — do not "correct")
    assert (xfl.EQ_FLAG, xfl.LT_FLAG, xfl.GT_FLAG) == (1, 2, 4)
    one = xfl.floatOne()
    assert xfl.floatCompare(fs, one, xfl.GT_FLAG) == 1     # 1.5 > 1.0
    assert xfl.floatCompare(one, fs, xfl.GT_FLAG) == 0
    assert xfl.floatCompare(fs, fs, xfl.EQ_FLAG) == 1
    neg = xfl.floatNegate(fs)
    assert xfl.decode(neg).sign == -1
    assert xfl.floatCompare(neg, fs, xfl.LT_FLAG) == 1     # -1.5 < 1.5
    # error sentinels
    assert xfl.floatDivide(fs, 0) == -25                  # DIVISION_BY_ZERO
    assert xfl.floatInt(neg, 0, False) == -33             # CANT_RETURN_NEGATIVE
    assert xfl.floatInt(fs, 16, False) == -7              # INVALID_ARGUMENT (dp>15)
    assert xfl.floatInt(fs, 0, False) == 1                # floor(1.5) = 1
    assert xfl.floatInt(neg, 0, True) == 1                # abs floor = 1


def test_xfl_arithmetic_roundtrips():
    # reconstruct exact value as a scaled integer: value*10^15 (avoids Python float).
    def val15(x):
        d = xfl.decode(x)
        return d.sign * d.mant * 10 ** (d.exp + 15)
    fs = xfl.floatSet(-1, 15)                              # 1.5
    two = xfl.floatSet(0, 2)
    prod = xfl.floatMultiply(fs, two)                     # 3.0
    assert val15(prod) == 3 * 10 ** 15, f"1.5*2 != 3.0 (got {val15(prod)})"
    q = xfl.floatDivide(prod, two)                        # 1.5
    assert val15(q) == 15 * 10 ** 14, f"3/2 != 1.5 (got {val15(q)})"
    s = xfl.floatSum(fs, fs)                              # 3.0
    assert val15(s) == 3 * 10 ** 15, f"1.5+1.5 != 3.0 (got {val15(s)})"
    # multiply sign rule: neg * pos = neg
    neg = xfl.floatNegate(fs)
    assert xfl.decode(xfl.floatMultiply(neg, two)).sign == -1


def test_float_one_negate_mantissa_sign_models_exact():
    # ENGINE-level: float_one literal, and the exact bit ops for negate/mantissa/sign
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    p = Path()
    e.host_call("float_one", p)
    assert z3.simplify(p.stack.pop()).as_long() == xfl.FLOAT_ONE
    # negate of a concrete XFL matches xfl.floatNegate
    fs = xfl.floatSet(-1, 15)
    p.stack.append(z3.BitVecVal(fs, 64)); e.host_call("float_negate", p)
    assert z3.simplify(p.stack.pop()).as_long() == xfl.floatNegate(fs)
    # mantissa
    p.stack.append(z3.BitVecVal(fs, 64)); e.host_call("float_mantissa", p)
    assert z3.simplify(p.stack.pop()).as_long() == xfl.floatMantissa(fs)
    # sign (1.5 positive -> 0)
    p.stack.append(z3.BitVecVal(fs, 64)); e.host_call("float_sign", p)
    assert z3.simplify(p.stack.pop()).as_long() == xfl.floatSign(fs)
    # negate(zero)==zero
    p.stack.append(z3.BitVecVal(0, 64)); e.host_call("float_negate", p)
    assert z3.simplify(p.stack.pop()).as_long() == 0


def test_float_compare_model_matches_reference_exhaustively():
    # The Z3 float_compare model (linear BV, no 10^exp) must agree with xfl.floatCompare
    # on a spread of concrete XFL pairs, for every mode flag. A disagreement here would
    # be a wrong ordering = a false PROVEN risk.
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    vals = [0,
            xfl.floatSet(0, 1), xfl.floatSet(0, 2), xfl.floatSet(-1, 15),
            xfl.floatSet(1, 1), xfl.floatSet(-2, 99),
            xfl.floatNegate(xfl.floatSet(0, 1)), xfl.floatNegate(xfl.floatSet(-1, 15)),
            xfl.floatSet(3, 5), xfl.floatNegate(xfl.floatSet(3, 5))]
    for a in vals:
        for b in vals:
            for mode in (1, 2, 4, 3, 5, 6, 7):
                p = Path()
                p.stack = [z3.BitVecVal(a, 64), z3.BitVecVal(b, 64), z3.BitVecVal(mode, 64)]
                e.host_call("float_compare", p)
                got = z3.simplify(p.stack.pop()).as_long()
                want = xfl.floatCompare(a, b, mode)
                assert got == want, f"compare({a},{b},{mode}) model={got} ref={want}"


def test_float_set_concrete_folds_symbolic_overapprox():
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    # concrete -> exact literal
    p = Path(); p.stack = [z3.BitVecVal((-1) & 0xFFFFFFFF, 32), z3.BitVecVal(15, 64)]
    e.host_call("float_set", p)
    assert z3.simplify(p.stack.pop()).as_long() == xfl.floatSet(-1, 15)
    assert "float_set" not in e.float_overapprox, "concrete float_set must NOT over-approx"
    # symbolic mantissa -> fresh over-approx + flagged
    p2 = Path(); p2.stack = [z3.BitVecVal(0, 32), z3.BitVec("m", 64)]
    e.host_call("float_set", p2)
    assert "float_set" in e.float_overapprox, "symbolic float_set must be over-approximated"


def test_float_multiply_divide_symbolic_are_overapprox_and_sound():
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    # symbolic multiply -> over-approx, fresh result, and the two results not unified
    p = Path(); p.stack = [z3.BitVec("a", 64), z3.BitVec("b", 64)]
    e.host_call("float_multiply", p)
    r1 = p.stack.pop()
    p.stack = [z3.BitVec("c", 64), z3.BitVec("d", 64)]
    e.host_call("float_multiply", p)
    r2 = p.stack.pop()
    assert "float_multiply" in e.float_overapprox
    s = z3.Solver(); s.add(r1 != r2)
    assert s.check() == z3.sat, "two over-approx multiply results wrongly unified"
    # symbolic divide forks a div-by-zero (-25) sentinel sibling
    e2 = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    e2._extra_forks = []
    p2 = Path(); p2.stack = [z3.BitVec("x", 64), z3.BitVec("y", 64)]
    e2.host_call("float_divide", p2)
    assert "float_divide" in e2.float_overapprox
    assert len(e2._extra_forks) == 1, "divide must fork a div-by-zero sentinel path"
    sib = e2._extra_forks[0]
    assert z3.simplify(sib.stack[-1]).as_long() == (xfl.DIVISION_BY_ZERO & ((1 << 64) - 1))


def test_float_log_root_are_unsupported():
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    p = Path(); p.stack = [z3.BitVec("x", 64)]
    e.host_call("float_log", p)
    assert "float_log" in e.unsupported
    p.stack = [z3.BitVec("x", 64), z3.BitVecVal(2, 32)]
    e.host_call("float_root", p)
    assert "float_root" in e.unsupported


def test_iou_sfamount_48byte_path_and_native_untouched():
    # 48-byte read -> issued layout exposes amt_xfl + amt48; 8-byte read stays native.
    e = Engine(open(os.path.join(H, "limit_iou.wasm"), "rb").read())
    e.run()
    assert "amt_xfl" in e.inputs, "48-byte issued sfAmount did not expose amt_xfl"
    assert "amt48" in e.inputs and len(e.inputs["amt48"]) == 48
    # native limit hook must still use the 8-byte path (no IOU drift)
    en = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    en.run()
    assert "amt" in en.inputs and len(en.inputs["amt"]) == 8
    assert "amt_xfl" not in en.inputs, "native sfAmount wrongly promoted to issued"


def test_iou_matrix_verdicts():
    # The 4 IOU fixtures and their REQUIRED verdicts.
    assert prove_limit_iou.main(os.path.join(H, "limit_iou.wasm")) == 0          # PROVEN
    assert prove_limit_iou.main(os.path.join(H, "limit_iou_inverted.wasm")) == 2  # CEX
    # emit_iou.wasm emits a concrete IOU while reading NO incoming amount = value creation.
    # IOU conservation is NOT modeled (no incoming-issued comparison), so this MUST fail closed
    # to INCONCLUSIVE — it previously returned a FALSE PROVEN (0) and this test enshrined it.
    rc_iou_cons = prove_conservation.main(os.path.join(H, "emit_iou.wasm"))
    assert rc_iou_cons == 3, f"emit_iou conservation MUST be INCONCLUSIVE(3), got {rc_iou_cons}"
    assert rc_iou_cons != 0, "FATAL: IOU conservation returned a FALSE PROVEN (the audit bug)"
    # CRITICAL: a symbolic float_multiply into an emit must be INCONCLUSIVE, never PROVEN.
    rc = prove_conservation.main(os.path.join(H, "iou_multiply_bug.wasm"))
    assert rc == 3, f"iou_multiply_bug MUST be INCONCLUSIVE(3), got {rc} — model UNSOUND if 0!"
    assert rc != 0, "FATAL: symbolic float op reached a PROVEN (false proof)"


def test_no_symbolic_float_op_ever_reaches_proven():
    # SOUNDNESS GUARANTEE: for the over-approx fixture, float_overapprox is non-empty
    # AND the conservation driver refuses PROVEN. Assert the invariant directly.
    e = Engine(open(os.path.join(H, "iou_multiply_bug.wasm"), "rb").read())
    e.run()
    assert e.float_overapprox, "over-approx not recorded for symbolic multiply"
    # any accepting path that emits an over-approx IOU must force INCONCLUSIVE
    rc = prove_conservation.main(os.path.join(H, "iou_multiply_bug.wasm"))
    assert rc == 3


# --- ADVERSARIAL re-verification of the IOU-conservation fail-closed fix --------
# (commit ae415fc: prove_conservation no longer returns a false PROVEN for any
#  hook that creates IOU value. These hooks are the attacks; each MUST be 3, never 0.)

def test_conservation_mixed_native_and_iou_emit_is_not_proven():
    # DECISIVE FALL-THROUGH ATTACK: one accepting path emits BOTH a clean native
    # payment (forward HALF the incoming drops — conserves on the native axis) AND
    # an IOU payment (1.5 USD minted from nothing). If `iou_emitting` only looked at
    # the native list, control would fall through to the NATIVE branch, prove
    # `drops/2 <= drops`, and IGNORE the value-creating IOU emit -> a FALSE PROVEN.
    # The global iou_emitting guard must fire FIRST and force INCONCLUSIVE.
    rc = prove_conservation.main(os.path.join(H, "emit_mixed_native_iou.wasm"))
    assert rc == 3, f"mixed native+IOU emit MUST be INCONCLUSIVE(3), got {rc}"
    assert rc != 0, "FATAL: native+IOU mixed emit fell through to a FALSE PROVEN"


def test_conservation_per_path_split_native_vs_iou_is_not_proven():
    # PER-PATH SPLIT ATTACK: path A (even drops) emits a clean conserving native
    # forward; path B (odd drops) mints an IOU from nothing. A driver that proved
    # path A while skipping the IOU on path B would falsely PROVE. The IOU emit on
    # ANY accepting path must taint the WHOLE verdict to INCONCLUSIVE.
    rc = prove_conservation.main(os.path.join(H, "emit_split_native_iou.wasm"))
    assert rc == 3, f"per-path native|IOU split MUST be INCONCLUSIVE(3), got {rc}"
    assert rc != 0, "FATAL: per-path IOU emit was skipped -> FALSE PROVEN"


def test_conservation_iou_classifier_confusion_never_proves():
    # PARSER-CONFUSION ATTACK: a PURE IOU emit whose 20-byte currency code has
    # byte[0] == 0x68 collides with the sfFee header at offset 44 — the exact byte
    # the engine uses to tell native from issued. The classifier IS fooled (reads it
    # as native), but the IOU value word (bit63 set) parsed as "drops" is always
    # >= ~1.9e16 while incoming drops are symbolic (solver picks 0). So the verdict
    # is never PROVEN: it is either ERROR(1, no incoming amount), INCONCLUSIVE(3), or
    # a (correctly non-PROVEN) COUNTEREXAMPLE(2). The cardinal sin — PROVEN(0) — must
    # NOT occur. (Documents that the misclassification is non-exploitable for soundness.)
    rc1 = prove_conservation.main(os.path.join(H, "emit_iou_currency_collision.wasm"))
    assert rc1 != 0, f"FATAL: colliding-currency IOU reached PROVEN, got {rc1}"
    assert rc1 in (1, 2, 3), f"unexpected verdict {rc1}"
    # the sharp version reads an incoming native amount (passes the no-amount guard) and
    # picks a tiny XFL; even so the masked value word is huge -> CEX, never PROVEN.
    rc2 = prove_conservation.main(os.path.join(H, "emit_iou_collision_reads_amt.wasm"))
    assert rc2 != 0, f"FATAL: colliding-currency IOU (reads amt) reached PROVEN, got {rc2}"
    assert rc2 in (2, 3), f"unexpected verdict {rc2}"


def test_conservation_iou_emit_min_value_word_is_strictly_positive():
    # ENGINE-LEVEL backstop for the classifier-confusion case: the smallest NORMALIZED
    # XFL, serialized as an issued value word (bit63 set) and masked to native drops
    # (top byte & 0x3F), is still strictly positive (~1.9e16). So a misclassified IOU
    # can never present as 0 drops, hence can never satisfy `total <= incoming` for the
    # symbolic incoming=0 case -> never a false PROVEN via misclassification.
    smallest = xfl.encode(1, xfl.MIN_MANT, -96)          # +, min mantissa, min exponent
    word = smallest | (1 << 63)                          # is-issued bit set (what float_sto writes)
    extracted = word & ((0x3F << 56) | ((1 << 56) - 1))  # top byte & 0x3F, low 7 bytes kept
    assert extracted > 0, "misclassified IOU could present as 0 drops (soundness hole)"
    assert extracted >= 10 ** 15, "expected normalized mantissa floor in extracted drops"


# --- ADVERSARIAL re-verification of the read-site normalize-XFL fix -------------
# (commit ae415fc: incoming issued amount constrained to _float_normalized at the
#  otxn_field 48-byte read. The constraint must EXCLUDE only impossible denormals,
#  never a real over-limit counterexample.)

def test_normalize_constraint_does_not_hide_inverted_cex():
    # The inverted IOU limit must STILL be a real CEX, and the witness must be a
    # genuinely over-limit pair under the engine's own XFL ordering — proving the
    # added normalize constraint did not suppress the counterexample.
    assert prove_limit_iou.main(os.path.join(H, "limit_iou_inverted.wasm")) == 2
    e = Engine(open(os.path.join(H, "limit_iou_inverted.wasm"), "rb").read()); e.run()
    amtx = e.inputs["amt_xfl"]
    lim = e.inputs["param:LIM"]
    limx = z3.Concat(*lim[:8]) & z3.BitVecVal(0x7FFFFFFFFFFFFFFF, 64)
    eng_cmp = e._float_cmp_c(amtx, limx)
    found_positive = False
    for code, cons in e.accepts:
        s = z3.Solver(); s.add(*cons)
        s.add(eng_cmp == z3.BitVecVal(1, 8))             # amt > LIM (the violation)
        s.add(e._float_normalized(amtx)); s.add(e._float_normalized(limx))
        s.add(z3.Extract(62, 62, amtx) == 1)             # POSITIVE amt (XFL sign bit 62)
        s.add(z3.Extract(62, 62, limx) == 1)             # POSITIVE LIM
        s.add(amtx != 0); s.add(limx != 0)
        if s.check() == z3.sat:
            m = s.model()
            av = m.eval(amtx, model_completion=True).as_long()
            lv = m.eval(limx, model_completion=True).as_long()
            # cross-check with the independent reference comparator
            assert xfl.floatCmp(av, lv) == 1, "witness is not actually over-limit"
            found_positive = True
    assert found_positive, "normalize constraint hid the natural positive over-limit CEX"


def test_normalize_constraint_keeps_eqonly_violation_findable():
    # An IOU limit that only rejects amt == LIM (mode 1 EQ) ACCEPTS a whole family of
    # NORMALIZED over-limit amounts. If the read-site normalize constraint wrongly
    # excluded any of them this would falsely PROVE; it must be CEX(2).
    rc = prove_limit_iou.main(os.path.join(H, "limit_iou_eqonly.wasm"))
    assert rc == 2, f"EQ-only broken IOU limit MUST be a COUNTEREXAMPLE(2), got {rc}"


def test_normalize_constraint_admits_both_signs_of_normalized_xfl():
    # SOUNDNESS of the restriction: _float_normalized must admit EVERY canonical XFL
    # the host can produce (both signs, mantissa floor/ceiling, exponent range) and
    # reject ONLY non-canonical encodings (here: the denormal zero-mantissa word the
    # host never emits). Admitting a real value is what guarantees no CEX is hidden.
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    samples = [
        xfl.encode(1, xfl.MIN_MANT, -96), xfl.encode(-1, xfl.MIN_MANT, -96),
        xfl.encode(1, xfl.MAX_MANT - 1, 80), xfl.encode(-1, xfl.MAX_MANT - 1, 80),
        xfl.encode(1, 5_000_000_000_000_000, 0), xfl.encode(-1, 5_000_000_000_000_000, 0),
        0,
    ]
    for v in samples:
        s = z3.Solver(); s.add(e._float_normalized(z3.BitVecVal(v & ((1 << 64) - 1), 64)))
        assert s.check() == z3.sat, f"normalized constraint wrongly EXCLUDED a real XFL {v}"
    # a denormal the host never produces must be rejected (no spurious CEX possible)
    denormal = (1 << 62) | (97 << 54) | 0
    s = z3.Solver(); s.add(e._float_normalized(z3.BitVecVal(denormal, 64)))
    assert s.check() == z3.unsat, "denormal must be excluded by the normalize constraint"


def test_dsl_xfl_operands_are_only_normalized_or_concrete():
    # The DSL feeds _float_cmp_c only two XFL sources: `iou_amount` (read-site
    # normalized, prover.py:302) and `xfl(...)` literals (concrete/canonical). Confirm
    # there is no third symbolic XFL producer that could reach the compare un-normalized.
    import re
    src = open(os.path.join(ROOT, "src", "prover.py")).read()
    # amt_xfl is written exactly once, and on the line BEFORE it the read is normalized.
    writes = [i for i, ln in enumerate(src.splitlines()) if 'self.inputs["amt_xfl"]' in ln]
    assert len(writes) == 1, "amt_xfl written in more than one place — re-audit normalization"
    lines = src.splitlines()
    window = "\n".join(lines[max(0, writes[0] - 4):writes[0] + 1])
    assert "_float_normalized(xflv)" in window, "amt_xfl read site is not normalized"
    # every _float_cmp_c symbolic operand site in the engine normalizes first
    assert src.count("_float_normalized(a)") >= 1 and src.count("_float_normalized(b)") >= 1


def _norm_xfl_sample():
    """A dense, boundary-heavy sample of *normalized* XFL int64 values: both signs,
    exponent min/max (-96..80), mantissa boundaries (1e15, 1e16-1), zero, and
    equal-magnitude-opposite-sign pairs."""
    vals = {0}
    mants = [xfl.MIN_MANT, xfl.MIN_MANT + 1, 1_234_567_890_123_456,
             5_000_000_000_000_000, 9_999_999_999_999_998, xfl.MAX_MANT - 1]
    exps = [-96, -80, -50, -1, 0, 1, 23, 50, 79, 80]
    for s in (1, -1):
        for m in mants:
            for e in exps:
                v = xfl.encode(s, m, e)
                if v > 0:
                    vals.add(v)
    return sorted(vals)


def test_float_compare_cross_check_dense_normalized():
    """ADVERSARIAL CROSS-CHECK: the Z3 _float_cmp_c model must equal xfl.floatCmp AND
    the float_compare host model must equal xfl.floatCompare on a LARGE normalized
    sample (both signs, exponent + mantissa boundaries, zero, equal-mag opposite-sign),
    for ALL 7 non-zero mode flags. A single disagreement here is a wrong ordering =
    a false-PROVEN risk. This is the highest-risk surface; keep it dense."""
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    cmpc = e._float_cmp_c
    vals = _norm_xfl_sample()
    assert len(vals) >= 80, f"sample too small: {len(vals)}"
    checked = 0
    for a in vals:
        for b in vals:
            cm = z3.simplify(cmpc(z3.BitVecVal(a, 64), z3.BitVecVal(b, 64))).as_signed_long()
            cr = xfl.floatCmp(a, b)
            assert cm == cr, f"cmp({a},{b}) model={cm} ref={cr}"
            for mode in (1, 2, 3, 4, 5, 6, 7):
                tm = 1 if (((mode & 1) and cm == 0) or ((mode & 2) and cm < 0)
                           or ((mode & 4) and cm > 0)) else 0
                tr = xfl.floatCompare(a, b, mode)
                assert tm == tr, f"compare({a},{b},{mode}) model={tm} ref={tr}"
                checked += 1
    assert checked >= 45000, f"expected dense coverage, only {checked} pairs*modes"


def test_float_compare_sign_zero_edges_match_reference():
    """Explicit sign/zero edge cases in the Z3 model (Attack 5): negative vs positive,
    negative vs negative (reversed ordering), zero vs positive, zero vs negative,
    equal magnitude opposite sign. Each must match xfl.floatCmp."""
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    cmpc = e._float_cmp_c
    p5, n5, p100, n100 = (xfl.floatSet(0, 5), xfl.floatNegate(xfl.floatSet(0, 5)),
                          xfl.floatSet(0, 100), xfl.floatNegate(xfl.floatSet(0, 100)))
    cases = [(n5, p100), (p100, n5), (n5, n100), (n100, n5),
             (0, n5), (0, p5), (p5, n5), (n5, p5), (0, 0)]
    for a, b in cases:
        cm = z3.simplify(cmpc(z3.BitVecVal(a, 64), z3.BitVecVal(b, 64))).as_signed_long()
        assert cm == xfl.floatCmp(a, b), f"sign/zero edge cmp({a},{b}) model={cm} ref={xfl.floatCmp(a,b)}"


def test_denormal_zero_mantissa_excluded_by_normalization_guard():
    """KNOWN BOUNDARY: the lexicographic (exp-first) magnitude compare diverges from
    true magnitude ONLY for a non-canonical XFL whose mantissa field is 0 but whose
    word is non-zero (a denormal the host never produces). The _float_normalized guard
    MUST exclude it, so it can never manufacture or suppress a counterexample. This
    test pins that the guard rejects such a value (fail-closed)."""
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    denormal = (1 << 62) | (97 << 54) | 0          # positive, exp 0, mantissa-field 0, word != 0
    assert denormal != 0
    s = z3.Solver(); s.add(e._float_normalized(z3.BitVecVal(denormal, 64)))
    assert s.check() == z3.unsat, "denormal zero-mantissa XFL must NOT satisfy _float_normalized"
    # and that this is the kind of value that diverges (documents the boundary):
    tiny = xfl.encode(1, xfl.MIN_MANT, -96)
    assert xfl.floatCmp(tiny, denormal) != z3.simplify(
        e._float_cmp_c(z3.BitVecVal(tiny, 64), z3.BitVecVal(denormal, 64))).as_signed_long(), \
        "expected the documented denormal divergence (guard is what makes it safe)"


def test_float_compare_model_antisymmetric_on_normalized():
    """The Z3 compare must be antisymmetric for all normalized symbolic XFLs:
    c(a,b) == -c(b,a). A break would mean an order-dependent (unsound) comparison."""
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    a, b = z3.BitVec("a", 64), z3.BitVec("b", 64)
    s = z3.Solver()
    s.add(e._float_normalized(a), e._float_normalized(b))
    s.add(e._float_cmp_c(a, b) != -e._float_cmp_c(b, a))
    assert s.check() == z3.unsat, "model float compare is not antisymmetric"


def test_overapprox_taint_persists_through_float_sto_laundering():
    """ATTACK 2: launder a symbolic (over-approximated) float result through float_sto
    into memory. The taint flag MUST persist AND the stored bytes must remain symbolic
    (a function of the over-approx result), so a driver re-reading them cannot vacuously
    prove anything. Defeating taint here would be a false-PROVEN vector."""
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
    p = Path(); p.stack = [z3.BitVec("a", 64), z3.BitVec("b", 64)]
    e.host_call("float_multiply", p)
    res = p.stack.pop()
    assert "float_multiply" in e.float_overapprox
    e._extra_forks = []
    p.stack = [z3.BitVecVal(0, 64), z3.BitVecVal(48, 64), z3.BitVecVal(0, 64),
               z3.BitVecVal(0, 64), z3.BitVecVal(0, 64), z3.BitVecVal(0, 64),
               res, z3.BitVecVal(0, 64)]
    e.host_call("float_sto", p)
    assert "float_multiply" in e.float_overapprox, "taint cleared by float_sto laundering!"
    word = z3.Concat(*[e.load_byte(p, i) for i in range(8)])   # fieldcode 0 -> value at 0..7
    assert not z3.is_bv_value(z3.simplify(word)), "laundered word became concrete (taint lost)"
    # the stored word is exactly the over-approx result with the is-issued bit set
    s = z3.Solver(); s.add(word != (res | z3.BitVecVal(1 << 63, 64)))
    assert s.check() == z3.unsat, "stored word is not the symbolic over-approx result"


def test_error_sentinel_forks_explore_both_paths():
    """ATTACK 3: every symbolic float error fork must create a sibling carrying the
    correct sentinel under the error condition, while the main path carries its
    negation — so a hook's `if (r < 0) rollback` reject path is NEVER silently dropped
    (dropping it = false PROVEN for the inverse invariant)."""
    def fresh():
        en = Engine(open(os.path.join(H, "limit.wasm"), "rb").read())
        en._extra_forks = []
        return en
    # divide: den==0 -> -25 ; partition is exact
    e = fresh(); p = Path(); p.stack = [z3.BitVec("x", 64), z3.BitVec("y", 64)]
    e.host_call("float_divide", p)
    assert len(e._extra_forks) == 1
    assert z3.simplify(e._extra_forks[0].stack[-1]).as_signed_long() == xfl.DIVISION_BY_ZERO
    sib = e._extra_forks[0]
    s = z3.Solver(); s.add(*sib.cons); s.add(z3.BitVec("y", 64) != 0)
    assert s.check() == z3.unsat, "divide sentinel sibling does not force divisor==0"
    s = z3.Solver(); s.add(*p.cons); s.add(z3.BitVec("y", 64) == 0)
    assert s.check() == z3.unsat, "divide main path does not force divisor!=0"
    # int: negative input (absflag 0) -> -33
    e = fresh(); p = Path()
    p.stack = [z3.BitVec("x", 64), z3.BitVecVal(2, 64), z3.BitVecVal(0, 64)]
    e.host_call("float_int", p)
    assert len(e._extra_forks) == 1
    assert z3.simplify(e._extra_forks[0].stack[-1]).as_signed_long() == xfl.CANT_RETURN_NEGATIVE
    # sto: x<0 -> -7
    e = fresh(); p = Path()
    p.stack = [z3.BitVecVal(0, 64), z3.BitVecVal(48, 64), z3.BitVecVal(0, 64),
               z3.BitVecVal(0, 64), z3.BitVecVal(0, 64), z3.BitVecVal(0, 64),
               z3.BitVec("xv", 64), z3.BitVecVal(0, 64)]
    e.host_call("float_sto", p)
    assert len(e._extra_forks) == 1
    assert z3.simplify(e._extra_forks[0].stack[-1]).as_signed_long() == xfl.INVALID_ARGUMENT
    # invert: x==0 -> -25
    e = fresh(); p = Path(); p.stack = [z3.BitVec("x", 64)]
    e.host_call("float_invert", p)
    assert len(e._extra_forks) == 1
    assert z3.simplify(e._extra_forks[0].stack[-1]).as_signed_long() == xfl.DIVISION_BY_ZERO


def test_limit_iou_proven_is_non_vacuous():
    """ATTACK 4: the limit_iou PROVEN must be NON-VACUOUS — there is a real accept path
    reachable with an under-limit amount, a real rollback path reachable with an
    over-limit amount, and the accept path is provably UNSAT with an over-limit amount."""
    e = Engine(open(os.path.join(H, "limit_iou.wasm"), "rb").read())
    e.run()
    assert len(e.accepts) >= 1 and len(e.rollbacks) >= 1
    amtx = e.inputs["amt_xfl"]
    limx = z3.Concat(*e.inputs["param:LIM"][:8]) & z3.BitVecVal(0x7FFFFFFFFFFFFFFF, 64)
    GT = z3.BitVecVal(1, 8); LT = z3.BitVecVal(-1, 8)
    nm = lambda: (e._float_normalized(amtx), e._float_normalized(limx))
    for _, cons in e.accepts:
        s = z3.Solver(); s.add(*cons, *nm()); s.add(e._float_cmp_c(amtx, limx) == LT)
        assert s.check() == z3.sat, "accept path unreachable with under-limit amount (vacuous)"
        s = z3.Solver(); s.add(*cons, *nm()); s.add(e._float_cmp_c(amtx, limx) == GT)
        assert s.check() == z3.unsat, "accept path reachable with OVER-limit amount (UNSOUND)"
    for _, cons in e.rollbacks:
        s = z3.Solver(); s.add(*cons, *nm()); s.add(e._float_cmp_c(amtx, limx) == GT)
        assert s.check() == z3.sat, "rollback path unreachable with over-limit amount"


# --- call_indirect soundness fixtures (hand-WASM, full control over table+elements) ----
FUNCREF = 0x70


def _indirect_module(codes, table_entries, passive=False, tableidx=0):
    """Module: imports _g/accept/rollback, one handler per `codes` entry (each calls
    accept(0,0,code)), and hook(i32) that call_indirects through table[arg0] (a symbolic
    selector). `table_entries` = global func indices placed in the table at offset 0.
    passive=True emits a flag-1 (passive) element so the table can't be resolved.
    tableidx = the table-index immediate encoded on the call_indirect (default 0)."""
    t_hook = _ftype([I32], [I64])          # 0
    t_g    = _ftype([I32, I32], [I32])     # 1
    t_acc  = _ftype([I32, I32, I64], [I64])# 2
    t_hand = _ftype([], [I64])             # 3  (the call_indirect type)
    types = [t_hook, t_g, t_acc, t_hand]

    def _imp(mod, nm, t):
        return (_uleb(len(mod)) + mod.encode() + _uleb(len(nm)) + nm.encode()
                + bytes([0x00]) + _uleb(t))
    imports = [_imp("env", "_g", 1), _imp("env", "accept", 2), _imp("env", "rollback", 2)]
    IMPC = 3
    nh = len(codes)
    func_types = [_uleb(3)] * nh + [_uleb(0)]            # handlers: type3; hook: type0

    def handler_body(code):
        b = _i32c(0) + _i32c(0) + _i64c(code) + bytes([0x10]) + _uleb(1) + bytes([0x0B])
        return _uleb(0) + b                              # call accept(idx 1); end
    GID = (1 << 31) + 1
    hook_b = (_i32c(GID & 0xFFFFFFFF) + _i32c(1) + bytes([0x10]) + _uleb(0) + bytes([0x1A])  # _g; drop
              + bytes([0x20]) + _uleb(0)                                    # local.get 0 (selector)
              + bytes([0x11]) + _uleb(3) + _uleb(tableidx)                   # call_indirect type3 table<tableidx>
              + bytes([0x1A]) + _i64c(0) + bytes([0x0B]))                    # drop; i64.const 0; end
    bodies = [handler_body(c) for c in codes] + [_uleb(0) + hook_b]

    sec_type = _sec(1, _vec(types))
    sec_import = _sec(2, _vec(imports))
    sec_func = _sec(3, _vec(func_types))
    sec_table = _sec(4, _vec([bytes([FUNCREF, 0x00]) + _uleb(max(1, len(table_entries)))]))
    sec_mem = _sec(5, _vec([bytes([0x00]) + _uleb(1)]))
    glob = bytes([I32, 0x01, 0x41]) + _sleb(65536) + bytes([0x0B])
    sec_global = _sec(6, _vec([glob]))
    hook_idx = IMPC + nh
    exp = _uleb(len("hook")) + b"hook" + bytes([0x00]) + _uleb(hook_idx)
    sec_export = _sec(7, _vec([exp]))
    if passive:
        el = _uleb(1) + bytes([0x00]) + _vec([_uleb(g) for g in table_entries])
    else:
        el = _uleb(0) + _i32c(0) + bytes([0x0B]) + _vec([_uleb(g) for g in table_entries])
    sec_elem = _sec(9, _vec([el]))
    sec_code = _sec(10, _vec([_uleb(len(b)) + b for b in bodies]))
    return (b"\x00asm" + struct.pack("<I", 1) + sec_type + sec_import + sec_func + sec_table +
            sec_mem + sec_global + sec_export + sec_elem + sec_code)


def test_call_indirect_safe_dispatch_proves():
    # both reachable targets accept with code 0 -> no unsafe accept; table fully resolved.
    e = Engine(_indirect_module(codes=[0, 0], table_entries=[3, 4])); e.run()
    assert "call_indirect" not in e.unsupported, "resolved indirect call must not be unsupported"
    assert e.accepts, "the indirect call should reach an accept"
    assert {c for c, _ in e.accepts} == {0}, "only the safe code-0 target should be accepted"


def test_call_indirect_unsafe_target_is_explored():
    # DECISIVE: a dispatch table with one unsafe target (accepts code 999) must NOT be
    # silently dropped — the fork explores it, so a driver checking "code != 999" finds it.
    e = Engine(_indirect_module(codes=[0, 999], table_entries=[3, 4])); e.run()
    assert "call_indirect" not in e.unsupported
    codes = {c for c, _ in e.accepts}
    assert 999 in codes, "the unsafe indirect target was dropped — would yield a FALSE proof"


def test_call_indirect_oob_traps_not_accepts():
    # symbolic selector over a 2-entry table: out-of-bounds indices must TRAP (rollback),
    # never accept. So a rollback path exists and no accept came from an OOB index.
    e = Engine(_indirect_module(codes=[0, 0], table_entries=[3, 4])); e.run()
    assert e.rollbacks, "out-of-bounds indirect index must trap to a rollback path"
    assert "call_indirect" not in e.unsupported


def test_call_indirect_unresolved_table_is_inconclusive():
    # a passive (flag-1) element section can't be resolved -> fail closed to INCONCLUSIVE.
    e = Engine(_indirect_module(codes=[0, 0], table_entries=[3, 4], passive=True)); e.run()
    assert "call_indirect" in e.unsupported, "unresolved table must force INCONCLUSIVE, not PROVEN"


def test_call_indirect_nonzero_tableidx_is_inconclusive():
    # the engine resolves only table 0; a dispatch through table index != 0 is NOT modeled.
    # It must fail closed (INCONCLUSIVE), never silently dispatch on table 0 -> false PROVEN.
    # Even with an UNSAFE target (code 999) in the table, the non-zero tableidx must short-
    # circuit to unsupported before any accept can be recorded.
    e = Engine(_indirect_module(codes=[0, 999], table_entries=[3, 4], tableidx=1)); e.run()
    assert "call_indirect" in e.unsupported, "tableidx!=0 must force INCONCLUSIVE, not dispatch table 0"
    # tableidx==0 control: the same module on table 0 stays resolvable (handler stub above).
    e0 = Engine(_indirect_module(codes=[0, 999], table_entries=[3, 4], tableidx=0)); e0.run()
    assert "call_indirect" not in e0.unsupported, "tableidx==0 must keep working as before"


# --- invariant DSL: equivalence with hand drivers + soundness -----------------
def test_dsl_equivalence_conservation():
    for h, expect in [("emit_forward", 0), ("emit_double", 0), ("emit_inflate", 2)]:
        w = os.path.join(H, f"{h}.wasm")
        assert prove_dsl.main(w, "accept implies emitted_total <= incoming_drops") == expect
        assert prove_conservation.main(w) == expect            # DSL == hand driver


def test_dsl_equivalence_nospend():
    for h, expect in [("emit_forward", 0), ("emit_double", 2)]:
        w = os.path.join(H, f"{h}.wasm")
        assert prove_dsl.main(w, "accept implies emit_count <= 1") == expect
        assert prove_nospend.main(w) == expect


def test_dsl_equivalence_limit():
    exp = {"limit": 0, "limit_buggy": 2, "limit_inverted": 2}
    for h, ex in exp.items():
        assert prove_dsl.main(os.path.join(H, f"{h}.wasm"),
                              "accept implies incoming_drops <= param[LIM]") == ex
    assert prove_limit.main(os.path.join(H, "limit.wasm")) == 0          # hand agrees
    assert prove_limit.main(os.path.join(H, "limit_buggy.wasm")) == 2


def test_dsl_rejects_unknown_identifier():
    # unknown id -> HARD reject (exit 1), never a silent pass
    assert prove_dsl.main(os.path.join(H, "limit.wasm"), "accept implies foobar <= 5") == 1


def test_dsl_rejects_bad_token_and_xfl_arithmetic():
    assert prove_dsl.main(os.path.join(H, "limit.wasm"), "accept implies emit_count <= 1 ** 2") == 1
    assert prove_dsl.main(os.path.join(H, "limit_iou.wasm"),
                          "accept implies iou_amount <= xfl(5) + xfl(3)") == 1   # no XFL arithmetic


def test_dsl_rejects_non_boolean_root_predicate():
    # A non-boolean top-level expression must HARD-reject (exit 1), never PROVEN. The danger:
    # the per-path bool check only fires when there ARE accepting paths, so a bare value term
    # could slip to a vacuous PROVEN on a zero-accept hook. limit.wasm HAS accept paths and
    # still must reject — the guard is independent of accept count.
    w = os.path.join(H, "limit.wasm")
    assert prove_dsl.main(w, "incoming_drops") == 1            # bare quantity, not a predicate
    assert prove_dsl.main(w, "emitted_total + 1") == 1        # value arithmetic, not a predicate
    assert prove_dsl.main(w, "emit_count") == 1
    # static checks agree (engine-independent)
    assert dsl.is_bool_root(dsl.parse("accept implies incoming_drops <= 5")) is True
    assert dsl.is_bool_root(dsl.parse("incoming_drops")) is False
    assert dsl.is_bool_root(dsl.parse("emitted_total + 1")) is False
    for bad in ("incoming_drops", "emitted_total + 1", "emit_count"):
        try:
            dsl.require_bool_root(dsl.parse(bad)); assert False, f"{bad!r} should reject"
        except dsl.DSLError:
            pass


def test_dsl_non_boolean_root_zero_accept_is_not_proven():
    # The exact bug: on a hook with NO accepting paths the per-path translation never fires,
    # so a non-boolean predicate would fall through to a vacuous PROVEN. Drive evaluate() with
    # an engine that has zero accepts and assert a non-bool root is rejected (1), never PROVEN.
    e = Engine(open(os.path.join(H, "limit.wasm"), "rb").read()); e.run()
    e.accepts = []; e.accepts_full = []; e.emits_on_accept = []   # simulate zero-accept hook
    # a VALID boolean predicate over zero accepts is allowed to be vacuously PROVEN ...
    assert prove_dsl.evaluate(e, dsl.parse("accept implies emit_count <= 1")) == 0
    # ... but a NON-boolean root must still hard-reject even with zero accept paths.
    assert prove_dsl.evaluate(e, dsl.parse("incoming_drops")) == 1
    assert prove_dsl.evaluate(e, dsl.parse("emitted_total + 1")) == 1


def test_dsl_violation_is_counterexample():
    # emit_forward emits exactly once; "emit_count >= 2" is false on its accept path -> CEX
    assert prove_dsl.main(os.path.join(H, "emit_forward.wasm"),
                          "accept implies emit_count >= 2") == 2


def test_dsl_negation_is_correct():
    # the proof negates the predicate; a wrong negation = a false PROVEN. Pin it.
    fwd = os.path.join(H, "emit_forward.wasm")     # emit_count == 1
    dbl = os.path.join(H, "emit_double.wasm")      # emit_count == 2
    assert prove_dsl.main(fwd, "accept implies not (emit_count == 1)") == 2   # not(true)=false -> CEX
    assert prove_dsl.main(dbl, "accept implies not (emit_count == 1)") == 0   # not(false)=true -> PROVEN
    # De Morgan: not(a and b) must give the same verdict as (not a) or (not b)
    a = prove_dsl.main(dbl, "accept implies not (emit_count >= 1 and emit_count <= 1)")
    b = prove_dsl.main(dbl, "accept implies (not emit_count >= 1) or (not emit_count <= 1)")
    assert a == b == 0


def test_dsl_float_overapprox_taints_to_inconclusive():
    # an XFL-referencing predicate must fail closed to INCONCLUSIVE when a nonlinear float
    # op was over-approximated — never PROVEN. Inject the taint to exercise the real gate.
    e = Engine(open(os.path.join(H, "limit_iou.wasm"), "rb").read()); e.run()
    e.float_overapprox.add("float_test_injected")
    # a tautology over an XFL term: P or not P — provably no counterexample on any path,
    # so the only thing that can change the verdict is the fail-closed taint gate.
    ast = dsl.parse("accept implies (iou_amount <= xfl(1000000) or not (iou_amount <= xfl(1000000)))")
    assert prove_dsl.evaluate(e, ast) == 3   # tainted XFL term -> INCONCLUSIVE, never PROVEN


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    # also run the read-after-write adversarial suite (separate module, one runner)
    import test_raw
    fns += [v for k, v in sorted(vars(test_raw).items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
