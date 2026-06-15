"""Prove NO INSECURE NONCE DEPENDENCE — OWASP SC03 (bad randomness) + SC09 (timing/insecure).

  for all inputs:  an ACCEPT decision must not hinge on ledger_nonce
                   (the nonce is grindable/predictable, NOT secure randomness)

WHAT THIS PROVES (read carefully — do NOT overclaim):
  This driver proves that NO accepting path's reachability DEPENDS on the value of
  `ledger_nonce`. It does NOT prove "the hook is free of all time dependence": gating on
  `ledger_seq` / `ledger_last_time` (e.g. an escrow-style deadline `seq >= DEADLINE`) is a
  LEGITIMATE pattern and is intentionally NOT flagged. The dangerous class this targets is a
  security decision seeded from the ledger nonce (a lottery/raffle/"random winner" gated on
  nonce bytes), which a submitter can predict or grind to win at will.

Hoare triple (the property, stated as independence):
  { N = ledger_nonce, all other inputs fixed }
  hook(...)
  { accept-reachability(inputs) is INVARIANT under changing N }
Proof obligation (negated, per accepting path P with constraints C):
  is there an input I and two nonce values N1 != N2 such that C[N:=N1] holds but
  C[N:=N2] does NOT?  If yes, P's accept genuinely depends on the nonce -> COUNTEREXAMPLE.

Engine modeling: `ledger_nonce` host reads return FRESH SYMBOLIC bytes, every one registered
in `e.nonce_syms`. The dependence test substitutes those symbols with a primed copy (all
NON-nonce symbols shared) and asks Z3 whether the path constraint can hold under the original
nonce yet fail under the primed nonce — a sound, exact dependence query (no heuristics).

KNOWN ENGINE LIMITATION — nonce-through-state laundering (fail-closed here):
  The shared engine's `state` host fn returns a FRESH `state_old:<key>` symbol and does NOT
  connect a same-invocation `state_set` write (which lands in `p.writes`) to a later `state`
  read of the same key. That modeling is sound-by-design for prove_monotonic's worst case, so
  we do NOT change it. But it means a hook can LAUNDER the nonce out of the dependence query:
      read ledger_nonce -> state_set(KEY, nonce) -> state(KEY) read-back -> gate accept on it
  Here the accept constraint references `state_old:KEY` (fresh, nonce-free), NOT any nonce
  symbol, so the substitution query sees no nonce -> UNSAT -> a FALSE PROVEN. To stay sound,
  this driver detects the laundering precondition directly: on ANY accepting path, if a value
  that depends on a nonce symbol flows into a `state_set` write (recorded in `e.accepts_full`'s
  per-path writes dict), the nonce-dependence query is INCOMPLETE for that path and we return
  INCONCLUSIVE(3) — NEVER PROVEN. (Over-conservative is acceptable; a missed laundering is not.)

Soundness / fail-closed: solver `unknown` (on the dependence query OR a feasibility check)
=> INCONCLUSIVE; unsupported opcode / hit unroll bound => INCONCLUSIVE; a nonce-derived value
written to state on an accepting path (laundering precondition, see above) => INCONCLUSIVE.
Never a false PROVEN. A hook that never reads the nonce trivially has no nonce dependence ->
PROVEN (vacuously, and that is correct: no decision can hinge on something never read).

Usage: python prove_time_nonce.py <hook.wasm>
Exit 0 = PROVEN, 2 = COUNTEREXAMPLE, 3 = INCONCLUSIVE.
"""
import sys
import z3
from prover import Engine


def _depends_on(expr, target_names: set) -> bool:
    """SOUND: True iff the Z3 expression tree contains a leaf constant (variable) whose
    name is in `target_names`. Walks the WHOLE AST (every child of every node), so a nonce
    symbol buried under arithmetic / concat / extract is still found. A non-AST value
    (e.g. a Python int from a fully-concrete write) trivially depends on nothing."""
    if not z3.is_ast(expr):
        return False
    seen = set()
    stack = [expr]
    while stack:
        node = stack.pop()
        if not z3.is_ast(node):
            continue
        key = node.get_id()
        if key in seen:
            continue
        seen.add(key)
        # A 0-arity application that is an uninterpreted constant == a variable leaf.
        if z3.is_const(node) and node.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            if str(node) in target_names:
                return True
        for ch in node.children():
            stack.append(ch)
    return False


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    nonce_syms = list(e.nonce_syms)
    print(f"explored: {len(e.accepts)} accepting path(s); "
          f"{len(nonce_syms)} ledger_nonce byte(s) read")

    if nonce_syms:
        nonce_names = {str(b) for b in nonce_syms}

        # FAIL-CLOSED: nonce-through-state laundering. The engine does NOT connect a
        # same-invocation state_set write to a later state read (state() returns a fresh
        # state_old:<key> symbol), so a hook that writes a nonce-derived value to state and
        # gates accept on the read-back would have a nonce-FREE accept constraint -> the
        # substitution query below would miss it and falsely PROVE. We therefore check the
        # laundering PRECONDITION directly: any accepting path whose state writes include a
        # value depending on a nonce symbol makes the dependence query INCOMPLETE -> we
        # cannot claim PROVEN for that path. (e.accepts_full carries per-path writes.)
        for code, cons, writes in e.accepts_full:
            for key, val in writes.items():
                if _depends_on(val, nonce_names):
                    print("\n⚠️ INCONCLUSIVE — an accepting path writes a ledger_nonce-derived "
                          f"value into state (key {key!r}). The engine does not model "
                          "same-invocation state read-after-write, so a nonce laundered through "
                          "state cannot be tracked by the dependence query; cannot claim PROVEN "
                          "(fail-closed).")
                    return 3

        # Build a substitution nonce -> fresh primed nonce. Shared (non-nonce) symbols are
        # left untouched, so the two constraint copies agree on EVERYTHING except the nonce.
        primed = [z3.BitVec(f"{b}__prime", b.size()) for b in nonce_syms]
        sub = list(zip(nonce_syms, primed))

        for code, cons in e.accepts:
            C = z3.And(*cons) if cons else z3.BoolVal(True)
            Cp = z3.substitute(C, *sub)
            s = z3.Solver()
            # C holds (path reachable for some input + nonce N1) but Cp fails for the SAME
            # non-nonce input under a different nonce N2 => accept depends on the nonce.
            s.add(C)
            s.add(z3.Not(Cp))
            r = s.check()
            if r == z3.unknown:
                print("\n⚠️ INCONCLUSIVE — solver returned `unknown` on the nonce-dependence "
                      "query for an accept path; cannot claim PROVEN.")
                return 3
            if r == z3.sat:
                print("\n❌ COUNTEREXAMPLE — an accept decision DEPENDS on ledger_nonce:")
                print("   the same transaction is accepted under one nonce and rejected under "
                      "another — a grindable/predictable nonce decides the outcome (insecure "
                      "randomness). An attacker who predicts/grinds the nonce controls the result.")
                return 2

    if e.unsupported:
        print(f"\n⚠️ INCONCLUSIVE — unsupported opcode(s) {sorted(e.unsupported)} reached; not PROVEN.")
        return 3
    if e.hit_bound:
        print("\n⚠️ INCONCLUSIVE — a loop exceeded the unroll bound; not PROVEN.")
        return 3

    print("\n✅ PROVEN — for ALL inputs, no accept decision hinges on ledger_nonce. "
          "(Legitimate ledger_seq/ledger_last_time deadlines are not flagged — see docstring.)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
