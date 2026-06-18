"""Prove PREVIEW-FAITHFULNESS — the outcome a wallet shows BEFORE you sign is provably the outcome
that executes on-ledger.

  for all inputs:  the OBSERVABLE OUTCOME of the hook — its accept/reject DECISION, its EMITTED
                   transactions, and its STATE WRITES — is INVARIANT under the ledger ENTROPY that
                   can differ between the preview (simulate) moment and on-ledger execution:
                   ledger_nonce, ledger_seq, ledger_last_time.

WHY THIS MATTERS (the Xaman simulate-panel integration): a wallet previews "what will this do?" by
simulating the hook at sign-time. If the hook's outcome depends on ledger entropy that changes
between the preview and execution (a nonce, the sequence, the clock), the preview can LIE — the user
signs expecting one effect and gets another. A PROVEN here means the simulate panel's preview is a
*guarantee*, not a guess.

WHAT THIS PROVES — and its SCOPE (do NOT overclaim):
  Faithful = the outcome is invariant under ledger_nonce / ledger_seq / ledger_last_time. It remains
  CONDITIONAL on the hook STATE as read at preview time: a concurrent change to that state between
  preview and execution is a separate, inherent caveat NOT covered here (the wallet previews against
  current state by definition). A time-gated hook (accept iff `ledger_seq >= DEADLINE`) is correctly
  reported NOT faithful — its preview genuinely can flip as the ledger advances. (This is the
  intended DIFFERENCE from prove_time_nonce, which deliberately does not flag legit seq/time
  deadlines: that invariant targets insecure randomness; THIS one targets preview reliability.)

Method (sound, reuses prove_time_nonce machinery):
  - DECISION: per accepting path constraint C, substitute every entropy symbol with a fresh primed
    copy (all non-entropy symbols shared). If C can hold yet the primed copy Cp fail for the same
    non-entropy input, the accept decision flips under entropy -> COUNTEREXAMPLE (exact query).
  - EMITS (v1 scope boundary): proving an emitted txn faithful requires proving EVERY user-observable
    field is entropy-invariant. A positive allowlist of checked fields is unsound (the next omitted
    field slips a false PROVEN — audit FP1/FP3/FP4). So v1 FAILS CLOSED: any emit on an accepting
    path -> INCONCLUSIVE. Complete emit coverage (a field-aware whole-blob check exempting only the
    protocol-mechanical FLS/LLS/Fee/etxn_details bytes) is deferred to v2 with its own audit.
  - STATE WRITES: if any persisted state write on an accepting path depends on an entropy symbol ->
    COUNTEREXAMPLE. (Syntactic dependence is conservative toward flagging = safe; never a false PROVEN.)
  Fail closed: solver `unknown` / unsupported / hit-bound -> INCONCLUSIVE. No feasible accepting
  path -> N/A (vacuity_guard), never a vacuous PROVEN. A hook that reads no entropy and whose
  effects don't reference it is faithful -> PROVEN.

Usage: python prove_preview_faithfulness.py <hook.wasm>
Exit 0 = PROVEN, 1 = N/A, 2 = COUNTEREXAMPLE, 3 = INCONCLUSIVE.
"""
import sys
import z3
from prover import Engine
from soundness import unsound_gate, vacuity_guard


def _depends_on(expr, target_names: set) -> bool:
    """SOUND: True iff the Z3 AST of `expr` contains a variable leaf whose name is in
    `target_names`. Walks every child (entropy buried under arithmetic/concat/extract is found).
    A non-AST value (a concrete Python int) depends on nothing."""
    if not z3.is_ast(expr):
        return False
    seen = set(); stack = [expr]
    while stack:
        node = stack.pop()
        if not z3.is_ast(node):
            continue
        k = node.get_id()
        if k in seen:
            continue
        seen.add(k)
        if z3.is_const(node) and node.decl().kind() == z3.Z3_OP_UNINTERPRETED and str(node) in target_names:
            return True
        for ch in node.children():
            stack.append(ch)
    return False


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    entropy = list(e.nonce_syms) + list(e.time_syms)
    entropy_names = {str(b) for b in entropy}
    print(f"explored: {len(e.accepts_full)} accepting path(s); "
          f"entropy symbols read: {len(e.nonce_syms)} nonce + {len(e.time_syms)} seq/time")

    n_checked = 0

    # (1) DECISION dependence — exact substitution query per accepting path.
    if entropy:
        primed = [z3.BitVec(f"{b}__prime", b.size()) for b in entropy]
        sub = list(zip(entropy, primed))
        for code, cons in e.accepts:
            C = z3.And(*cons) if cons else z3.BoolVal(True)
            Cp = z3.substitute(C, *sub)
            s = z3.Solver(); s.add(C); s.add(z3.Not(Cp))
            r = s.check()
            if r == z3.unknown:
                print("\n⚠️ INCONCLUSIVE — solver `unknown` on the entropy-dependence query for an "
                      "accept path; cannot claim PROVEN.")
                return 3
            if r == z3.sat:
                print("\n❌ COUNTEREXAMPLE — the accept/reject DECISION depends on ledger entropy "
                      "(nonce/seq/last_time):")
                print("   the same signed transaction is accepted under one ledger state and "
                      "rejected under another — a preview computed at sign-time can DIFFER from "
                      "on-ledger execution (e.g. a sequence/time deadline). Preview is not faithful.")
                return 2

    # (2) EMITS — v1 scope boundary (FAIL CLOSED). Proving an emitted transaction is preview-faithful
    # means proving NO user-observable emitted field varies with entropy. Two audit rounds showed a
    # positive allowlist of checked fields (amount/dest/tags) is UNSOUND BY DESIGN — the next omitted
    # observable field (Flags, InvoiceID, Memos, …) slips a false PROVEN through (audit FP3/FP4). The
    # complete fix needs a field-aware whole-blob entropy check that exempts only the protocol-
    # mechanical fields (FLS/LLS validity window, Fee, host etxn_details) — deferred to v2 with its
    # own audit. Until then, ANY emit on an accepting path is INCONCLUSIVE: we DO NOT certify the
    # preview-faithfulness of an emitting hook rather than risk a false PROVEN. (Non-emitting hooks —
    # accept/reject + state, the guardrail/state-machine class — are fully covered below.)
    for cons, obs_list, emit_count in e.emit_obs_on_accept:
        if emit_count > 0:
            print("\n⚠️ INCONCLUSIVE — an accepting path EMITS a transaction. v1 proves preview-"
                  "faithfulness for the accept/reject decision and state writes; certifying that "
                  "EVERY observable field of an emitted transaction is entropy-invariant needs the "
                  "v2 field-aware blob check. Refusing to claim PROVEN for an emitting hook "
                  "(fail-closed).")
            return 3

    # (3) STATE-WRITE dependence — a previewed persisted effect that varies with entropy.
    for code, cons, writes in e.accepts_full:
        n_checked += 1
        for key, val in writes.items():
            if _depends_on(val, entropy_names):
                print("\n❌ COUNTEREXAMPLE — a persisted STATE WRITE depends on ledger entropy "
                      f"(nonce/seq/last_time) at key {key!r}: the previewed state effect can differ "
                      "at execution. Preview is not faithful.")
                return 2

    code = unsound_gate(e)
    if code is not None:
        return code

    code = vacuity_guard(n_checked, "preview faithfulness (no feasible accepting path produces an "
                                    "observable effect to check)")
    if code is not None:
        return code

    print("\n✅ PROVEN — for ALL inputs, the hook's accept/reject DECISION and its STATE WRITES are "
          "INVARIANT under ledger entropy (ledger_nonce / ledger_seq / ledger_last_time), and this "
          "hook emits no transaction. A wallet's pre-sign preview of this transaction's "
          "decision + state effect is a GUARANTEE of the on-ledger result. (SCOPE: v1 covers the "
          "decision + state writes of NON-emitting hooks; an emitting hook returns INCONCLUSIVE "
          "pending v2 emit coverage. Conditional on the hook state as read at preview time — a "
          "concurrent state change between preview and execution is a separate, inherent caveat.)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
