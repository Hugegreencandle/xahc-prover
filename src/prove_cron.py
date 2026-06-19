"""Prove cron-stacking safety: a hook re-arms at most K schedulers per invocation.

  for all inputs:  accept  =>  #(emitted CronSet txns) <= K

CronSet (ttCRON_SET = 93, the `Cron` amendment) schedules a future hook self-invocation (<=256
repeats). A hook that emits MORE than one CronSet per run grows the pending-cron set every cycle
=> unbounded stacking — the hook-side analogue of the protocol bug `fixCronStacking` patched.
Bounding re-arm to <=K (default 1) keeps the cron chain from compounding.

This is a STRUCTURAL property: the engine forks a path per branch, so each accepting path has a
concrete set of emitted tx types. We count CronSet emits per accepting path. Fail-closed: an emit
whose TransactionType the engine could not read concretely is treated as a POSSIBLE CronSet, so if
worst-case (confirmed + undetermined) could exceed K we return INCONCLUSIVE, never PROVEN. (There
is no per-path SMT obligation here, so `recheck` does not apply; `reverify` — re-running the engine
— is the independent check for this invariant.)

Exit 0 PROVEN · 1 N/A (no cron activity) · 2 COUNTEREXAMPLE · 3 INCONCLUSIVE.
"""
import sys
from prover import Engine
from soundness import unsound_gate

TT_CRON_SET = 93


def main(path: str, k: int = 1) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    accepts = e.emit_tts_on_accept  # list of (cons, emit_tts:list[int|None], emit_count)
    print(f"explored: {len(accepts)} accepting path(s); bound K={k}")

    any_cron = False
    any_unknown = False
    worst = 0
    for _cons, tts, _ec in accepts:
        n_cron = sum(1 for t in tts if t == TT_CRON_SET)
        n_unknown = sum(1 for t in tts if t is None)
        any_cron = any_cron or n_cron > 0
        any_unknown = any_unknown or n_unknown > 0
        worst = max(worst, n_cron)
        # A confirmed over-bound is a definitive counterexample.
        if n_cron > k:
            print(f"\n❌ COUNTEREXAMPLE — an accepting path emits {n_cron} CronSet txns (> K={k}); "
                  f"re-arming more than once per invocation stacks crons unboundedly.")
            return 2
        # Undetermined-type emits could be CronSet — if they could push the count over K, fail closed.
        if n_cron + n_unknown > k:
            print(f"\n⚠️ INCONCLUSIVE — an accepting path has {n_cron} CronSet + {n_unknown} "
                  f"undetermined-type emit(s); worst case could exceed K={k}. Not PROVEN.")
            return 3

    # Engine soundness gate (unsupported opcode / solver unknown / hit bound) -> INCONCLUSIVE.
    code = unsound_gate(e)
    if code is not None:
        return code

    if not any_cron and not any_unknown:
        print("\n— N/A — the hook emits no CronSet (and no undetermined-type emits); "
              "cron-stacking invariant not exercised.")
        return 1

    note = " (incl. worst-case undetermined-type emits)" if any_unknown else ""
    print(f"\n✅ PROVEN — for ALL inputs, accept ⟹ ≤ {k} CronSet emitted per invocation"
          f"{note}; max confirmed seen = {worst}. No unbounded cron stacking.")
    return 0


if __name__ == "__main__":
    kk = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    sys.exit(main(sys.argv[1], kk))
