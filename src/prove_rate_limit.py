"""Prove RATE-LIMIT (cooldown) — an action is accepted only after a minimum time has elapsed since
the last one, and the recorded timestamp is the real ledger clock (not attacker-spoofable).

  for all inputs:  accept  =>  (A) persisted_time'  >=  prior_time  +  COOLDOWN   (enough elapsed)
                          AND  (B) persisted_time'  is bound to ledger_last_time   (not spoofable)

CONTEXT. A cooldown / anti-spam gate: "one action per COOLDOWN seconds." It's a stateful inductive
property like period-budget — state slot 0x01 holds the last-action timestamp; each accepted action
must be at least COOLDOWN past the stored one, and must STAMP the real ledger time so the next
cooldown is measured honestly. Two ways it's unsafe, both ruled out:
  (A) NO GATE — accepts regardless of elapsed time (spam).
  (B) SPOOFABLE STAMP — writes an attacker-chosen value as the "timestamp" instead of the ledger
      clock, so the elapsed check is meaningless (an attacker writes prior+COOLDOWN and bypasses it).

MODEL. State slot 0x01 = last-action timestamp (8B). Param COOLDOWN = minimum delta (8B). The hook
reads now = ledger_last_time() (engine symbol e.inputs["ledger_last_time"]), the prior stamp from
slot 0x01, requires now >= prior + COOLDOWN, and persists now. We prove on every accept that writes
the slot:
  (A) cons & ULT128(new, old + COOLDOWN)            UNSAT  — else COUNTEREXAMPLE (accepted too soon)
  (B) the written value DEPENDS on ledger_last_time         — else COUNTEREXAMPLE (spoofable stamp)
128-bit compare avoids wrap masking a real violation.

STRICT FORM (every accept is a gated action): the check runs over EVERY feasible accepting path. An
accept that does NOT stamp the cooldown slot is an action accepted WITHOUT the rate-limit gate (an
admin override, an early accept, an attacker-triggered branch) -> COUNTEREXAMPLE. A hook that
legitimately accepts non-actions on pass-through paths must scope to the gated accept, or rollback
non-actions so every accept is a rate-limited action. [audit FP-RL-01: filtering to slot-writers let
a bypass accept slip a false PROVEN.]

Fail closed: solver `unknown` / unsupported / hit bound / dropped path -> INCONCLUSIVE. No COOLDOWN
param or no ledger_last_time read -> N/A. No accept writes the slot -> N/A (vacuity_guard), never a
vacuous PROVEN.

Usage: python prove_rate_limit.py <hook.wasm>
Exit 0 = PROVEN, 1 = N/A, 2 = COUNTEREXAMPLE, 3 = INCONCLUSIVE.
"""
import sys
import z3
from prover import Engine, feasible
from soundness import unsound_gate, vacuity_guard

W = 128
SLOT = "\x01"            # last-action timestamp
CD_KEY = "param:COOLDOWN"
TIME_NAME = "ledger_last_time"


def z128(x):
    return z3.ZeroExt(W - x.size(), x) if x.size() < W else x


def main(path: str) -> int:
    try:
        e = Engine(open(path, "rb").read())
        e.run()
    except Exception as ex:  # noqa: BLE001 — fail closed (parse OR run), never exit-1/N-A alias
        print(f"\n⚠️ INCONCLUSIVE — engine could not analyze the hook ({type(ex).__name__}: "
              f"{str(ex)[:140]}); not PROVEN.")
        return 3

    cd = e.inputs.get(CD_KEY)
    now = e.inputs.get(TIME_NAME)
    if not cd or now is None:
        print("N/A — hook does not read BOTH a COOLDOWN parameter and ledger_last_time; the "
              "rate-limit property is not exercised. Not claimed.")
        return 1
    COOLDOWN = z3.Concat(*cd) if isinstance(cd, list) and len(cd) > 1 else (cd[0] if isinstance(cd, list) else cd)

    n_slot = sum(1 for (_, _, w) in e.accepts_full if SLOT in w)
    print(f"explored: {len(e.accepts_full)} accepting path(s); {n_slot} stamp the "
          f"rate-limit slot 0x{ord(SLOT):02x}")
    n_checked = 0
    # Check EVERY feasible accept — not just the slot-stamping ones. An accept that does NOT stamp
    # the cooldown slot is an action accepted WITHOUT the rate-limit gate (an admin override, an
    # early accept, an attacker-triggered branch) = a spam bypass. Filtering to slot-writers let
    # such a path slip a false PROVEN. [audit FP-RL-01] Strict-form, like prove_authz/permissioned.
    for code, cons, writes in e.accepts_full:
        if not feasible(cons):
            continue
        if SLOT not in writes:
            print("\n❌ COUNTEREXAMPLE — an accepting path does NOT stamp the cooldown slot "
                  f"0x{ord(SLOT):02x}: this action is accepted WITHOUT any elapsed-time gate (a "
                  "rate-limit bypass — e.g. an override / early accept / attacker-triggered branch).")
            return 2
        new = writes[SLOT]
        old_bytes = e.state_old.get(SLOT)
        if not old_bytes:
            print("\n❌ COUNTEREXAMPLE — accept stamps the slot WITHOUT reading the prior timestamp: "
                  "no elapsed-time comparison constrains the action (no rate limit).")
            return 2
        old = z3.Concat(*old_bytes) if len(old_bytes) > 1 else old_bytes[0]
        if old.size() != new.size():
            print(f"\n⚠️ INCONCLUSIVE — slot write {new.size()//8}B vs prior {old.size()//8}B; not "
                  "comparable. Not PROVEN.")
            return 3
        n_checked += 1

        # (A) THE GATE — on the REAL ledger clock, not the written stamp. (Checking the stamp would
        # let `stamp = max(now, prior+COOLDOWN)` accept too-soon yet look compliant — a burst bypass.)
        # accept must imply the actual ledger time is >= prior + COOLDOWN.
        s = z3.Solver(); s.set("timeout", 120000)
        s.add(*cons)
        s.add(z3.ULT(z128(now), z128(old) + z128(COOLDOWN)))
        r = s.check()
        if r == z3.unknown:
            print(f"\n⚠️ INCONCLUSIVE — solver `unknown` on accept code {code}; not PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model(); ev = lambda b: m.eval(b, model_completion=True).as_long()
            print("\n❌ COUNTEREXAMPLE — accept fires BEFORE the cooldown elapsed:")
            print(f"   ledger time = {ev(z128(now))}   prior = {ev(z128(old))}   "
                  f"COOLDOWN = {ev(z128(COOLDOWN))}  (now < prior + COOLDOWN)")
            return 2

        # (B) HONEST STAMP (sound induction) — the persisted timestamp must EQUAL the real ledger
        # clock, so the next cooldown's "prior" is a true past time (not an attacker/forward value).
        s2 = z3.Solver(); s2.set("timeout", 120000)
        s2.add(*cons)
        s2.add(new != now)
        r2 = s2.check()
        if r2 == z3.unknown:
            print(f"\n⚠️ INCONCLUSIVE — solver `unknown` on the stamp-honesty query (code {code}); not PROVEN.")
            return 3
        if r2 == z3.sat:
            print("\n❌ COUNTEREXAMPLE — the persisted timestamp is NOT the real ledger clock "
                  "(ledger_last_time): a spoofable / forward-dated stamp breaks the cooldown's "
                  "induction (an attacker stamps prior+COOLDOWN and bypasses the gate next time).")
            return 2

    code = unsound_gate(e)
    if code is not None:
        return code
    code = vacuity_guard(n_checked, "rate-limit (no accepting path stamps the cooldown slot)")
    if code is not None:
        return code

    print("\n✅ PROVEN — for ALL inputs, the hook accepts an action only at least COOLDOWN after its "
          "prior action, and stamps the real ledger time (not an attacker value). A genuine, "
          "non-spoofable cooldown / anti-spam gate. (SCOPE: single-slot per-account cooldown, "
          "wall-clock via ledger_last_time.)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
