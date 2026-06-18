"""Prove EMIT DESTINATION-LOCK — every payment the hook EMITS goes only to an allowed destination.

  for all inputs:  accept  =>  every emitted Payment's Destination  ==  the locked dest (param DST)

Distinct from `permissioned-transfer` (which gates the INCOMING transaction's destination): this
gates the hook's OWN emitted transactions. The threat it rules out: a hook that can be driven to
EMIT a payment to an attacker-chosen address (fund redirection). Useful for any hook that pays out —
a treasury/settlement Hook should only ever emit to its configured counterparty.

MODEL. The locked destination is a 20-byte HookParameter `DST` (symbolic to the prover -> proven for
ALL DST values). For each emitted native Payment captured per accept path (Engine.emit_obs_on_accept,
the audited dest extractor), the destination must equal DST byte-for-byte. An emit whose blob is NOT
the recognized native template (IOU/custom) FAILS CLOSED -> INCONCLUSIVE (the dest can't be read, so
the lock can't be certified). NOTE: this checks ONE specific field (the emitted Destination), so —
unlike preview-faithfulness's "every observable field invariant" — there is no field-coverage gap;
the dest extractor itself was audited sound.

Fail closed: solver `unknown` / unsupported / hit bound / dropped path -> INCONCLUSIVE. A hook that
reads no DST param -> N/A (the lock isn't parameterized). No emitted payment on any accept path ->
N/A (vacuity_guard), never a vacuous PROVEN.

Usage: python prove_dst_lock.py <hook.wasm>
Exit 0 = PROVEN, 1 = N/A, 2 = COUNTEREXAMPLE, 3 = INCONCLUSIVE.
"""
import sys
import z3
from prover import Engine
from soundness import unsound_gate, vacuity_guard

DST_KEY = "param:DST"


def main(path: str) -> int:
    # Construct AND run inside the guard: a parse-time fault (corrupt/non-wasm input) during
    # Engine() must also fail closed to INCONCLUSIVE, not exit 1 (which aliases N/A). [audit DSTLOCK-1]
    try:
        e = Engine(open(path, "rb").read())
        e.run()
    except Exception as ex:  # noqa: BLE001 — fail closed, never crash to an N/A-aliasing exit
        print(f"\n⚠️ INCONCLUSIVE — engine could not analyze the hook ({type(ex).__name__}: "
              f"{str(ex)[:140]}); not PROVEN.")
        return 3

    dst = e.inputs.get(DST_KEY)
    if not dst or len(dst) < 20:
        print("N/A — hook does not read a 20-byte destination-lock parameter DST; the emit "
              "destination-lock property is not exercised. Not claimed.")
        return 1

    print(f"explored: {len(e.emit_obs_on_accept)} accepting path(s) with emit records")
    n_checked = 0
    for cons, obs_list, emit_count in e.emit_obs_on_accept:
        parsed = [o for o in obs_list if o is not None]
        if emit_count > len(parsed):
            print("\n⚠️ INCONCLUSIVE — an accepting path emits a transaction whose blob is not the "
                  "recognized native-Payment template (IOU/custom); its destination can't be read to "
                  "verify the lock. Cannot claim PROVEN (fail-closed).")
            return 3
        for obs in parsed:
            n_checked += 1
            d = obs["dest"]
            not_locked = z3.Or(*[d[i] != dst[i] for i in range(20)])
            s = z3.Solver(); s.add(*cons); s.add(not_locked)
            r = s.check()
            if r == z3.unknown:
                print("\n⚠️ INCONCLUSIVE — solver `unknown` on an emit-destination query; not PROVEN.")
                return 3
            if r == z3.sat:
                m = s.model()
                ev = lambda b: m.eval(b, model_completion=True).as_long() & 0xFF
                dv = bytes(ev(b) for b in d); lv = bytes(ev(b) for b in dst)
                print("\n❌ COUNTEREXAMPLE — the hook EMITS a payment to an UNLOCKED destination "
                      "(not the configured DST):")
                print(f"   emitted destination = {dv.hex().upper()}")
                print(f"   locked DST          = {lv.hex().upper()}")
                return 2

    code = unsound_gate(e)
    if code is not None:
        return code
    code = vacuity_guard(n_checked, "emit destination-lock (no accepting path emits a payment)")
    if code is not None:
        return code

    print("\n✅ PROVEN — for ALL inputs, every payment this hook emits is sent to the locked "
          "destination DST. The hook cannot be driven to emit funds to any other address. "
          "(SCOPE: native-template emitted Payments; an unrecognized emit blob fails closed.)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
