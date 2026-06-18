"""Prove IN-WORLD RESOURCE CONSERVATION — no value minted from nothing.

  for all inputs:  accept  =>  resource' (persisted)  <=  resource_old (read)  +  MINT

where `resource` is an in-world resource/currency counter held in a HookState slot, and MINT is
a declared mint allowance read from a hook parameter (the cap on how much new resource THIS
transition may legitimately create). With no MINT param, MINT = 0 — pure conservation: a
transition may only move/destroy resource, never create it.

WHY (EverArcade / persistent on-world economies): a world with "economic evolution" that cannot
prove its resource ledger is an infinite-inflation / dupe bug waiting to happen. This is the
DUAL of prove_monotonic: monotonic proves a counter never moves DOWN (replay/high-water mark);
this proves an in-world resource counter never moves UP beyond a declared mint (no inflation).
It is distinct from prove_conservation, which bounds EMITTED native XRP by the INCOMING payment
— here the conserved quantity is a STATE resource, not emitted value.

CONTRACT (what a hook must look like to be analyzable here):
  HookState slot RES (the conserved resource counter, big-endian uint, read then written).
  Optional hook parameter "MINT" (8-byte BE drops) — the declared per-transition mint cap; if
  absent, MINT = 0 (pure conservation).

SCOPE / SOUNDNESS (fail-closed, never a false PROVEN):
  - A write to RES with NO prior read (unconditional overwrite) => COUNTEREXAMPLE (the resource
    is set with no regard to its prior value — unbounded creation), mirroring prove_monotonic.
  - A width mismatch between read and written value => INCONCLUSIVE (not comparable).
  - unsupported opcode / hit unroll bound / solver `unknown` => INCONCLUSIVE.
  - Single-invocation, single-account bound: proves THIS transition does not inflate the slot
    beyond MINT. Cross-account / multi-tick aggregate conservation is out of scope (Tier-1
    differential replay territory) — never claimed here.

Usage: python prove_resource_conservation.py <hook.wasm>
Exit 0 = PROVEN, 2 = COUNTEREXAMPLE, 3 = INCONCLUSIVE, 1 = N/A.
"""
import sys
import z3
from prover import Engine, feasible
from field import parse_field, bv_byte_slice

W = 128
RES_KEY = "\x01"   # the conserved-resource slot (fixed 1-byte key 0x01), latin1


def z128(x):
    return z3.ZeroExt(W - x.size(), x) if x.size() < W else x


def main(path: str, field=None) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    # the declared mint allowance (0 if the hook reads no MINT param)
    mint_bytes = e.inputs.get("param:MINT")
    MINT = z128(z3.Concat(*mint_bytes)) if mint_bytes else z3.BitVecVal(0, W)

    # --field targets a byte sub-field of a packed slot (e.g. 01:8:8 = the resource field of a
    # [tick|resource] slot); default = the whole 0x01 resource slot.
    res_key = field.key if field is not None else RES_KEY

    # only paths that persist the resource slot are in scope for this obligation.
    res_writes = [(c, cons, w) for (c, cons, w) in e.accepts_full if res_key in w]
    if not res_writes:
        print(f"N/A — no accepting path persists the resource slot (key 0x{ord(res_key):02x}); "
              "the resource-conservation property was not exercised. Not claimed.")
        return 1

    print(f"explored: {len(e.accepts_full)} accepting path(s) "
          f"({len(res_writes)} persist the resource slot); "
          f"MINT cap {'from param' if mint_bytes else '= 0 (pure conservation)'}"
          + (f"; targeting field {field}" if field else ""))

    for code, cons, writes in res_writes:
        if not feasible(cons):
            continue
        wval = writes[res_key]
        old_bytes = e.state_old.get(res_key)
        # FAIL CLOSED: an unconditional write (no prior read) creates resource from nothing.
        if not old_bytes:
            print(f"\n❌ COUNTEREXAMPLE — accept writes the resource slot WITHOUT reading its "
                  "prior value: resource is created with no regard to what was there (unbounded "
                  "mint from nothing).")
            return 2
        old = z3.Concat(*old_bytes) if len(old_bytes) > 1 else old_bytes[0]
        if old.size() != wval.size():
            print(f"\n⚠️ INCONCLUSIVE — resource write is {wval.size() // 8}B but the prior read "
                  f"was {old.size() // 8}B; not comparable, conservation unproven. Not PROVEN.")
            return 3

        # When --field is set, compare only the targeted byte sub-field (the resource sub-field).
        cmp_w, cmp_o = wval, old
        if field is not None:
            try:
                cmp_w = bv_byte_slice(wval, field.off, field.length)
                cmp_o = bv_byte_slice(old, field.off, field.length)
            except ValueError as ex:
                print(f"\n⚠️ INCONCLUSIVE — {ex}; cannot check the field. Not PROVEN.")
                return 3

        # NEGATION of the invariant: persisted resource' > resource_old + MINT (inflation past
        # the declared mint). 128-bit to avoid wrap masking a real overflow.
        s = z3.Solver(); s.set("timeout", 120000)
        s.add(*cons)
        s.add(z3.UGT(z128(cmp_w), z128(cmp_o) + MINT))
        r = s.check()
        if r == z3.unknown:
            print(f"\n⚠️ INCONCLUSIVE — solver `unknown` on accept code {code}; not PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model(); ev = lambda b: m.eval(b, model_completion=True).as_long()
            print("\n❌ COUNTEREXAMPLE — accept INFLATES the in-world resource beyond the declared mint:")
            print(f"   prior resource = {ev(z128(cmp_o))}   MINT cap = {ev(MINT)}")
            print(f"   persisted resource' = {ev(z128(cmp_w))}  >  prior + MINT = "
                  f"{ev(z128(cmp_o)) + ev(MINT)}  -> value created from nothing")
            return 2

    if e.float_overapprox:
        print(f"\n⚠️ INCONCLUSIVE — float op(s) {sorted(e.float_overapprox)} over-approximated; not PROVEN.")
        return 3
    if e.unsupported:
        print(f"\n⚠️ INCONCLUSIVE — unsupported opcode(s) {sorted(e.unsupported)} reached; not PROVEN.")
        return 3
    if e.hit_bound:
        print("\n⚠️ INCONCLUSIVE — a loop exceeded the unroll bound; not PROVEN.")
        return 3

    print("\n✅ PROVEN — for ALL inputs, no accepting path inflates the in-world resource slot "
          "beyond its declared MINT allowance (resource' <= resource_old + MINT). No value is "
          "created from nothing. (SCOPE: single-invocation, single-account state slot; "
          "cross-account / multi-tick aggregate conservation is out of model.)")
    return 0


if __name__ == "__main__":
    argv = sys.argv[2:]
    fld = parse_field(argv[argv.index("--field") + 1]) if "--field" in argv else None
    sys.exit(main(sys.argv[1], fld))
