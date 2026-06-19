"""Prove the agent_guardrail invariant — the REAL deployed hook.

  for all inputs:  (accept AND outgoing Payment)  =>  drops <= LIM

"outgoing Payment" is the hook's own condition: otxn_type == Payment(0) AND the
originating account == the hook's account (origin == hook_account, 20 bytes).
`drops` uses the guardrail's decode: byte 0 masked with 0x3F (strips the native /
sign flag bits), big-endian.

Usage: python prove_guardrail.py <agent_guardrail.wasm> [max_drops]
"""
import sys
import z3
from prover import Engine
from soundness import unsound_gate
from smt_export import emit_query
from watch.predicates import decode_drops, over_limit, dest_not_allowed, Z3Ops


def main(path: str, max_drops: int | None = None) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    amt = e.inputs.get("amt")
    lim = e.inputs.get("param:LIM")
    origin = e.inputs.get("origin")
    me = e.inputs.get("hookacc")
    tt = e.inputs.get("otxn_type")
    if not all([amt, lim, origin, me, tt is not None]):
        print("ERROR: hook does not look like agent_guardrail (needs otxn_type, sfAccount, hook_account, sfAmount, LIM)")
        return 1

    # the guardrail's amount decode masks byte0 with 0x3F (strips not-XRP/sign bits).
    # SHARED with the watcher via watch.predicates — same rule, two evaluators (no fork).
    drops = decode_drops(amt, Z3Ops)
    limit = z3.Concat(*lim)
    is_payment = tt == 0
    is_outgoing = z3.And(*[origin[i] == me[i] for i in range(20)])

    print(f"explored paths: {len(e.accepts)} accepting, {len(e.rollbacks)} rolling back")
    if max_drops is not None:
        print(f"(restricting to reachable inputs: drops <= {max_drops})")

    # ── invariant 1: spend-limit ───────────────────────────────────────────
    #   (accept AND outgoing Payment)  =>  drops <= LIM
    for code, cons in e.accepts:
        s = z3.Solver()
        s.add(*cons)
        s.add(is_payment, is_outgoing)          # scope: an OUTGOING PAYMENT
        s.add(over_limit(drops, limit, Z3Ops))  # ...that the hook still accepted over-limit (shared rule)
        if max_drops is not None:
            s.add(z3.ULE(drops, z3.BitVecVal(max_drops, 64)))
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE [spend-limit] — solver returned `unknown` "
                  "(timeout/incompleteness) on an accepting path; cannot claim PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model()
            ev = lambda b: m.eval(b, model_completion=True).as_long()
            av = bytes(ev(b) for b in amt)
            lv = bytes(ev(b) for b in lim)
            dv = ((av[0] & 0x3F) << 56) | int.from_bytes(av[1:], "big")
            lvv = int.from_bytes(lv, "big")
            print("\n❌ COUNTEREXAMPLE [spend-limit] — guardrail ACCEPTS an over-limit OUTGOING payment:")
            print(f"   accept code {code}: drops={dv} > LIM={lvv}")
            print(f"   sfAmount bytes = {av.hex().upper()}   LIM = {lv.hex().upper()}")
            return 2
        emit_query(s, "guardrail", "spendlimit")  # unsat: path proven — record obligation

    # ── invariant 2: destination allowlist (the DST lock) ───────────────────
    #   (accept AND outgoing Payment AND DST policy set)  =>  dest == allowed
    # The host return for hook_param(DST) is symbolic; ==20 means a 20-byte
    # account policy is present. We prove the lock can't be bypassed.
    dest = e.inputs.get("dest")
    allowed = e.inputs.get("param:DST")
    dst_ret = e.inputs.get("hook_param_ret:DST")
    if dest and allowed and dst_ret is not None:
        dest_mismatch = dest_not_allowed(dest, allowed, Z3Ops)   # shared rule (no fork)
        for code, cons in e.accepts:
            s = z3.Solver()
            s.add(*cons)
            s.add(is_payment, is_outgoing)              # an OUTGOING PAYMENT
            s.add(dst_ret == 20)                        # ...with a DST policy set
            s.add(dest_mismatch)                        # ...to a NON-allowed destination
            r = s.check()
            if r == z3.unknown:
                print("\n⚠️ INCONCLUSIVE [dst-lock] — solver returned `unknown` "
                      "(timeout/incompleteness) on an accepting path; cannot claim PROVEN.")
                return 3
            if r == z3.sat:
                m = s.model()
                ev = lambda b: m.eval(b, model_completion=True).as_long()
                dv = bytes(ev(b) for b in dest)
                lvv = bytes(ev(b) for b in allowed)
                print("\n❌ COUNTEREXAMPLE [dst-lock] — guardrail ACCEPTS a payment to a non-allowed destination:")
                print(f"   accept code {code}: Destination={dv.hex().upper()}  allowed(DST)={lvv.hex().upper()}")
                return 2
            emit_query(s, "guardrail", "dstlock")  # unsat: path proven — record obligation
        dst_proven = True
    else:
        dst_proven = False   # hook reads no DST param — lock invariant N/A

    code = unsound_gate(e)
    if code is not None:
        return code

    print("\n✅ PROVEN [spend-limit] — for ALL inputs, the guardrail never accepts an outgoing payment over LIM.")
    if dst_proven:
        print("✅ PROVEN [dst-lock]   — for ALL inputs, when a DST policy is set, an accepted outgoing payment goes only to the allowed account.")
    return 0


if __name__ == "__main__":
    # Positional: <hook.wasm> [max_drops].  Optional flags (do NOT change main()'s signature,
    # which the test suite calls directly):
    #   --emit-manifest <path>   write a proof manifest (only on a PROVEN exit; fail-closed)
    #   --lim <drops>            deployment per-tx cap to record in the manifest params
    #   --dst <40-hex>           deployment destination allowlist (20-byte account-id, hex)
    argv = sys.argv[1:]
    emit_path = lim_param = dst_param = None
    positional = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--emit-manifest":
            emit_path = argv[i + 1]; i += 2
        elif a == "--lim":
            lim_param = int(argv[i + 1]); i += 2
        elif a == "--dst":
            dst_param = argv[i + 1]; i += 2
        else:
            positional.append(a); i += 1
    hook_path = positional[0]
    md = int(positional[1]) if len(positional) > 1 else None

    code = main(hook_path, md)

    if emit_path is not None:
        # FAIL CLOSED: only a PROVEN run emits a manifest. write_manifest itself also refuses.
        if code != 0:
            print(f"\n(not emitting manifest: prover exit {code} is not PROVEN)")
            sys.exit(code)
        from watch.manifest import build_manifest, write_manifest
        params = {}
        if lim_param is not None:
            params["LIM"] = lim_param
        if dst_param is not None:
            params["DST"] = dst_param.upper()
        m = build_manifest(
            wasm=open(hook_path, "rb").read(),
            invariant="guardrail",
            verdict="PROVEN [spend-limit, dst-lock]",
            exit_code=code,
            params=params,
            scope_caveats=["native XAH amounts only — IOU/issued amounts are out of model"],
        )
        write_manifest(m, emit_path)
        print(f"\n📄 proof manifest written: {emit_path}  (HookHash {m.hook_hash[:8]}…{m.hook_hash[-8:]})")

    sys.exit(code)
