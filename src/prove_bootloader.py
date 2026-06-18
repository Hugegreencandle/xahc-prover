"""Prove a REFERENCE-MODEL bootloader gate — "accept only on a matching hash".

  for all inputs:  accept  =>  candidate_hash == pinned_hash   (all 32 bytes)

CONTEXT (the layer-1-UI / PWA boot-blob story, Xahau discussion #759). A bootloader is meant to be
the root of trust for a Hook's UI: fetch a larger stage-2 app, run it ONLY if the bytes hash to a
pinned value. The go/no-go decision is a small, bounded gate — exactly the shape this engine proves.
We model that gate (`bootloader_verify.c` is a REFERENCE MODEL, not a deployed hook) as an
accept-decision over two 32-byte inputs:
  PIN — the pinned SHA-512Half the policy fixes,
  CAN — the candidate hash the wallet computed over the fetched stage-2 bytes,
and prove the gate ACCEPTS (hands control to stage-2) ONLY when all 32 bytes match.

WHAT THIS PROVES — and the three things it does NOT (read before quoting this anywhere):
This closes exactly ONE link — the gate's accept logic. It is the same byte-exact-equality
discipline as the guardrail's dst-lock (20 bytes; there over a real testnet-validated hook, here
over a reference model). EXPLICITLY out of model and TRUSTED:
  1. The on-chain `SetBoot` transaction (xahaud) stores the blob VERBATIM and verifies NOTHING —
     the pin/compare is a wallet-side convention, not protocol-enforced. The node does not hash.
  2. The wallet's SHA-512Half over the fetched stage-2 bytes (fed in here as CAN) is trusted.
  3. Stage-2 sandboxing / isolation after the gate accepts is out of model.
So do NOT say "the whole app is proven" or "prove(Hook)+prove(bootloader) = the app verified": the
proof covers the gate's accept condition, not the boot chain end to end.

Fail-closed: solver `unknown` / unsupported opcode / hit unroll bound => INCONCLUSIVE, never PROVEN.

Usage: python prove_bootloader.py <hook.wasm>
Exit 0 = PROVEN, 2 = COUNTEREXAMPLE, 3 = INCONCLUSIVE, 1 = N/A.
"""
import sys
import z3
from prover import Engine
from soundness import unsound_gate

N = 32  # SHA-512Half digest length


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    e.run()

    pin = e.inputs.get("param:PIN")
    can = e.inputs.get("param:CAN")
    if not pin or not can or len(pin) < N or len(can) < N:
        print("ERROR: hook does not read the verify-core params PIN (32-byte pinned hash) and "
              "CAN (32-byte candidate hash). Not analyzable by this driver.")
        return 1

    # Non-vacuity (BL-INFO-1): a gate that reads PIN/CAN but NEVER accepts would make the
    # accept ⟹ match obligation vacuously true and print a misleading "cannot hand control" banner.
    # Disclose instead (mirrors prove_unchecked_return's 0-accept N/A), so PROVEN only ever
    # describes a gate that actually accepts on some input.
    if not e.accepts:
        print("N/A — the gate has 0 accepting paths; the accept ⟹ (candidate == pinned) "
              "obligation is vacuous, not claimed.")
        return 1

    # negation of the invariant: an accepting path where ANY of the 32 bytes differ.
    mismatch = z3.Or(*[pin[i] != can[i] for i in range(N)])

    print(f"explored: {len(e.accepts)} accepting path(s); checking accept ⟹ candidate == pinned (32B)")

    for code, cons in e.accepts:
        s = z3.Solver()
        s.set("timeout", 120000)
        s.add(*cons)
        s.add(mismatch)
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE — solver returned `unknown` on an accepting path; not PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model()
            ev = lambda bs: bytes(m.eval(b, model_completion=True).as_long() for b in bs)
            pv, cv = ev(pin[:N]), ev(can[:N])
            diff = next(i for i in range(N) if pv[i] != cv[i])
            print("\n❌ COUNTEREXAMPLE — the loader ACCEPTS a candidate whose hash ≠ the pin:")
            print(f"   first differing byte {diff}: pin={pv[diff]:#04x} candidate={cv[diff]:#04x}")
            print(f"   PIN={pv.hex().upper()}")
            print(f"   CAN={cv.hex().upper()}")
            print("   => the loader could be tricked into running UNVERIFIED stage-2 bytes.")
            return 2

    code = unsound_gate(e)
    if code is not None:
        return code

    print("\n✅ PROVEN — for ALL inputs, the gate accepts (hands control to stage-2) ONLY when the "
          "candidate hash equals the pinned hash, all 32 bytes. ASSUMING the wallet computes "
          "CAN = SHA-512Half(fetched bytes) correctly and stage-2 is sandboxed — and noting the "
          "on-chain SetBoot stores the blob verbatim and verifies nothing — the loader cannot hand "
          "control to bytes whose hash != pin. (Proves the gate's accept logic, not the whole boot "
          "chain; reference model, not a deployed hook.)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
