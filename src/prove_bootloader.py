"""Prove the BOOTLOADER verify-core invariant — "loads only verified bytes".

  for all inputs:  accept  =>  candidate_hash == pinned_hash   (all 32 bytes)

THE POINT (the layer-1-UI / PWA boot-blob story, Xahau discussion #759). An on-chain bootloader is
the root of trust for a Hook's UI: it fetches a larger stage-2 app from anywhere and must run it
ONLY if the bytes hash to the pinned value. The loader's go/no-go decision is a small, bounded gate
— exactly the shape this engine proves. We model that gate as an accept-decision over two 32-byte
inputs:
  PIN — the pinned SHA-512Half the policy fixes,
  CAN — the candidate hash the wallet computed over the fetched stage-2 bytes,
and prove the gate ACCEPTS (hands control to stage-2) ONLY when all 32 bytes match. A loader that
satisfies this cannot be tricked into executing unverified code:
  prove(Hook) + prove(bootloader)  =  the whole app's trust base is formally verified, UI included.

SCOPE (honest): we prove the verify GATE's accept condition over the candidate/pinned hashes. The
actual SHA-512Half of the fetched bundle is computed wallet-side and fed in as CAN; this proof
guarantees the gate's go/no-go is sound (never "go" on a hash != pin), not that the wallet hashes
correctly. Same byte-exact-equality discipline as the guardrail's dst-lock (20 bytes), here 32.

Fail-closed: solver `unknown` / unsupported opcode / hit unroll bound => INCONCLUSIVE, never PROVEN.

Usage: python prove_bootloader.py <hook.wasm>
Exit 0 = PROVEN, 2 = COUNTEREXAMPLE, 3 = INCONCLUSIVE, 1 = N/A.
"""
import sys
import z3
from prover import Engine

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

    if e.unsupported:
        print(f"\n⚠️ INCONCLUSIVE — unsupported opcode(s) {sorted(e.unsupported)} reached; not PROVEN.")
        return 3
    if e.hit_bound:
        print("\n⚠️ INCONCLUSIVE — a loop exceeded the unroll bound; not PROVEN.")
        return 3

    print("\n✅ PROVEN — for ALL inputs, the loader accepts (hands control to stage-2) ONLY when the "
          "candidate hash equals the pinned hash, all 32 bytes. It cannot be tricked into running "
          "unverified code. (SCOPE: proves the verify gate's accept condition; the wallet supplies "
          "CAN = SHA-512Half(fetched bytes).)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
