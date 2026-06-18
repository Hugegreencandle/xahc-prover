"""Prove BOOT-UPGRADE SAFETY — the bootloader's pinned hash can only be changed by an authorized
key, and only forward (no downgrade to an older, possibly-vulnerable stage-2).

  for all inputs:  accept (re-pin)  =>  origin == owner          (authorized)
                                    AND  new_version > old_version (monotonic; no downgrade/replay)

CONTEXT. `prove_bootloader` proves the GATE ("accept only on a matching hash"). This proves the
UPGRADE path that changes what's pinned: the on-chain re-pin of the bootloader's stage-2 hash. Two
ways an upgrade path is unsafe — both are catastrophic for a boot root-of-trust:
  (1) NO AUTHORIZATION — anyone can re-pin -> an attacker swaps the app the wallet will boot.
  (2) DOWNGRADE/REPLAY — re-pin to an OLDER pinned hash + version -> roll the boot target back to a
      known-vulnerable stage-2. Monotonic version (strictly increasing) forbids it.
This is the natural completion of the bootloader story (Xahau discussion #759): the gate proves
"boot only the pinned blob"; this proves "only the owner can change the pin, and only forward."

MODEL. The re-pin hook persists state slot 0x01 = [version:u64 | hash:32] (40 bytes). It reads the
originating account (sfAccount -> "origin") + the hook account (hook_account -> "owner"/"hookacc"),
and the prior [version|hash] from state. We prove, on EVERY accepting path that persists the slot:
  A (authz):     cons & (origin != owner)            UNSAT   — else COUNTEREXAMPLE (unauthorized re-pin)
  B (monotonic): cons & (new_version <= old_version)  UNSAT   — else COUNTEREXAMPLE (downgrade/replay)
The version is the first 8 bytes of the slot (field 01:0:8). Both obligations must hold; a hook that
passes one on some path and the other on another is NOT proven — both are checked on every re-pin.

SCOPE / out of model (do NOT overclaim): same trust boundary as prove_bootloader — the on-chain
SetBoot stores the blob verbatim and the node verifies nothing; the wallet's hash + the version
encoding fed in here are trusted. This proves the re-pin GATE's accept logic, not the boot chain
end to end.

Fail closed: solver `unknown` / unsupported / hit bound -> INCONCLUSIVE. No re-pin accept path -> N/A
(vacuity_guard), never a vacuous PROVEN.

Usage: python prove_boot_upgrade.py <hook.wasm>
Exit 0 = PROVEN, 1 = N/A, 2 = COUNTEREXAMPLE, 3 = INCONCLUSIVE.
"""
import sys
import z3
from prover import Engine, feasible
from soundness import unsound_gate, vacuity_guard
from field import parse_field, bv_byte_slice

SLOT = "\x01"          # [version:u64 | hash:32]
VER = parse_field("01:0:8")   # the version sub-field (first 8 bytes, big-endian)


def main(path: str) -> int:
    e = Engine(open(path, "rb").read())
    # FAIL CLOSED on an engine error: an uncaught exception (e.g. a symbolic guard-id) must map to
    # INCONCLUSIVE (3), NOT crash out with exit 1 — which aliases the N/A code an orchestrator keys
    # on. [audit FP-BOOT-03] A crash can never be a PROVEN, but it must not masquerade as N/A.
    try:
        e.run()
    except Exception as ex:  # noqa: BLE001
        print(f"\n⚠️ INCONCLUSIVE — the engine could not analyze the hook "
              f"({type(ex).__name__}: {str(ex)[:140]}); could not prove. Not PROVEN.")
        return 3

    origin = e.inputs.get("origin")
    owner = e.inputs.get("hookacc")

    repins = [(c, cons, w) for (c, cons, w) in e.accepts_full if SLOT in w]
    all_keys = sorted({f"0x{ord(k):02x}" for _, _, w in e.accepts_full for k in w})
    print(f"explored: {len(e.accepts_full)} accepting path(s); {len(repins)} persist the boot slot "
          f"0x{ord(SLOT):02x} [version|hash]")
    if not repins:
        # SCOPE: this invariant assumes the boot blob is pinned under slot 0x01. Name the slots the
        # hook ACTUALLY persisted so an operator can confirm the convention matches their bootloader
        # (a re-pin under a different key is NOT analyzed here). [audit FP-BOOT-02]
        print(f"N/A — no accepting path re-pins the boot slot 0x{ord(SLOT):02x}; the upgrade-"
              f"authorization property is not exercised. Not claimed. (Slots this hook writes on "
              f"accept: {all_keys or 'none'} — if your bootloader pins under a different key, this "
              "invariant does not cover it.)")
        return 1
    # A hook that RE-PINS but never reads BOTH sfAccount (origin) and hook_account (owner) cannot be
    # gating the re-pin on authorization at all — it accepts a pin change with no owner check. That
    # is an UNAUTHORIZED re-pin (COUNTEREXAMPLE), not an un-exercised property (N/A). [fail toward
    # flagging the danger, not silently sidelining it.]
    if not origin or not owner:
        print("\n❌ COUNTEREXAMPLE — the hook re-pins the boot slot WITHOUT reading the originating "
              "account / hook owner: the pinned boot hash can be changed with NO authorization "
              "check. Unauthorized upgrade.")
        return 2
    not_owner = z3.Or(*[origin[i] != owner[i] for i in range(20)])

    n_checked = 0
    for code, cons, writes in repins:
        if not feasible(cons):
            continue
        wval = writes[SLOT]
        old_bytes = e.state_old.get(SLOT)
        if not old_bytes:
            print("\n❌ COUNTEREXAMPLE — accept re-pins the boot slot WITHOUT reading its prior "
                  "value: version is overwritten with no regard to the old version (a downgrade or "
                  "replay is unconstrained).")
            return 2
        old = z3.Concat(*old_bytes) if len(old_bytes) > 1 else old_bytes[0]
        if old.size() != wval.size():
            print(f"\n⚠️ INCONCLUSIVE — re-pin write is {wval.size() // 8}B but prior read was "
                  f"{old.size() // 8}B; not comparable. Not PROVEN.")
            return 3
        try:
            new_ver = bv_byte_slice(wval, VER.off, VER.length)
            old_ver = bv_byte_slice(old, VER.off, VER.length)
        except ValueError as ex:
            print(f"\n⚠️ INCONCLUSIVE — {ex}; cannot read the version field. Not PROVEN.")
            return 3
        n_checked += 1

        # A — authorization: an accepting re-pin by a non-owner.
        s = z3.Solver(); s.add(*cons); s.add(not_owner)
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE — solver `unknown` on the authorization query. Not PROVEN.")
            return 3
        if r == z3.sat:
            print("\n❌ COUNTEREXAMPLE — the hook ACCEPTS a re-pin from a NON-OWNER account: anyone "
                  "can change the pinned boot hash (unauthorized upgrade).")
            return 2

        # B — monotonic version: an accepting re-pin that does not strictly advance the version.
        s = z3.Solver(); s.add(*cons); s.add(z3.ULE(new_ver, old_ver))
        r = s.check()
        if r == z3.unknown:
            print("\n⚠️ INCONCLUSIVE — solver `unknown` on the version-monotonic query. Not PROVEN.")
            return 3
        if r == z3.sat:
            m = s.model(); ev = lambda b: m.eval(b, model_completion=True).as_long()
            print("\n❌ COUNTEREXAMPLE — the hook ACCEPTS a re-pin that does NOT advance the version "
                  "(downgrade / replay to an older pinned hash):")
            print(f"   new version = {ev(new_ver)}   old version = {ev(old_ver)}  (new <= old)")
            return 2

    code = unsound_gate(e)
    if code is not None:
        return code
    code = vacuity_guard(n_checked, "boot-upgrade safety (no accepting path re-pins the boot slot)")
    if code is not None:
        return code

    print("\n✅ PROVEN — for ALL inputs, the bootloader's pinned hash is re-pinned ONLY by the owner "
          "AND only with a strictly greater version (no downgrade/replay to an older stage-2). "
          "(SCOPE: the re-pin gate's accept logic; the on-chain SetBoot stores the blob verbatim and "
          "the node verifies nothing — the hash + version encoding are trusted, per prove_bootloader.)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
