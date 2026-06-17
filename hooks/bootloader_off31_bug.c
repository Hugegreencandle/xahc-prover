#include "xahc/xahc.h"
/* NEGATIVE CONTROL (off-by-one): compares only bytes 0..30, leaving byte 31 UNCHECKED.
 * A candidate matching the first 31 bytes but differing at byte 31 is still accepted.
 * Must -> COUNTEREXAMPLE. This is the soundness control for the driver's negation covering
 * the LAST byte: if prove_bootloader looped range(31) instead of range(32), this would
 * falsely PROVE. */
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t pk[3]={'P','I','N'}, ck[3]={'C','A','N'};
    uint8_t pin[32], can[32];
    XAHC_HOOK_PARAM_REQUIRE(pin, pk, 32);
    XAHC_HOOK_PARAM_REQUIRE(can, ck, 32);
    int ok = 1;
    for (int i = 0; XAHC_GUARD(31), i < 31; ++i)   /* BUG: 31 not 32 — byte 31 unchecked */
        if (pin[i] != can[i]) ok = 0;
    XAHC_REQUIRE(ok, "first-31-bytes match (BUG)");
    XAHC_ACCEPT("accepted ignoring byte 31");
    return 0;
}
