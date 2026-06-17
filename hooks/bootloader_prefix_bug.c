#include "xahc/xahc.h"
/* NEGATIVE CONTROL: compares only the first 4 bytes of the hash -> accepts a bundle whose hash
 * merely shares a prefix with the pin (a forgeable collision). Must -> COUNTEREXAMPLE. */
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t pk[3]={'P','I','N'}, ck[3]={'C','A','N'};
    uint8_t pin[32], can[32];
    XAHC_HOOK_PARAM_REQUIRE(pin, pk, 32);
    XAHC_HOOK_PARAM_REQUIRE(can, ck, 32);
    int ok = 1;
    for (int i = 0; XAHC_GUARD(4), i < 4; ++i)   /* BUG: only 4 of 32 bytes */
        if (pin[i] != can[i]) ok = 0;
    XAHC_REQUIRE(ok, "prefix match (BUG)");
    XAHC_ACCEPT("accepted on 4-byte prefix");
    return 0;
}
