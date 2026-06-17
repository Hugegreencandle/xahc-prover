#include "xahc/xahc.h"
/* NEGATIVE CONTROL: never checks the hash at all -> runs ANY stage-2. Must -> COUNTEREXAMPLE. */
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t pk[3]={'P','I','N'}, ck[3]={'C','A','N'};
    uint8_t pin[32], can[32];
    XAHC_HOOK_PARAM_REQUIRE(pin, pk, 32);
    XAHC_HOOK_PARAM_REQUIRE(can, ck, 32);
    XAHC_ACCEPT("accepted without verifying (BUG)");
    return 0;
}
