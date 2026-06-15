#include "xahc/xahc.h"
/* ATTACK 1b: emit WITHOUT ever calling etxn_reserve. reserved_n = None (budget 0),
 * emit_count = 1 > 0 => MUST be COUNTEREXAMPLE (runtime -13). No cbak. */
static const uint8_t DST[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
int64_t hook(uint32_t reserved) {
    XAHC_HOOK_ENTRY();
    int64_t drops = xahc_otxn_drops();
    XAHC_REQUIRE(drops >= 0, "native only");
    uint8_t tx[XAHC_PAYMENT_SIZE];
    uint32_t len = xahc_build_payment(tx, DST, (uint64_t)drops / 2, 0, 0);
    XAHC_TRY(emit(0, 0, (uint32_t)tx, len));   /* never reserved */
    XAHC_ACCEPT("emit with no reserve");
    return 0;
}
