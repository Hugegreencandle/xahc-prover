#include "xahc/xahc.h"
static const uint8_t DST[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
/* cbak that does NOT emit — statically harmless, but engine cannot model re-entry. */
int64_t cbak(uint32_t reserved) { return 0; }
int64_t hook(uint32_t reserved) {
    XAHC_HOOK_ENTRY();
    XAHC_TRY(etxn_reserve(1));
    int64_t drops = xahc_otxn_drops();
    XAHC_REQUIRE(drops >= 0, "native only");
    uint8_t tx[XAHC_PAYMENT_SIZE];
    uint32_t len = xahc_build_payment(tx, DST, (uint64_t)drops / 2, 0, 0);
    XAHC_TRY(emit(0, 0, (uint32_t)tx, len));   /* 1 emit, budget 1: statically OK */
    XAHC_ACCEPT("safe cbak emitter");
    return 0;
}
