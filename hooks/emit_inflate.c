#include "xahc/xahc.h"
static const uint8_t DST[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
int64_t cbak(uint32_t reserved) { return 0; }
/* BUG (value creation): emits MORE than it received. Breaks balance conservation. */
int64_t hook(uint32_t reserved) {
    XAHC_HOOK_ENTRY();
    if (otxn_type() != XAHC_ttPAYMENT) XAHC_ACCEPT("nonpay");
    int64_t drops = xahc_otxn_drops();
    XAHC_REQUIRE(drops >= 0, "native only");
    XAHC_EMIT_PAYMENT(DST, (uint64_t)drops + 1000000, 0, 0);
    XAHC_ACCEPT("over-forwarded");
    return 0;
}
