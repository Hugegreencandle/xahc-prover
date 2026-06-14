#include "xahc/xahc.h"
/* ADVERSARIAL (soundness attack): on an incoming native payment, emit HALF the
 * drops onward (native — conserves on the native axis) AND ALSO emit 1.5 USD as
 * an issued (IOU) amount (pure value creation). The native-conservation check
 * alone would see only `drops/2 <= drops` and could FALSELY prove. The IOU emit
 * MUST force the conservation driver to INCONCLUSIVE (fail closed), never PROVEN.
 */
static const uint8_t DST[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved) {
    XAHC_HOOK_ENTRY();
    if (otxn_type() != XAHC_ttPAYMENT) XAHC_ACCEPT("nonpay");
    int64_t drops = xahc_otxn_drops();
    XAHC_REQUIRE(drops >= 0, "native only");

    /* native emit: forward half (conserves on the native axis) */
    XAHC_EMIT_PAYMENT(DST, (uint64_t)drops / 2, 0, 0);

    /* IOU emit: 1.5 USD out of thin air (value creation the native check misses) */
    uint8_t cur[20];
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i) cur[i] = 0;
    cur[12] = 'U'; cur[13] = 'S'; cur[14] = 'D';
    uint8_t iss[20];
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i) iss[i] = 0xCC;
    int64_t xfl = float_set(-1, 15);   /* 1.5 */
    XAHC_EMIT_PAYMENT_IOU(DST, xfl, cur, iss, 0, 0);

    XAHC_ACCEPT("forwarded half + minted iou");
    return 0;
}
