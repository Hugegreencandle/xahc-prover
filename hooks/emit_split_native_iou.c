#include "xahc/xahc.h"
/* ADVERSARIAL (soundness attack, per-path split): two accepting paths.
 *   path A (drops even): clean native forward of half — conserves.
 *   path B (drops odd) : emit 1.5 USD IOU out of thin air — value creation.
 * If the driver decided per-path and proved path A while skipping the IOU on
 * path B, that would be a false PROVEN. The IOU emit on ANY accepting path must
 * force the whole verdict to INCONCLUSIVE.
 */
static const uint8_t DST[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved) {
    XAHC_HOOK_ENTRY();
    if (otxn_type() != XAHC_ttPAYMENT) XAHC_ACCEPT("nonpay");
    int64_t drops = xahc_otxn_drops();
    XAHC_REQUIRE(drops >= 0, "native only");

    if ((drops & 1) == 0) {
        /* even: clean native forward (conserves) */
        XAHC_EMIT_PAYMENT(DST, (uint64_t)drops / 2, 0, 0);
        XAHC_ACCEPT("native half");
    }

    /* odd: mint an IOU from nothing */
    uint8_t cur[20];
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i) cur[i] = 0;
    cur[12] = 'U'; cur[13] = 'S'; cur[14] = 'D';
    uint8_t iss[20];
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i) iss[i] = 0xCC;
    int64_t xfl = float_set(-1, 15);   /* 1.5 */
    XAHC_EMIT_PAYMENT_IOU(DST, xfl, cur, iss, 0, 0);
    XAHC_ACCEPT("minted iou");
    return 0;
}
