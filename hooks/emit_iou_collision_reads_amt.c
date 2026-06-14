#include "xahc/xahc.h"
/* ADVERSARIAL (the SHARP version): read incoming native drops (so the driver
 * does NOT bail with "never reads sfAmount"), require drops large, then emit a
 * PURE IOU whose currency[0]==0x68 collides with the sfFee header at offset 44.
 * If the classifier is fooled into reading the IOU as native, it parses the XFL
 * value word as "drops"; we pick an XFL whose masked value word is SMALL so the
 * bogus native total is <= incoming -> a FALSE PROVEN while real IOU value is
 * minted. PROVEN(0) here is a soundness break.
 */
int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved) {
    XAHC_HOOK_ENTRY();
    if (otxn_type() != XAHC_ttPAYMENT) XAHC_ACCEPT("nonpay");
    int64_t drops = xahc_otxn_drops();          /* read incoming native amount */
    XAHC_REQUIRE(drops >= 0, "native only");

    uint8_t cur[20];
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i) cur[i] = 0;
    cur[0]  = 0x68;          /* collide with sfFee header byte at offset 44 */
    cur[12] = 'X'; cur[13] = 'X'; cur[14] = 'X';
    uint8_t iss[20];
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i) iss[i] = 0xCC;
    uint8_t dst[20];
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i) dst[i] = 0xBB;

    /* float_set(-15, 1000000000000000) = 1.0 ; the serialized XFL word is large,
     * but choose a tiny magnitude so masked low bytes look like small drops. */
    int64_t xfl = float_set(-80, 1000000000000000LL);  /* 1e-65, tiny */
    XAHC_EMIT_PAYMENT_IOU(dst, xfl, cur, iss, 0, 0);

    XAHC_ACCEPT("minted tiny iou, colliding currency, after reading amt");
    return 0;
}
