#include "xahc/xahc.h"
/* ADVERSARIAL (parser-confusion attack on IOU classification): emit a PURE IOU
 * payment whose 20-byte currency code has byte[0] == 0x68. In the on-ledger emit
 * blob the currency's first byte lands at offset 44 — the exact byte the engine's
 * native/IOU classifier uses (native iff byte44 == 0x68 == sfFee header). If the
 * classifier is fooled, it will read this IOU as a NATIVE payment, parse the
 * XFL value word as "drops", skip the iou_emitting guard, and potentially PROVE
 * native conservation while real IOU value is created. The driver MUST still
 * fail closed (never PROVEN) on this hook.
 *
 * No incoming native amount is read -> if misclassified as native, the driver
 * either errors (no amount) or proves vacuously; either way PROVEN(0) here = a
 * soundness break.
 */
int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved) {
    XAHC_HOOK_ENTRY();
    if (otxn_type() != XAHC_ttPAYMENT) XAHC_ACCEPT("nonpay");

    uint8_t cur[20];
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i) cur[i] = 0;
    cur[0]  = 0x68;          /* collide with sfFee header byte at offset 44 */
    cur[12] = 'X'; cur[13] = 'X'; cur[14] = 'X';
    uint8_t iss[20];
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i) iss[i] = 0xCC;
    uint8_t dst[20];
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i) dst[i] = 0xBB;

    int64_t xfl = float_set(0, 1000000000000000LL);  /* 1.0 (1e15 x 10^0) */
    XAHC_EMIT_PAYMENT_IOU(dst, xfl, cur, iss, 0, 0);

    XAHC_ACCEPT("minted iou with colliding currency");
    return 0;
}
