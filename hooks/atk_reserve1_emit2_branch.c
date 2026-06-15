#include "xahc/xahc.h"
/* ATTACK 1c: conditional over-emit. Reserve 1. On the payment branch emit TWICE.
 * On the non-payment branch emit zero. The payment-branch accept path has
 * emit_count(2) > reserved(1) => MUST be COUNTEREXAMPLE. No cbak. */
static const uint8_t DST[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
static void emit_one(uint64_t drops) {
    uint8_t tx[XAHC_PAYMENT_SIZE];
    uint32_t len = xahc_build_payment(tx, DST, drops, 0, 0);
    XAHC_TRY(emit(0, 0, (uint32_t)tx, len));
}
int64_t hook(uint32_t reserved) {
    XAHC_HOOK_ENTRY();
    XAHC_TRY(etxn_reserve(1));
    int64_t drops = xahc_otxn_drops();
    if (drops >= 0) {
        emit_one((uint64_t)drops / 4);
        emit_one((uint64_t)drops / 4);   /* over budget on this branch */
        XAHC_ACCEPT("paid path over-emit");
    }
    XAHC_ACCEPT("non-pay no emit");
    return 0;
}
