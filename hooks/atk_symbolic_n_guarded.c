#include "xahc/xahc.h"
/* ATTACK 2b: attacker-controlled reserve count, PROPERLY GUARDED. Read param 'N',
 * REQUIRE n >= 3 before emitting, then reserve n and emit 3. On every accept path
 * n >= 3 >= emit_count => MUST be PROVEN (correct). Tests we don't falsely CEX a
 * safe symbolic-n hook AND don't vacuously PROVEN. No cbak. */
static const uint8_t DST[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
static void emit_one(uint64_t drops) {
    uint8_t tx[XAHC_PAYMENT_SIZE];
    uint32_t len = xahc_build_payment(tx, DST, drops, 0, 0);
    XAHC_TRY(emit(0, 0, (uint32_t)tx, len));
}
int64_t hook(uint32_t reserved) {
    XAHC_HOOK_ENTRY();
    uint8_t key[1] = { 'N' };
    uint8_t nbuf[1] = { 0 };
    hook_param((uint32_t)nbuf, 1, (uint32_t)key, 1);
    uint32_t n = (uint32_t)nbuf[0];
    XAHC_REQUIRE(n >= 3, "need budget >= 3");           /* guard: n >= emit_count */
    XAHC_TRY(etxn_reserve(n));
    emit_one(1);
    emit_one(1);
    emit_one(1);
    XAHC_ACCEPT("guarded symbolic reserve");
    return 0;
}
