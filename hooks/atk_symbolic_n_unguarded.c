#include "xahc/xahc.h"
/* ATTACK 2a: attacker-controlled reserve count, UNGUARDED. Read a hook param 'N'
 * (1 byte) and reserve THAT many, then unconditionally emit 3. Since N is
 * unconstrained (0..255), emit_count(3) > N is feasible (e.g. N=0,1,2) =>
 * MUST be COUNTEREXAMPLE. A false PROVEN here would be catastrophic. No cbak. */
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
    hook_param((uint32_t)nbuf, 1, (uint32_t)key, 1);   /* symbolic byte */
    uint32_t n = (uint32_t)nbuf[0];
    XAHC_TRY(etxn_reserve(n));                           /* reserve symbolic n */
    emit_one(1);
    emit_one(1);
    emit_one(1);                                         /* 3 emits, n unconstrained */
    XAHC_ACCEPT("unguarded symbolic reserve");
    return 0;
}
