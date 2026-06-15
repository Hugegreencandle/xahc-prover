#include "xahc/xahc.h"
static const uint8_t DST[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
static void emit_one(uint64_t drops) {
    uint8_t tx[XAHC_PAYMENT_SIZE];
    uint32_t len = xahc_build_payment(tx, DST, drops, 0, 0);
    XAHC_TRY(emit(0, 0, (uint32_t)tx, len));
}
int64_t hook(uint32_t reserved) {
    XAHC_HOOK_ENTRY();
    etxn_reserve(1);   /* FIRST binds budget = 1 */
    etxn_reserve(5);   /* SECOND -> -8 ALREADY_SET, binds nothing (budget stays 1) */
    emit_one(1);
    emit_one(1);
    emit_one(1);       /* 3 emits vs binding budget 1 => -13 */
    XAHC_ACCEPT("double reserve, first smaller");
    return 0;
}
