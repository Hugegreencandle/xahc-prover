#include "xahc/xahc.h"
static const uint8_t DST[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
static void emit_one(uint64_t d){uint8_t tx[XAHC_PAYMENT_SIZE];uint32_t l=xahc_build_payment(tx,DST,d,0,0);XAHC_TRY(emit(0,0,(uint32_t)tx,l));}
int64_t hook(uint32_t reserved){
    XAHC_HOOK_ENTRY();
    XAHC_TRY(etxn_reserve(2));
    int64_t drops = xahc_otxn_drops();
    XAHC_REQUIRE(drops >= 0, "native");
    /* symbolic trip count derived from drops; guard allows many iterations */
    uint32_t k = (uint32_t)((uint64_t)drops & 0xFF);   /* 0..255, symbolic */
    for (uint32_t i = 0; _g(1, 300), i < k; i++) {
        emit_one(1);    /* could emit up to 255 times, budget only 2 */
    }
    XAHC_ACCEPT("loop emit symbolic count");
    return 0;
}
