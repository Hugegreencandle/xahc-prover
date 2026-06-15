#include "xahc/xahc.h"
static const uint8_t DST[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
int64_t cbak(uint32_t reserved){ return 0; }
static void emit_one(uint64_t d){uint8_t tx[XAHC_PAYMENT_SIZE];uint32_t l=xahc_build_payment(tx,DST,d,0,0);XAHC_TRY(emit(0,0,(uint32_t)tx,l));}
int64_t hook(uint32_t reserved){
    XAHC_HOOK_ENTRY();
    XAHC_TRY(etxn_reserve(1));
    emit_one(1); emit_one(1); emit_one(1);
    XAHC_ACCEPT("cbak + over-emit");
    return 0;
}
