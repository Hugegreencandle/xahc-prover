#include "xahc/xahc.h"
static const uint8_t DST[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
static void emit_one(uint64_t d){uint8_t tx[XAHC_PAYMENT_SIZE];uint32_t l=xahc_build_payment(tx,DST,d,0,0);XAHC_TRY(emit(0,0,(uint32_t)tx,l));}
int64_t hook(uint32_t reserved){
    XAHC_HOOK_ENTRY();
    uint8_t key[1]={'N'}; uint8_t nb[4]={0,0,0,0};
    hook_param((uint32_t)nb,4,(uint32_t)key,1);
    int32_t n = (int32_t)((uint32_t)nb[0] | ((uint32_t)nb[1]<<8) | ((uint32_t)nb[2]<<16) | ((uint32_t)nb[3]<<24));
    XAHC_REQUIRE(n >= 3, "signed >=3");      /* SIGNED guard */
    XAHC_TRY(etxn_reserve((uint32_t)n));      /* reserve as unsigned */
    emit_one(1); emit_one(1); emit_one(1);
    XAHC_ACCEPT("signed-guarded reserve");
    return 0;
}
