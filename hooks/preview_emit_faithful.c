#include "xahc/xahc.h"
#include "xahc/emit/payment.h"
int64_t cbak(uint32_t r){return 0;}
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t dst[20]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
    XAHC_EMIT_PAYMENT(dst, 1000, 0, 0);   /* routing fields all fixed -> faithful */
    XAHC_ACCEPT("emit faithful");
    return 0;
}
