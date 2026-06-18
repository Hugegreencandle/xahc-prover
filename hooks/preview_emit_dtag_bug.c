#include "xahc/xahc.h"
#include "xahc/emit/payment.h"
extern int64_t ledger_last_time(void);
int64_t cbak(uint32_t r){return 0;}
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t dst[20]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
    XAHC_EMIT_PAYMENT(dst, 1000, (uint32_t)ledger_last_time(), 0);   /* dest tag from entropy (BUG) */
    XAHC_ACCEPT("emit entropy dtag");
    return 0;
}
