#include "xahc/xahc.h"
#include "xahc/emit/payment.h"
int64_t cbak(uint32_t r){return 0;}
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t dk[3]={'D','S','T'}, dst[20];
    XAHC_HOOK_PARAM_REQUIRE(dst, dk, 20);
    XAHC_EMIT_PAYMENT(dst, 1000, 0, 0);     /* emit ONLY to the locked DST */
    XAHC_ACCEPT("paid locked dest");
    return 0;
}
