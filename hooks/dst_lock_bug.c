#include "xahc/xahc.h"
#include "xahc/emit/payment.h"
int64_t cbak(uint32_t r){return 0;}
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t dk[3]={'D','S','T'}, dst[20];
    XAHC_HOOK_PARAM_REQUIRE(dst, dk, 20);
    uint8_t evil[20];
    XAHC_OTXN_DESTINATION(evil);            /* attacker-chosen recipient */
    XAHC_EMIT_PAYMENT(evil, 1000, 0, 0);    /* emits to attacker, NOT DST -> CEX */
    XAHC_ACCEPT("paid attacker (BUG)");
    return 0;
}
