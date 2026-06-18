#include "xahc/xahc.h"
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    XAHC_REQUIRE(otxn_type() == XAHC_ttPAYMENT, "payments only");
    uint8_t ak[3]={'A','L','W'}, alw[20];
    XAHC_HOOK_PARAM_REQUIRE(alw, ak, 20);
    uint8_t dest[20];
    XAHC_OTXN_DESTINATION(dest);
    /* enforcement removed (BUG): accepts ANY destination */
    XAHC_ACCEPT("any dest (BUG)");
    return 0;
}
