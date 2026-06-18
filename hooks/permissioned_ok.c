#include "xahc/xahc.h"
/* Permissioned transfer (strict gate): accept ONLY a Payment to the allowlisted counterparty ALW.
 * Non-payments are rolled back, so EVERY accept is an authorized transfer. */
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    XAHC_REQUIRE(otxn_type() == XAHC_ttPAYMENT, "payments only");
    uint8_t ak[3]={'A','L','W'}, alw[20];
    XAHC_HOOK_PARAM_REQUIRE(alw, ak, 20);
    uint8_t dest[20];
    XAHC_OTXN_DESTINATION(dest);
    for (int i=0; XAHC_GUARD(20), i<20; ++i)
        XAHC_REQUIRE(dest[i]==alw[i], "destination not authorized");   /* full 20-byte allowlist gate */
    XAHC_ACCEPT("authorized counterparty");
    return 0;
}
