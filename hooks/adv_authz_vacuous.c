#include "xahc/xahc.h"
int64_t cbak(uint32_t reserved) { return 0; }
int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();
    uint8_t origin[20], me[20];
    XAHC_OTXN_ACCOUNT(origin);
    hook_account(XAHC_SBUF(me));
    /* reads both, but ALWAYS rolls back — no accept path exists */
    XAHC_REQUIRE(0, "always reject");
    XAHC_ACCEPT("never reached");
    return 0;
}
