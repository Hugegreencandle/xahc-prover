#include "xahc/xahc.h"
int64_t cbak(uint32_t reserved) { return 0; }
int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();
    uint8_t origin[20], me[20];
    XAHC_OTXN_ACCOUNT(origin);
    hook_account(XAHC_SBUF(me));
    int ok = 1;
    /* BUG: only compares the first 4 bytes of the 20-byte account */
    for (int i = 0; XAHC_GUARD(4), i < 4; ++i)
        if (origin[i] != me[i]) ok = 0;
    XAHC_REQUIRE(ok, "not the owner (prefix only)");
    XAHC_ACCEPT("owner authorized");
    return 0;
}
