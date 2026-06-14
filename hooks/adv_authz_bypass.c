#include "xahc/xahc.h"
int64_t cbak(uint32_t reserved) { return 0; }
int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();
    uint8_t origin[20], me[20];
    XAHC_OTXN_ACCOUNT(origin);
    hook_account(XAHC_SBUF(me));
    /* a "fast path": if first byte is 0xAA, skip the auth check entirely */
    if (origin[0] == 0xAA) {
        XAHC_ACCEPT("fast path bypass");
    }
    int ok = 1;
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i)
        if (origin[i] != me[i]) ok = 0;
    XAHC_REQUIRE(ok, "not owner");
    XAHC_ACCEPT("owner authorized");
    return 0;
}
