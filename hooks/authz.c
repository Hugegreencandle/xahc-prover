#include "xahc/xahc.h"

/* Owner-only action gate (CORRECT). Only the hook's own account may trigger an accept;
 * any other originating account is rolled back. */

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    uint8_t origin[20], me[20];
    XAHC_OTXN_ACCOUNT(origin);
    hook_account(XAHC_SBUF(me));

    int ok = 1;
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i)
        if (origin[i] != me[i]) ok = 0;
    XAHC_REQUIRE(ok, "not the owner");

    XAHC_ACCEPT("owner authorized");
    return 0;
}
