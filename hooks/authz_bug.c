#include "xahc/xahc.h"

/* BUGGY authorization — reads both accounts but NEVER enforces origin == owner, so any
 * account can trigger the privileged accept. The prover should return an attacker
 * originating account != owner. */

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    uint8_t origin[20], me[20];
    XAHC_OTXN_ACCOUNT(origin);
    hook_account(XAHC_SBUF(me));
    /* BUG: missing  XAHC_REQUIRE(origin == me, "not the owner");  */

    XAHC_ACCEPT("accepted (no auth check!)");
    return 0;
}
