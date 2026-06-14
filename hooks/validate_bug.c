#include "xahc/xahc.h"

/* BUGGY input validation — reads hook_param(LIM) but IGNORES the return value, then
 * accepts. When LIM is absent the host returns a negative code and `lim` holds garbage,
 * yet the hook proceeds (fail-OPEN). The prover should find an accept path where the
 * param is absent. */

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    uint8_t key[3] = { 'L', 'I', 'M' };
    uint8_t lim[8];
    hook_param(XAHC_SBUF(lim), XAHC_SBUF(key));   /* BUG: return value ignored */

    XAHC_ACCEPT("accepted regardless of param presence");
    return 0;
}
