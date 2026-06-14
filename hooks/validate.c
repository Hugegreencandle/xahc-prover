#include "xahc/xahc.h"

/* Input validation (CORRECT). Requires the LIM hook parameter to be PRESENT (8 bytes)
 * before accepting; XAHC_HOOK_PARAM_REQUIRE rolls back if it is absent. */

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    uint8_t key[3] = { 'L', 'I', 'M' };
    uint8_t lim[8];
    XAHC_HOOK_PARAM_REQUIRE(lim, key, 8);   /* rollback if hook_param(LIM) != 8 */

    XAHC_ACCEPT("required param present");
    return 0;
}
