#include "xahc/xahc.h"
int64_t cbak(uint32_t reserved) { return 0; }
int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();
    uint8_t key[3] = { 'L','I','M' };
    uint8_t lim[8];
    int64_t r = hook_param(XAHC_SBUF(lim), XAHC_SBUF(key));
    if (r == 8) {            /* correct signed presence check */
        XAHC_ACCEPT("present");
    }
    XAHC_REQUIRE(0, "absent");
    return 0;
}
