#include "xahc/xahc.h"
int64_t cbak(uint32_t reserved) { return 0; }
int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();
    uint8_t key[3] = { 'L','I','M' };
    uint8_t lim[8];
    int64_t r = hook_param(XAHC_SBUF(lim), XAHC_SBUF(key));
    /* BUG: cast the (possibly negative) return to uint32 then check > 0.
       A negative int64 ret has nonzero low-32 bits, so (uint32_t)r could be huge>0,
       passing this guard while the param is actually ABSENT. */
    if ((uint32_t)r > 0) {
        XAHC_ACCEPT("param 'present' via unsigned-cast bug");
    }
    XAHC_REQUIRE(0, "absent");
    return 0;
}
