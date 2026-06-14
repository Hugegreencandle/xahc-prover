#include "xahc/xahc.h"

/* BUGGY arithmetic — accepts when (incoming drops + TIP) <= LIM, but `drops + tip` can
 * WRAP uint64. A near-MAX tip wraps the sum to a small number that passes the limit check,
 * letting an effectively over-limit payment through. The prover should find the wrapping
 * input. */

int64_t cbak(uint32_t reserved) { return 0; }

static uint64_t be8(const uint8_t* b) {
    return ((uint64_t)b[0]<<56)|((uint64_t)b[1]<<48)|((uint64_t)b[2]<<40)|((uint64_t)b[3]<<32)|
           ((uint64_t)b[4]<<24)|((uint64_t)b[5]<<16)|((uint64_t)b[6]<<8)|((uint64_t)b[7]);
}

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    int64_t d = xahc_otxn_drops();
    XAHC_REQUIRE(d >= 0, "native only");
    uint64_t drops = (uint64_t)d;

    uint8_t tk[3] = { 'T','I','P' }, tb[8]; XAHC_HOOK_PARAM_REQUIRE(tb, tk, 8);
    uint8_t lk[3] = { 'L','I','M' }, lb[8]; XAHC_HOOK_PARAM_REQUIRE(lb, lk, 8);
    uint64_t tip = be8(tb), lim = be8(lb);

    uint64_t total = drops + tip;                 /* BUG: no overflow guard */
    XAHC_REQUIRE(total <= lim, "over per-tx limit");

    XAHC_ACCEPT("within limit");
    return 0;
}
