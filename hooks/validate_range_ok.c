#include "xahc/xahc.h"
/* SC04 reference: param VAL must be present AND within the declared [LO, HI] bounds.
 * Checks presence (REQUIRE) + BOTH bounds before accepting -> PROVEN. */
static inline uint64_t be64(const uint8_t* b){
    return ((uint64_t)b[0]<<56)|((uint64_t)b[1]<<48)|((uint64_t)b[2]<<40)|((uint64_t)b[3]<<32)|
           ((uint64_t)b[4]<<24)|((uint64_t)b[5]<<16)|((uint64_t)b[6]<<8)|((uint64_t)b[7]);
}
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t vk[3]={'V','A','L'}, lk[3]={'L','O','_'}, hk[3]={'H','I','_'};
    uint8_t vb[8], lb[8], hb[8];
    XAHC_HOOK_PARAM_REQUIRE(vb, vk, 8);
    XAHC_HOOK_PARAM_REQUIRE(lb, lk, 8);
    XAHC_HOOK_PARAM_REQUIRE(hb, hk, 8);
    uint64_t val=be64(vb), lo=be64(lb), hi=be64(hb);
    XAHC_REQUIRE(val >= lo, "below declared min");
    XAHC_REQUIRE(val <= hi, "above declared max");
    XAHC_ACCEPT("in declared range");
    return 0;
}
