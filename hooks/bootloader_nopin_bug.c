#include "xahc/xahc.h"
/* NEGATIVE CONTROL (absent pin): never reads/requires PIN at all — accepts any candidate.
 * A loader with no pinned hash trusts whatever bytes it's handed. Must -> COUNTEREXAMPLE
 * OR N/A (driver must NOT report PROVEN). Probes the driver's presence/shape handling. */
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t ck[3]={'C','A','N'};
    uint8_t can[32];
    XAHC_HOOK_PARAM_REQUIRE(can, ck, 32);
    XAHC_ACCEPT("accepted with no pinned hash (BUG)");
    return 0;
}
