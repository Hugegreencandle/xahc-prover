#include "xahc/xahc.h"
extern int64_t ledger_seq(void);
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t dk[3]={'D','E','A'}, dl[8];
    XAHC_HOOK_PARAM_REQUIRE(dl,dk,8);
    uint64_t deadline=((uint64_t)dl[0]<<56)|((uint64_t)dl[1]<<48)|((uint64_t)dl[2]<<40)|((uint64_t)dl[3]<<32)|((uint64_t)dl[4]<<24)|((uint64_t)dl[5]<<16)|((uint64_t)dl[6]<<8)|((uint64_t)dl[7]);
    XAHC_REQUIRE((uint64_t)ledger_seq()>=deadline,"before deadline"); /* decision depends on seq (BUG for preview) */
    XAHC_ACCEPT("after deadline");
    return 0;
}
