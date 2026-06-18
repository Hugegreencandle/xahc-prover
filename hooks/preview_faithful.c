#include "xahc/xahc.h"
/* Preview-faithful: outcome (accept + state write) is a function of the SIGNED TX only. No nonce/
 * seq/time. A wallet preview of this tx is guaranteed to match execution. */
static inline void wr64(uint8_t* b,uint64_t v){for(int i=0;i<8;i++)b[i]=(uint8_t)(v>>(56-8*i));}
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    int64_t drops=xahc_otxn_drops(); XAHC_REQUIRE(drops>=0,"native only");
    uint8_t lim_key[3]={'L','I','M'}, lim[8];
    XAHC_HOOK_PARAM_REQUIRE(lim,lim_key,8);
    uint64_t limit=((uint64_t)lim[0]<<56)|((uint64_t)lim[1]<<48)|((uint64_t)lim[2]<<40)|((uint64_t)lim[3]<<32)|((uint64_t)lim[4]<<24)|((uint64_t)lim[5]<<16)|((uint64_t)lim[6]<<8)|((uint64_t)lim[7]);
    XAHC_REQUIRE((uint64_t)drops<=limit,"over limit");      /* decision = f(signed tx, param) */
    uint8_t skey[1]={0x01}, sval[8]; wr64(sval,(uint64_t)drops);  /* state = f(signed tx) */
    XAHC_STATE_SET(skey,sval);
    XAHC_ACCEPT("faithful");
    return 0;
}
