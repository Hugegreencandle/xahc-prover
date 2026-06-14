#include "xahc/xahc.h"
/* SUBTLE BUG: amounts compared as SIGNED int64_t. A payment with the high bit
   set (>= ~9.2e18 drops) reads as NEGATIVE -> slips under any positive limit. */
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t amt[8]; otxn_field(XAHC_SBUF(amt), sfAmount);
    uint8_t key[3] = {'L','I','M'}; uint8_t lim[8];
    hook_param(XAHC_SBUF(lim), XAHC_SBUF(key));
    int64_t drops = ((int64_t)amt[0]<<56)|((int64_t)amt[1]<<48)|((int64_t)amt[2]<<40)|((int64_t)amt[3]<<32)|((int64_t)amt[4]<<24)|((int64_t)amt[5]<<16)|((int64_t)amt[6]<<8)|((int64_t)amt[7]);
    int64_t limit= ((int64_t)lim[0]<<56)|((int64_t)lim[1]<<48)|((int64_t)lim[2]<<40)|((int64_t)lim[3]<<32)|((int64_t)lim[4]<<24)|((int64_t)lim[5]<<16)|((int64_t)lim[6]<<8)|((int64_t)lim[7]);
    if (drops > limit) rollback(0,0,1);   /* signed > : the bug */
    accept(0,0,2);
    return 0;
}
