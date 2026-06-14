#include "xahc/xahc.h"
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t amt[8]; otxn_field(XAHC_SBUF(amt), sfAmount);
    uint8_t key[3] = {'L','I','M'}; uint8_t lim[8];
    hook_param(XAHC_SBUF(lim), XAHC_SBUF(key));
    uint64_t drops = ((uint64_t)amt[0]<<56)|((uint64_t)amt[1]<<48)|((uint64_t)amt[2]<<40)|((uint64_t)amt[3]<<32)|((uint64_t)amt[4]<<24)|((uint64_t)amt[5]<<16)|((uint64_t)amt[6]<<8)|((uint64_t)amt[7]);
    uint64_t limit= ((uint64_t)lim[0]<<56)|((uint64_t)lim[1]<<48)|((uint64_t)lim[2]<<40)|((uint64_t)lim[3]<<32)|((uint64_t)lim[4]<<24)|((uint64_t)lim[5]<<16)|((uint64_t)lim[6]<<8)|((uint64_t)lim[7]);
    if (drops > limit) rollback(0,0,1);
    accept(0,0,2);
    return 0;
}
