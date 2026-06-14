#include "xahc/xahc.h"
/* ADVERSARIAL (CEX must survive the normalize constraint): an IOU spend-limit
 * that only rejects when amt == LIM (mode 1 = EQ). It therefore ACCEPTS every
 * amount strictly greater than LIM — violable by a whole family of NORMALIZED
 * incoming XFLs. If the _float_normalized constraint at the read site wrongly
 * excluded the violating amounts, this would FALSELY prove. It must be CEX(2).
 */
extern int64_t float_compare(int64_t, int64_t, uint32_t);

int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t amt[48]; otxn_field(XAHC_SBUF(amt), sfAmount);
    int64_t amtx = ((int64_t)amt[0]<<56)|((int64_t)amt[1]<<48)|((int64_t)amt[2]<<40)
                 |((int64_t)amt[3]<<32)|((int64_t)amt[4]<<24)|((int64_t)amt[5]<<16)
                 |((int64_t)amt[6]<<8)|((int64_t)amt[7]);
    amtx &= 0x7FFFFFFFFFFFFFFFLL;
    uint8_t key[3] = {'L','I','M'}; uint8_t lim[8];
    hook_param(XAHC_SBUF(lim), XAHC_SBUF(key));
    int64_t limx = ((int64_t)lim[0]<<56)|((int64_t)lim[1]<<48)|((int64_t)lim[2]<<40)
                 |((int64_t)lim[3]<<32)|((int64_t)lim[4]<<24)|((int64_t)lim[5]<<16)
                 |((int64_t)lim[6]<<8)|((int64_t)lim[7]);
    if (float_compare(amtx, limx, 1) == 1) rollback(0,0,1);   /* 1 = EQ only — broken */
    accept(0,0,2);
    return 0;
}
