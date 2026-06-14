#include "xahc/xahc.h"
/* IOU spend-limit: reject if the incoming issued (trustline) Amount exceeds LIM.
 * The amount is an issued STAmount (48 bytes); its 8-byte value word is an XFL
 * (with bit63 set = is-issued). We compare in XFL space via float_compare.
 *
 * LIM is supplied as an 8-byte XFL hook-param (already in XFL form). */
extern int64_t float_compare(int64_t, int64_t, uint32_t);

int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t amt[48]; otxn_field(XAHC_SBUF(amt), sfAmount);
    /* big-endian 8-byte value word -> XFL (clear bit63, the is-issued flag) */
    int64_t amtx = ((int64_t)amt[0]<<56)|((int64_t)amt[1]<<48)|((int64_t)amt[2]<<40)
                 |((int64_t)amt[3]<<32)|((int64_t)amt[4]<<24)|((int64_t)amt[5]<<16)
                 |((int64_t)amt[6]<<8)|((int64_t)amt[7]);
    amtx &= 0x7FFFFFFFFFFFFFFFLL;             /* clear bit63 -> XFL */
    uint8_t key[3] = {'L','I','M'}; uint8_t lim[8];
    hook_param(XAHC_SBUF(lim), XAHC_SBUF(key));
    int64_t limx = ((int64_t)lim[0]<<56)|((int64_t)lim[1]<<48)|((int64_t)lim[2]<<40)
                 |((int64_t)lim[3]<<32)|((int64_t)lim[4]<<24)|((int64_t)lim[5]<<16)
                 |((int64_t)lim[6]<<8)|((int64_t)lim[7]);
    if (float_compare(amtx, limx, 4) == 1) rollback(0,0,1);   /* 4 = GT: amt > LIM -> reject */
    accept(0,0,2);
    return 0;
}
