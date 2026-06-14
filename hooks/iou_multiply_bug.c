#include "xahc/xahc.h"
/* CRITICAL NEGATIVE TEST: take the incoming issued amount, MULTIPLY it by a
 * symbolic factor (from a hook-param), and emit the product as an IOU. Because
 * the multiply is over a SYMBOLIC operand, the prover cannot compute the emitted
 * value soundly -> the conservation verdict MUST be INCONCLUSIVE (exit 3), and
 * NEVER PROVEN. If this ever proves PROVEN the XFL model is unsound. */
extern int64_t float_set(int32_t, int64_t);
extern int64_t float_multiply(int64_t, int64_t);

int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t amt[48]; otxn_field(XAHC_SBUF(amt), sfAmount);
    int64_t amtx = ((int64_t)amt[0]<<56)|((int64_t)amt[1]<<48)|((int64_t)amt[2]<<40)
                 |((int64_t)amt[3]<<32)|((int64_t)amt[4]<<24)|((int64_t)amt[5]<<16)
                 |((int64_t)amt[6]<<8)|((int64_t)amt[7]);
    amtx &= 0x7FFFFFFFFFFFFFFFLL;

    /* factor's mantissa comes from a hook-param -> symbolic */
    uint8_t key[6] = {'F','A','C','T','O','R'}; uint8_t fac[8];
    hook_param(XAHC_SBUF(fac), XAHC_SBUF(key));
    int64_t mant = ((int64_t)fac[0]<<56)|((int64_t)fac[1]<<48)|((int64_t)fac[2]<<40)
                 |((int64_t)fac[3]<<32)|((int64_t)fac[4]<<24)|((int64_t)fac[5]<<16)
                 |((int64_t)fac[6]<<8)|((int64_t)fac[7]);
    int64_t factor = float_set(0, mant);
    int64_t product = float_multiply(amtx, factor);   /* SYMBOLIC nonlinear op */

    uint8_t cur[20]; for (int i=0; XAHC_GUARD(20), i<20; ++i) cur[i]=0;
    cur[12]='U'; cur[13]='S'; cur[14]='D';
    uint8_t iss[20]; for (int i=0; XAHC_GUARD(20), i<20; ++i) iss[i]=0xCC;
    uint8_t dst[20]; for (int i=0; XAHC_GUARD(20), i<20; ++i) dst[i]=0xBB;

    XAHC_EMIT_PAYMENT_IOU(dst, product, cur, iss, 0, 0);
    XAHC_ACCEPT("emitted scaled iou");
    return 0;
}
