#include "xahc/xahc.h"
/* Commitment kernel: persist a state transition to slot 0x01, then commit the HONEST hash of the
 * new state to slot 0x02. root == SHA512Half(new state) for all inputs -> PROVEN. */
extern int64_t util_sha512h(uint32_t,uint32_t,uint32_t,uint32_t);
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t skey[1]={0x01}, ckey[1]={0x02};
    uint8_t sval[16];
    int64_t srd=state(XAHC_SBUF(sval),XAHC_SBUF(skey));
    if(srd!=16){ for(int i=0;i<16;i++) sval[i]=0; }
    sval[0]=(uint8_t)(sval[0]+1);              /* deterministic transition */
    XAHC_STATE_SET(skey,sval);                  /* persist NEW state */
    uint8_t root[32];
    XAHC_REQUIRE(util_sha512h(XAHC_SBUF(root),XAHC_SBUF(sval))>=0,"hash");  /* root = H(new state) */
    XAHC_STATE_SET(ckey,root);                  /* commit the honest hash */
    XAHC_ACCEPT("commit");
    return 0;
}
