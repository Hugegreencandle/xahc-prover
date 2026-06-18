#include "xahc/xahc.h"
extern int64_t util_sha512h(uint32_t,uint32_t,uint32_t,uint32_t);
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t skey[1]={0x01}, ckey[1]={0x02};
    uint8_t sval[16];
    int64_t srd=state(XAHC_SBUF(sval),XAHC_SBUF(skey));
    if(srd!=16){ for(int i=0;i<16;i++) sval[i]=0; }
    sval[0]=(uint8_t)(sval[0]+1);
    XAHC_STATE_SET(skey,sval);
    uint8_t root[32];
    for(int i=0;i<32;i++) root[i]=(uint8_t)0xAB;  /* CONSTANT forged root (BUG) */
    XAHC_STATE_SET(ckey,root);
    XAHC_ACCEPT("commit constant (BUG)");
    return 0;
}
