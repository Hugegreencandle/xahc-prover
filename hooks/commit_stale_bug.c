#include "xahc/xahc.h"
extern int64_t util_sha512h(uint32_t,uint32_t,uint32_t,uint32_t);
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t skey[1]={0x01}, ckey[1]={0x02};
    uint8_t sval[16];
    int64_t srd=state(XAHC_SBUF(sval),XAHC_SBUF(skey));
    if(srd!=16){ for(int i=0;i<16;i++) sval[i]=0; }
    uint8_t root[32];
    XAHC_REQUIRE(util_sha512h(XAHC_SBUF(root),XAHC_SBUF(sval))>=0,"hash");  /* hash OLD state (BUG) */
    sval[0]=(uint8_t)(sval[0]+1);
    XAHC_STATE_SET(skey,sval);                  /* persist NEW */
    XAHC_STATE_SET(ckey,root);                  /* commit STALE hash */
    XAHC_ACCEPT("commit stale (BUG)");
    return 0;
}
