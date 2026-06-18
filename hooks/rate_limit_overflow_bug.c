#include "xahc/xahc.h"
extern int64_t ledger_last_time(void);
static inline uint64_t be64(const uint8_t* b){uint64_t v=0;for(int i=0;i<8;i++)v=(v<<8)|b[i];return v;}
static inline void wr64(uint8_t* b,uint64_t v){for(int i=0;i<8;i++)b[i]=(uint8_t)(v>>(56-8*i));}
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint64_t now=(uint64_t)ledger_last_time();
    uint8_t ck[8]={'C','O','O','L','D','O','W','N'}, cdv[8]; XAHC_HOOK_PARAM_REQUIRE(cdv,ck,8);
    uint64_t cd=be64(cdv);
    uint8_t skey[1]={0x01}, sval[8];
    int64_t srd=state(XAHC_SBUF(sval),XAHC_SBUF(skey));
    uint64_t last=(srd==8)?be64(sval):0;
    
    XAHC_REQUIRE(now>=last+cd, "cooldown (overflow-naive BUG)");
    wr64(sval, now);                                        /* stamp the real ledger time */
    XAHC_STATE_SET(skey,sval);
    XAHC_ACCEPT("overflow-naive gate (BUG)");
    return 0;
}
