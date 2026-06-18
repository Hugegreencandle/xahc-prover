#include "xahc/xahc.h"
extern int64_t ledger_last_time(void);
static inline void wr64(uint8_t* b,uint64_t v){for(int i=0;i<8;i++)b[i]=(uint8_t)(v>>(56-8*i));}
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t skey[1]={0x01}, sval[8];
    wr64(sval,(uint64_t)ledger_last_time());   /* persisted effect depends on entropy (BUG) */
    XAHC_STATE_SET(skey,sval);
    XAHC_ACCEPT("stamped");
    return 0;
}
