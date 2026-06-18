#include "xahc/xahc.h"
/* Bootloader re-pin gate: owner-only AND strictly-increasing version (no downgrade). Slot 0x01 =
 * [version:u64 | hash:32]. New version/hash arrive as params NV/NH (symbolic to the prover). */
static inline uint64_t be64(const uint8_t* b){uint64_t v=0;for(int i=0;i<8;i++)v=(v<<8)|b[i];return v;}
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t origin[20], me[20];
    XAHC_OTXN_ACCOUNT(origin);
    hook_account(XAHC_SBUF(me));
    /* authz removed (BUG) */
    uint8_t skey[1]={0x01}, sval[40];
    int64_t srd=state(XAHC_SBUF(sval),XAHC_SBUF(skey));
    uint64_t old_ver=(srd==40)?be64(&sval[0]):0;
    uint8_t nvk[2]={'N','V'}, nv[8]; XAHC_HOOK_PARAM_REQUIRE(nv,nvk,8);
    uint8_t nhk[2]={'N','H'}, nh[32]; XAHC_HOOK_PARAM_REQUIRE(nh,nhk,32);
    uint64_t new_ver=be64(nv);
    XAHC_REQUIRE(new_ver>old_ver, "no downgrade");                       /* MONOTONIC */
    for (int i=0; XAHC_GUARD(8),  i<8;  ++i) sval[i]=nv[i];
    for (int i=0; XAHC_GUARD(32), i<32; ++i) sval[8+i]=nh[i];
    XAHC_STATE_SET(skey,sval);
    XAHC_ACCEPT("re-pin noauth (BUG)");
    return 0;
}
