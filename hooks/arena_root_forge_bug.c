#include "xahc/xahc.h"
/* PoC for EverArcade Root Integrity: state_root == HASH(canonical(ArenaState)).
 * ArenaState slot 0x01 = canonical, fixed-layout, integer-only [tick:u64 | score:u64] (16B).
 * Fixed field order + integer-only = canonical by construction (the WASM-side analogue of the
 * byte-lex canonicalizer). state_root = HASH(canonical bytes) committed to slot 0x02. */
extern int64_t util_sha512h(uint32_t,uint32_t,uint32_t,uint32_t);
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t skey[1]={0x01}, ckey[1]={0x02}, sval[16];
    int64_t srd=state(XAHC_SBUF(sval),XAHC_SBUF(skey));
    if(srd!=16){ for(int i=0;i<16;i++) sval[i]=0; }
    /* deterministic transition over the canonical state */
    sval[7]=(uint8_t)(sval[7]+1);              /* tick++ (low byte) */
    XAHC_STATE_SET(skey,sval);                  /* persist canonical ArenaState */
    uint8_t root[32];
    for(int i=0;i<32;i++) root[i]=(uint8_t)0x77; /* forged root (BUG) */
    XAHC_STATE_SET(ckey,root);                  /* commit the honest root */
    XAHC_ACCEPT("forged root (BUG)");
    return 0;
}
