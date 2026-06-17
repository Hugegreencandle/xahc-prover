#include "xahc/xahc.h"
/* In-world resource conservation REFERENCE: a "spend" of an in-world resource. Reads the
 * resource slot 0x01 (8-byte BE), subtracts the requested amount (clamped so it never goes
 * negative / never wraps up), persists the smaller value. Never creates resource -> PROVEN. */
static inline uint64_t be64(const uint8_t* b){return ((uint64_t)b[0]<<56)|((uint64_t)b[1]<<48)|((uint64_t)b[2]<<40)|((uint64_t)b[3]<<32)|((uint64_t)b[4]<<24)|((uint64_t)b[5]<<16)|((uint64_t)b[6]<<8)|((uint64_t)b[7]);}
static inline void wr64(uint8_t* b,uint64_t v){b[0]=(uint8_t)(v>>56);b[1]=(uint8_t)(v>>48);b[2]=(uint8_t)(v>>40);b[3]=(uint8_t)(v>>32);b[4]=(uint8_t)(v>>24);b[5]=(uint8_t)(v>>16);b[6]=(uint8_t)(v>>8);b[7]=(uint8_t)(v);}
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    int64_t drops=xahc_otxn_drops();XAHC_REQUIRE(drops>=0,"native only");uint64_t amount=(uint64_t)drops;
    uint8_t skey[1]={0x01};uint8_t sval[8];
    int64_t srd=state(XAHC_SBUF(sval),XAHC_SBUF(skey));
    uint64_t res = (srd==8)?be64(sval):0;
    XAHC_REQUIRE(amount<=res,"insufficient resource");   /* can't spend more than held */
    uint64_t new_res = res - amount;                     /* strictly <= res: never inflates */
    wr64(sval,new_res);
    XAHC_STATE_SET(skey,sval);
    XAHC_ACCEPT("resource spent, conserved");
    return 0;
}
