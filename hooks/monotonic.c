#include "xahc/xahc.h"

/* Replay-protection nonce guard. A persisted NONCE in hook state must only ever
 * increase; each tx carries an 8-byte NONCE hook-parameter that must strictly
 * exceed the stored one. Correct: writes only a value greater than the prior. */

int64_t cbak(uint32_t reserved) { return 0; }

static uint64_t be64(const uint8_t* b) {
    return ((uint64_t)b[0]<<56)|((uint64_t)b[1]<<48)|((uint64_t)b[2]<<40)|((uint64_t)b[3]<<32)|
           ((uint64_t)b[4]<<24)|((uint64_t)b[5]<<16)|((uint64_t)b[6]<<8)|((uint64_t)b[7]);
}

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    uint8_t k[5] = { 'N','O','N','C','E' };
    uint64_t stored = xahc_state_u64(k, 5, 0);

    uint8_t nk[3] = { 'N','O','N' };
    uint8_t nb[8];
    XAHC_HOOK_PARAM_REQUIRE(nb, nk, 8);
    uint64_t incoming = be64(nb);

    XAHC_REQUIRE(incoming > stored, "nonce must strictly increase");
    XAHC_STATE_SET(k, nb);
    XAHC_ACCEPT("ok");
    return 0;
}
