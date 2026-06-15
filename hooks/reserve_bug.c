#include "xahc/xahc.h"

/* BUGGY emitter — emits a payment WITHOUT checking that the account keeps its reserve.
 * Reads the balance / owner_count / reserve params (so the prover has them) but never
 * gates the emit on headroom, so on inputs where balance is at/just above the reserve the
 * emit + fee drives the account below reserve (RESERVE_INSUFFICIENT, -38). The prover
 * should return a concrete (balance, owner_count, reserve) counterexample. */

static const uint8_t DST[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};

int64_t cbak(uint32_t reserved) { return 0; }

static uint64_t be8(const uint8_t* b) {
    return ((uint64_t)b[0]<<56)|((uint64_t)b[1]<<48)|((uint64_t)b[2]<<40)|((uint64_t)b[3]<<32)
         | ((uint64_t)b[4]<<24)|((uint64_t)b[5]<<16)|((uint64_t)b[6]<<8)|((uint64_t)b[7]);
}

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    uint8_t bal[8], ownc[8], rsvb[8], rsvi[8];
    uint8_t kBAL[3]={'B','A','L'}, kOWN[4]={'O','W','N','C'},
            kRSB[4]={'R','S','V','B'}, kRSI[4]={'R','S','V','I'};
    XAHC_REQUIRE(hook_param(XAHC_SBUF(bal),  XAHC_SBUF(kBAL)) == 8, "BAL");
    XAHC_REQUIRE(hook_param(XAHC_SBUF(ownc), XAHC_SBUF(kOWN)) == 8, "OWNC");
    XAHC_REQUIRE(hook_param(XAHC_SBUF(rsvb), XAHC_SBUF(kRSB)) == 8, "RSVB");
    XAHC_REQUIRE(hook_param(XAHC_SBUF(rsvi), XAHC_SBUF(kRSI)) == 8, "RSVI");

    /* params read but the reserve is NEVER consulted before emitting (the bug). */
    (void)be8(bal); (void)be8(ownc); (void)be8(rsvb); (void)be8(rsvi);

    uint64_t amount = 100;
    XAHC_EMIT_PAYMENT(DST, amount, 0, 0);   /* unconditional emit -> can breach reserve */
    XAHC_ACCEPT("emit (no reserve check!)");
    return 0;
}
