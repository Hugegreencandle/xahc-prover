#include "xahc/xahc.h"

/* ADVERSARIAL reserve attack #2 — the hook's OWN reserve math WRAPS in uint64.
 * It does NOT bound owner_count/inc, so base + owner_count*inc can wrap past 2^64
 * to a small number, making the headroom check pass while the TRUE reserve is huge.
 * The engine computes reserve in 128-bit (no wrap), so the true reserve exceeds the
 * balance even though the hook's wrapped check passed -> the account is below its
 * real reserve. Correct verdict: COUNTEREXAMPLE (2). A PROVEN here = the engine
 * reproduced the hook's wrap instead of computing the true wide reserve. */

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

    uint64_t balance = be8(bal);
    uint64_t ocount  = be8(ownc);
    uint64_t base    = be8(rsvb);
    uint64_t inc     = be8(rsvi);

    /* BUG: NO bounds on ocount/inc -> ocount*inc can wrap uint64. */
    uint64_t reserve = base + ocount * inc;   /* may wrap to a tiny value */

    uint64_t amount = 100;
    uint64_t fee_budget = 1000;

    /* The check passes whenever the WRAPPED reserve is small, even if the true
     * reserve (computed wide) is astronomically larger than the balance. */
    XAHC_REQUIRE(balance >= reserve, "already below reserve");
    uint64_t spend = amount + fee_budget;
    XAHC_REQUIRE(balance - reserve >= spend, "emit would breach reserve");

    XAHC_EMIT_PAYMENT(DST, amount, 0, 0);
    XAHC_ACCEPT("emit with wrapped reserve math");
    return 0;
}
