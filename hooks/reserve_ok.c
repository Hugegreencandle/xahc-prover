#include "xahc/xahc.h"

/* CORRECT reserve-safe emitter. Reads the standing balance, owner_count, and reserve
 * params (base, increment) as 8-byte big-endian hook params, then emits a payment ONLY if
 * the post-emit balance still covers the reserve (base + owner_count*increment). The amount
 * to send is the incoming drops; the hook proves headroom (balance >= reserve + amount + fee)
 * before emitting. Never drives the account below its reserve. */

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

    /* Bound the reserve params to sane on-ledger ranges so the reserve computation cannot
     * overflow uint64 (an unguarded base + owner_count*inc would wrap on adversarial inputs
     * — itself a reserve-safety bug). With these bounds base + ocount*inc < 2^63, no wrap. */
    XAHC_REQUIRE(ocount <= 1000000ULL,   "owner_count out of range");
    XAHC_REQUIRE(base   <= 1000000000ULL, "reserve base out of range");
    XAHC_REQUIRE(inc    <= 1000000000ULL, "reserve increment out of range");
    uint64_t reserve = base + ocount * inc;          /* <= 1e9 + 1e6*1e9 < 2^63: no wrap */

    /* The amount we want to push out. Small fixed amount so the reserve check, not the
     * amount decode, is what's under test. Fee upper bound budgeted at 1000 drops. */
    uint64_t amount = 100;
    uint64_t fee_budget = 1000;

    /* HEADROOM CHECK (the safety gate): require balance covers reserve + amount + fee.
     * Written to avoid wrap: compare balance against the (checked) sum. */
    XAHC_REQUIRE(balance >= reserve, "already below reserve");
    uint64_t spend = amount + fee_budget;            /* small constants, no wrap */
    XAHC_REQUIRE(balance - reserve >= spend, "emit would breach reserve");

    XAHC_EMIT_PAYMENT(DST, amount, 0, 0);
    XAHC_ACCEPT("reserve-safe emit");
    return 0;
}
