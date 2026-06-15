#include "xahc/xahc.h"

/* ADVERSARIAL reserve attack #1 — the emitted AMOUNT is derived from the same
 * param bytes the byte-substitution rewrites (balance), and the headroom check
 * is DELIBERATELY WRONG (off by the fee). If the byte-substitution were not
 * semantics-preserving across the cross-term (amount depends on BAL, and the
 * reserve check also depends on BAL), a mis-substitution could hide the breach.
 *
 * The hook emits `amount = balance / 2` and checks only `balance >= reserve`
 * (NOT balance - amount - fee >= reserve). On inputs where balance is just above
 * reserve, emitting half the balance + fee drives it below reserve -> -38.
 * Correct verdict: COUNTEREXAMPLE (2). A false PROVEN here = substitution bug. */

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

    XAHC_REQUIRE(ocount <= 1000000ULL,   "owner_count out of range");
    XAHC_REQUIRE(base   <= 1000000000ULL, "reserve base out of range");
    XAHC_REQUIRE(inc    <= 1000000000ULL, "reserve increment out of range");
    uint64_t reserve = base + ocount * inc;

    /* amount derived from balance — couples the emit to the substituted bytes */
    uint64_t amount = balance / 2;

    /* WRONG headroom check: ignores the amount entirely. */
    XAHC_REQUIRE(balance >= reserve, "already below reserve");

    XAHC_EMIT_PAYMENT(DST, amount, 0, 0);
    XAHC_ACCEPT("buggy var-amount emit");
    return 0;
}
