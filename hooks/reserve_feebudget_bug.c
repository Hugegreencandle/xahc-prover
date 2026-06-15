#include "xahc/xahc.h"

/* FEE-ESCALATION reserve bug. This hook DOES gate its emit on reserve headroom — but it
 * budgets the emit fee as a HARDCODED 10 drops (the host base fee floor) instead of the
 * network-dependent value `etxn_fee_base` actually returns. So it is reserve-safe when the
 * fee is exactly 10, but the moment the network base fee ESCALATES above 10 (a normal
 * on-ledger condition under load), the extra fee eats into the reserve and drives the
 * account below it (RESERVE_INSUFFICIENT, -38).
 *
 * This is the exact false-PROVEN the symbolic-fee model closes: with the per-emit fee pinned
 * at concrete 10, the old engine PROVED this hook reserve-safe. With the fee modeled
 * symbolically as >= 10 (unbounded above), the prover MUST find the fee-escalation
 * counterexample and refuse to PROVE it. */

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

    XAHC_REQUIRE(ocount <= 1000000ULL,    "owner_count out of range");
    XAHC_REQUIRE(base   <= 1000000000ULL, "reserve base out of range");
    XAHC_REQUIRE(inc    <= 1000000000ULL, "reserve increment out of range");
    uint64_t reserve = base + ocount * inc;          /* <= 1e9 + 1e6*1e9 < 2^63: no wrap */

    uint64_t amount = 100;
    uint64_t fee_budget = 10;                         /* THE BUG: assumes fee == host floor */

    XAHC_REQUIRE(balance >= reserve, "already below reserve");
    uint64_t spend = amount + fee_budget;             /* small constants, no wrap */
    XAHC_REQUIRE(balance - reserve >= spend, "emit would breach reserve (at fee=10)");

    /* The macro pays the REAL etxn_fee_base, which may exceed the 10 we budgeted above. */
    XAHC_EMIT_PAYMENT(DST, amount, 0, 0);
    XAHC_ACCEPT("reserve-safe ONLY if fee == 10");
    return 0;
}
