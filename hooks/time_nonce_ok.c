#include "xahc/xahc.h"

/* CORRECT: the security decision uses an escrow-style ledger_seq DEADLINE only — a
 * legitimate time gate (accept after ledger N). It never reads ledger_nonce, so no accept
 * decision can hinge on grindable randomness. The prover should return PROVEN for the
 * nonce-dependence invariant (ledger_seq deadlines are intentionally NOT flagged). */

extern int64_t ledger_seq(void);

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    int64_t seq = ledger_seq();
    /* Unlock only at/after a fixed deadline ledger. Legitimate, not nonce-dependent. */
    XAHC_REQUIRE(seq >= 5000000, "not yet unlocked");

    XAHC_ACCEPT("deadline reached");
    return 0;
}
