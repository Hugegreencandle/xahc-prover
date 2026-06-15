#include "xahc/xahc.h"

/* BUGGY "lottery": seeds the win condition from ledger_nonce. The hook reads the ledger
 * nonce and accepts (the player "wins") only when the first nonce byte is zero — a security
 * decision gated on a grindable/predictable value. A determined submitter can predict or
 * grind the nonce to win at will. The prover should return a counterexample showing the
 * accept decision DEPENDS on the nonce (same tx accepted under one nonce, rejected under
 * another). */

extern int64_t ledger_nonce(uint32_t write_ptr, uint32_t write_len);

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    uint8_t n[32];
    ledger_nonce((uint32_t)n, sizeof(n));

    /* BUG: the win/accept hinges on the nonce value (insecure randomness). */
    XAHC_REQUIRE(n[0] == 0, "you lose this round");

    XAHC_ACCEPT("you win (nonce lottery!)");
    return 0;
}
