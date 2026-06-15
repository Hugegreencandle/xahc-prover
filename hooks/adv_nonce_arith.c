#include "xahc/xahc.h"

/* ADVERSARIAL nonce attack — the nonce flows through ARITHMETIC and is MIXED with
 * a non-nonce hook param before the accept branch. The decision still genuinely
 * depends on the nonce (for a fixed param value, some nonces accept and some don't),
 * so the substitution query must catch it. Correct verdict: COUNTEREXAMPLE (2).
 * If the dependence query misses nonce-derived-through-arithmetic symbols, this
 * would falsely PROVEN. */

extern int64_t ledger_nonce(uint32_t write_ptr, uint32_t write_len);

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    uint8_t kK[3] = {'K','E','Y'};
    uint8_t pv[1];
    XAHC_REQUIRE(hook_param(XAHC_SBUF(pv), XAHC_SBUF(kK)) == 1, "KEY");

    uint8_t n[32];
    ledger_nonce((uint32_t)n, sizeof(n));

    /* nonce flows through arithmetic and is mixed with the (non-nonce) param. */
    uint32_t mixed = (uint32_t)n[0] * 3u + (uint32_t)n[1] + (uint32_t)pv[0];

    /* decision hinges on the mixed value -> depends on the nonce. */
    XAHC_REQUIRE((mixed & 0xFF) == 0, "you lose");

    XAHC_ACCEPT("you win (nonce arithmetic lottery)");
    return 0;
}
