#include "xahc/xahc.h"

/* BUGGY — the loop's iteration count is ATTACKER-CONTROLLED but the guard budgets
 * a fixed 8. xahc lint passes (a guard is present); on-chain a large count crosses
 * the guard past its budget and the hook dies with GUARD_VIOLATION. The classic
 * "I guarded the loop but underestimated the bound" footgun.
 *
 * The prover should hand back the input (an amount whose last byte is > 8) that
 * trips it — for every such input. */

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    uint8_t amt[8];
    if (otxn_field(XAHC_SBUF(amt), sfAmount) != 8)
        XAHC_ACCEPT("not native");

    int n = amt[7];                 /* attacker-controlled iteration count (0..255) */
    uint64_t acc = 0;
    for (int i = 0; XAHC_GUARD(8), i < n; ++i)   /* BUG: budgets 8, n can be 255 */
        acc += (uint64_t)i;

    XAHC_ACCEPT("done");
    return 0;
}
