#include "xahc/xahc.h"

/* BUGGY agent_guardrail — the destination lock is OFF-BY-ONE.
 * The DST compare loop runs `i < 19` instead of `i < 20`, so the LAST byte of
 * the destination account is never checked. An attacker can send to any account
 * whose first 19 bytes match the allowed one. The prover should hand back a
 * concrete counterexample (dest == allowed except byte 19). */

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    if (otxn_type() != XAHC_ttPAYMENT)
        XAHC_ACCEPT("not a payment");

    uint8_t origin[20], me[20];
    XAHC_OTXN_ACCOUNT(origin);
    hook_account(XAHC_SBUF(me));
    int outgoing = 1;
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i)
        if (origin[i] != me[i]) outgoing = 0;
    if (!outgoing)
        XAHC_ACCEPT("incoming");

    uint8_t lim_key[3] = { 'L', 'I', 'M' };
    uint8_t lim[8];
    XAHC_HOOK_PARAM_REQUIRE(lim, lim_key, 8);
    uint64_t limit =
        ((uint64_t)lim[0] << 56) | ((uint64_t)lim[1] << 48) |
        ((uint64_t)lim[2] << 40) | ((uint64_t)lim[3] << 32) |
        ((uint64_t)lim[4] << 24) | ((uint64_t)lim[5] << 16) |
        ((uint64_t)lim[6] << 8)  | ((uint64_t)lim[7]);

    int64_t drops = xahc_otxn_drops();
    XAHC_REQUIRE(drops >= 0, "native amount only");
    XAHC_REQUIRE((uint64_t)drops <= limit, "over per-tx spend limit");

    uint8_t dst_key[3] = { 'D', 'S', 'T' };
    uint8_t allowed[20];
    if (hook_param(XAHC_SBUF(allowed), XAHC_SBUF(dst_key)) == 20) {
        uint8_t dest[20];
        XAHC_OTXN_DESTINATION(dest);
        int ok = 1;
        for (int i = 0; XAHC_GUARD(20), i < 19; ++i)   /* BUG: i < 19 skips byte 19 */
            if (dest[i] != allowed[i]) ok = 0;
        XAHC_REQUIRE(ok, "destination not in policy");
    }

    XAHC_ACCEPT("within policy");
    return 0;
}
