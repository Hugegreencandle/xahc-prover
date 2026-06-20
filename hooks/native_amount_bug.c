#include "xahc/xahc.h"

/* BUGGY — reads the 8-byte sfAmount and hand-decodes it as native drops, masking byte0 with 0x3F
 * (stripping the not-XRP and sign flag bits) but NEVER REJECTING when the not-XRP bit (0x80) is set.
 * When the incoming Payment is an ISSUED (IOU) STAmount, byte0 has 0x80 set; this hook strips that
 * bit and reads the IOU's XFL value word as a tiny "drops" number, passing the min-amount gate. An
 * attacker pays a huge token that looks like dust XAH and the hook accepts.
 * prove_native_amount => COUNTEREXAMPLE. */
int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    uint8_t amt[8];
    XAHC_REQUIRE(otxn_field(XAHC_SBUF(amt), sfAmount) == 8, "sfAmount read");

    /* BUG: masks byte0 with 0x3F to drop the flag bits but never checks amt[0] & 0x80 (not-XRP).
     * An issued value word is silently treated as native drops. */
    uint64_t drops = ((uint64_t)(amt[0] & 0x3F) << 56) |
                     ((uint64_t)amt[1] << 48) | ((uint64_t)amt[2] << 40) |
                     ((uint64_t)amt[3] << 32) | ((uint64_t)amt[4] << 24) |
                     ((uint64_t)amt[5] << 16) | ((uint64_t)amt[6] << 8) |
                     ((uint64_t)amt[7]);

    XAHC_REQUIRE(drops >= 1000000, "min 1 XAH (BUG: trusts sfAmount, ignores not-XRP bit)");
    XAHC_ACCEPT("got paid (but the amount could be an issued token misread as drops)");
    return 0;
}
