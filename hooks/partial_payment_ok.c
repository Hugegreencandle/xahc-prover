#include "xahc/xahc.h"

/* CORRECT — gates on the received amount BUT rejects partial payments. Reads sfFlags and refuses any
 * tx with tfPartialPayment (0x00020000) set, so a dust delivered_amount can never trick the gate.
 * prove_partial_payment => PROVEN. */
int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();
    int64_t drops = xahc_otxn_drops();
    XAHC_REQUIRE(drops >= 0, "native only");

    /* reject partial payments: read sfFlags (UInt32, big-endian), refuse tfPartialPayment */
    uint8_t fb[4] = {0};
    otxn_field(XAHC_SBUF(fb), sfFlags);
    uint32_t flags = ((uint32_t)fb[0] << 24) | ((uint32_t)fb[1] << 16)
                   | ((uint32_t)fb[2] << 8)  | (uint32_t)fb[3];
    XAHC_REQUIRE((flags & 0x00020000u) == 0, "reject partial payment");

    XAHC_REQUIRE((uint64_t)drops >= 1000000, "min 1 XAH");
    XAHC_ACCEPT("paid in full, not a partial payment");
    return 0;
}
