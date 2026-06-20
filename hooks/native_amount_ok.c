#include "xahc/xahc.h"

/* CORRECT — gates on the received NATIVE amount and REJECTS issued (IOU) amounts. Uses
 * xahc_otxn_drops(), which reads the 8-byte sfAmount and returns -2 (NOT_XRP) when byte0's
 * not-XRP bit (0x80) is set. The `drops >= 0` check rolls back on any issued amount, so the
 * hook can never misread an IOU's XFL value word as native drops.
 * prove_native_amount => PROVEN. */
int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();
    int64_t drops = xahc_otxn_drops();
    XAHC_REQUIRE(drops >= 0, "native XAH only (rejects issued amounts)");
    XAHC_REQUIRE((uint64_t)drops >= 1000000, "min 1 XAH");
    XAHC_ACCEPT("genuinely-native payment, within policy");
    return 0;
}
