#include "xahc/xahc.h"

/* BUGGY — gates accept on sfAmount but NEVER checks tfPartialPayment. An attacker sends a big Amount
 * with tfPartialPayment set, delivering dust; the hook thinks it was paid in full.
 * prove_partial_payment => COUNTEREXAMPLE. */
int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();
    int64_t drops = xahc_otxn_drops();
    XAHC_REQUIRE(drops >= 1000000, "min 1 XAH (BUG: trusts sfAmount, ignores tfPartialPayment)");
    XAHC_ACCEPT("got paid (but delivered_amount could be dust)");
    return 0;
}
