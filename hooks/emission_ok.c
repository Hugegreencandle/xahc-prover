#include "xahc/xahc.h"

/* CORRECT emission-burden hook. Declares an emit budget of 2 up front via etxn_reserve(2),
 * then emits AT MOST 2 payments on every path. No cbak export -> no dynamic re-entry chain.
 *
 * Proves: accept => emit_count <= reserved(2). Emitting within the declared reserve never
 * trips runtime -13 TOO_MANY_EMITTED_TXN.
 *
 * NOTE: we call etxn_reserve / emit directly (not the XAHC_EMIT_PAYMENT macro) because that
 * macro embeds its own etxn_reserve(1); calling it twice would return -8 ALREADY_SET. Here we
 * reserve ONCE for the whole invocation and build/emit the payments by hand. */

static const uint8_t DST[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};

static void emit_one(uint64_t drops) {
    uint8_t tx[XAHC_PAYMENT_SIZE];
    uint32_t len = xahc_build_payment(tx, DST, drops, 0, 0);
    XAHC_TRY(emit(0, 0, (uint32_t)tx, len));
}

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    /* Declare the budget ONCE: at most 2 emitted txns this invocation. */
    XAHC_TRY(etxn_reserve(2));

    int64_t drops = xahc_otxn_drops();
    XAHC_REQUIRE(drops >= 0, "native only");

    /* Emit two payments — exactly at the reserved budget, never over it. */
    emit_one((uint64_t)drops / 4);
    emit_one((uint64_t)drops / 4);

    XAHC_ACCEPT("emitted within reserve");
    return 0;
}
