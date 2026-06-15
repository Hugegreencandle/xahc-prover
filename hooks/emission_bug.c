#include "xahc/xahc.h"

/* BUGGY emission-burden hook. Declares a budget of ONLY 1 via etxn_reserve(1), but emits
 * TWICE on the (incoming-payment) path. The second emit would fail at runtime with -13
 * TOO_MANY_EMITTED_TXN — and because the first emit already succeeded, the hook leaves a
 * partial/failed emit set: an over-budget emission burden.
 *
 * Proves nothing: the prover must find the accepting path where emit_count(2) > reserved(1)
 * and report a COUNTEREXAMPLE. No cbak export (so the static bound is decidable). */

static const uint8_t DST[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};

static void emit_one(uint64_t drops) {
    uint8_t tx[XAHC_PAYMENT_SIZE];
    uint32_t len = xahc_build_payment(tx, DST, drops, 0, 0);
    XAHC_TRY(emit(0, 0, (uint32_t)tx, len));
}

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    /* BUG: reserve only 1 ... */
    XAHC_TRY(etxn_reserve(1));

    int64_t drops = xahc_otxn_drops();
    XAHC_REQUIRE(drops >= 0, "native only");

    /* ... but emit twice on this path. emit_count (2) > reserved (1). */
    emit_one((uint64_t)drops / 4);
    emit_one((uint64_t)drops / 4);

    XAHC_ACCEPT("over-budget emit");
    return 0;
}
