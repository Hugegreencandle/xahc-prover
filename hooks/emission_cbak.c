#include "xahc/xahc.h"

/* DYNAMIC re-entry case — NOT statically decidable. This hook EXPORTS a cbak callback AND
 * emits. When an emitted txn settles, xahaud runs cbak; a cbak can itself emit and/or call
 * hook_again, so the TOTAL emission burden can grow across re-entries the symbolic engine
 * does NOT model (it analyzes a single `hook` invocation only).
 *
 * The emission-burden driver must therefore FAIL CLOSED -> INCONCLUSIVE for this hook, never
 * PROVEN. It only proves the static per-invocation reserve bound; the unbounded-emission-chain
 * property under cbak re-entry is out of scope. This fixture pins that fail-closed behaviour. */

static const uint8_t DST[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};

/* The callback re-emits when an emitted txn settles — exactly the re-entry the static analysis
 * cannot bound. (Its body is irrelevant to the verdict: merely EXPORTING cbak + emitting is the
 * trigger for INCONCLUSIVE.) */
int64_t cbak(uint32_t reserved) {
    etxn_reserve(1);
    uint8_t tx[XAHC_PAYMENT_SIZE];
    uint32_t len = xahc_build_payment(tx, DST, 1, 0, 0);
    emit(0, 0, (uint32_t)tx, len);
    return 0;
}

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();
    XAHC_TRY(etxn_reserve(1));
    int64_t drops = xahc_otxn_drops();
    XAHC_REQUIRE(drops >= 0, "native only");
    {
        uint8_t tx[XAHC_PAYMENT_SIZE];
        uint32_t len = xahc_build_payment(tx, DST, (uint64_t)drops / 2, 0, 0);
        XAHC_TRY(emit(0, 0, (uint32_t)tx, len));
    }
    XAHC_ACCEPT("emitted; cbak may re-emit");
    return 0;
}
