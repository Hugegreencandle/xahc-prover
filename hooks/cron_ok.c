#include "xahc/xahc.h"

/* CORRECT cron-stacking-safe hook: re-arms AT MOST ONE CronSet per invocation.
 *
 * Proves: accept => #(emitted CronSet) <= 1  (prove_cron, K=1). A cron-triggered hook that
 * re-arms exactly once keeps the cron chain linear; emitting >1 per run would stack unboundedly.
 *
 * NOTE: this is a MINIMAL cron-emitter for invariant testing — the emitted blob carries the
 * sfTransactionType field (0x12, value 0x005D = ttCRON_SET 93) which is all prove_cron inspects;
 * it is not a fully-populated, node-valid CronSet (that needs RepeatCount/etc.). The prover
 * records the emit and reads its TransactionType; it does not validate the whole tx. */

static void emit_cron(void) {
    /* sfTransactionType field id 0x12, then UInt16 big-endian 0x005D = CronSet(93); rest zero. */
    uint8_t tx[64] = { 0x12, 0x00, 0x5D };
    XAHC_TRY(emit(0, 0, (uint32_t)tx, sizeof(tx)));
}

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();
    XAHC_TRY(etxn_reserve(1));     /* budget: one emitted txn */
    emit_cron();                   /* re-arm exactly once */
    XAHC_ACCEPT("armed one cron");
    return 0;
}
