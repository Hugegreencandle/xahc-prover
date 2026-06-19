#include "xahc/xahc.h"

/* BUGGY cron-stacking hook: re-arms TWICE per invocation -> the pending-cron set grows every
 * cycle (unbounded stacking — the hook-side analogue of the protocol fixCronStacking bug).
 *
 * prove_cron (K=1) must return COUNTEREXAMPLE: an accepting path emits 2 CronSet txns. */

static void emit_cron(void) {
    uint8_t tx[64] = { 0x12, 0x00, 0x5D };   /* sfTransactionType = ttCRON_SET (93) */
    XAHC_TRY(emit(0, 0, (uint32_t)tx, sizeof(tx)));
}

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();
    XAHC_TRY(etxn_reserve(2));
    emit_cron();                   /* re-arm... */
    emit_cron();                   /* ...AND AGAIN -> stacking */
    XAHC_ACCEPT("armed two crons (BUG)");
    return 0;
}
