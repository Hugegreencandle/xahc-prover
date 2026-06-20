#include "xahc/xahc.h"

/* BUGGY SUBSCRIPTION (no cap gate -> overspends past CAP) — the Cron-native recurring-payment Hook.
 *
 * Deploy on a payer account with a recurring Cron (CronSet: DelaySeconds=period,
 * RepeatCount<=256, StartTime). Each cron fire invokes this hook as a WEAK TSH (post-apply, CANNOT
 * roll back — see docs/CRON-GROUND-TRUTH.md), so SAFETY MUST BE PROVEN, not trusted: a bad emit
 * already executed irreversibly. This hook is built so it is safe on EVERY invocation regardless of
 * trigger, which is the strongest provable claim (the cron is just the schedule).
 *
 * Invariant set (each in the xahc-prover battery):
 *   period-budget : cumulative emitted <= CAP, for ALL inputs (never overpay the subscription total)
 *   dst-lock      : the emitted Payment goes ONLY to the locked payee PAY
 *   nospend       : <= 1 Payment emitted per invocation (no double-pay)
 *
 * HookParameters (install-time):
 *   "PAY" (20-byte account-id)  REQUIRED — the locked payee
 *   "AMT" (8-byte BE drops)     REQUIRED — amount paid each period
 *   "CAP" (8-byte BE drops)     REQUIRED — total lifetime cap (paid never exceeds this)
 * HookState (one entry):
 *   key {0x01} -> value 8 bytes BE = `paid` (cumulative drops emitted so far)
 *
 * Fail CLOSED on any decode/state/overflow anomaly (rollback on the config path; on a cron fire we
 * simply do NOT emit). This is a spending AUTHORITY — when uncertain, it does not pay. */

int64_t cbak(uint32_t reserved) { return 0; }

static inline uint64_t be64(const uint8_t* b) {
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) | ((uint64_t)b[2] << 40) |
           ((uint64_t)b[3] << 32) | ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8)  | ((uint64_t)b[7]);
}
static inline void wr64(uint8_t* b, uint64_t v) {
    b[0] = (uint8_t)(v >> 56); b[1] = (uint8_t)(v >> 48); b[2] = (uint8_t)(v >> 40);
    b[3] = (uint8_t)(v >> 32); b[4] = (uint8_t)(v >> 24); b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >> 8);  b[7] = (uint8_t)(v);
}

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    /* --- required install params --- */
    uint8_t pay_key[3] = { 'P', 'A', 'Y' };
    uint8_t pay[20];
    XAHC_HOOK_PARAM_REQUIRE(pay, pay_key, 20);            /* the locked payee */

    uint8_t amt_key[3] = { 'A', 'M', 'T' };
    uint8_t amt_b[8];
    XAHC_HOOK_PARAM_REQUIRE(amt_b, amt_key, 8);
    uint64_t amt = be64(amt_b);

    uint8_t cap_key[3] = { 'C', 'A', 'P' };
    uint8_t cap_b[8];
    XAHC_HOOK_PARAM_REQUIRE(cap_b, cap_key, 8);
    uint64_t cap = be64(cap_b);

    /* --- read cumulative paid (default 0 if the slot does not exist yet) ---
     * FAIL CLOSED on a corrupt slot: state() returns the slot's byte length, or <0 if absent.
     * srd == 8  -> present & well-formed, use it. srd < 0 -> absent (first fire), paid stays 0.
     * srd >= 0 && != 8 -> the slot exists but is the WRONG length (corrupt / tampered): rolling
     * back rather than silently resetting paid to 0, which would re-open the whole cap (overspend). */
    uint8_t skey[1] = { 0x01 };
    uint8_t sval[8] = { 0 };
    uint64_t paid = 0;
    int64_t srd = state(XAHC_SBUF(sval), XAHC_SBUF(skey));
    if (srd == 8)
        paid = be64(sval);
    else
        XAHC_REQUIRE(srd < 0, "corrupt cumulative-paid slot (present but not 8 bytes)");

    /* --- the safety gate: pay one period iff it stays within the lifetime cap --- */
    uint64_t next = paid + amt;
    /* fail-closed: positive amount, no u64 overflow, and within cap */
    if (amt == 0 || next < paid)  /* BUG: dropped "next > cap" */
        XAHC_ACCEPT("subscription: cap reached or invalid — no payment this fire");

    /* emit exactly ONE capped payment to the locked payee (XAHC_EMIT_PAYMENT reserves 1) */
    XAHC_EMIT_PAYMENT(pay, amt, 0, 0);

    /* advance the cumulative paid; fail closed if the state write fails */
    wr64(sval, next);
    XAHC_REQUIRE(state_set(XAHC_SBUF(sval), XAHC_SBUF(skey)) == 8, "state_set paid failed");

    XAHC_ACCEPT("subscription: paid one period within cap");
    return 0;
}
