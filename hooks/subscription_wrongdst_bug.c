#include "xahc/xahc.h"

/* BUGGY SUBSCRIPTION (pays attacker) — the Cron-native recurring-payment Hook.
 *
 * Deploy on a payer account with a recurring Cron (CronSet: DelaySeconds=period,
 * RepeatCount<=256, StartTime). Each cron fire invokes this hook as a WEAK TSH (post-apply, CANNOT
 * roll back — see docs/CRON-GROUND-TRUTH.md), so SAFETY MUST BE PROVEN, not trusted: a bad emit
 * already executed irreversibly. This hook is built so it is safe on EVERY invocation regardless of
 * trigger, which is the strongest provable claim (the cron is just the schedule).
 *
 * PROVEN invariant set (xahc-prover, each PROVEN for this exact bytecode):
 *   emit-budget   : cumulative emitted <= CAP, for ALL inputs (never overpay the subscription total)
 *   emit-dst-lock : every emitted Payment goes ONLY to the locked payee PAY
 *   nospend       : <= 1 Payment emitted per invocation (no double-pay)
 *   monotonic     : the `paid` counter never moves backwards (replay/rollback-safe)
 *   termination   : no guard-violation on any input (always terminates cleanly)
 *
 * SCOPE / OPERATOR ASSUMPTIONS (NOT hook-level proofs — the honest trust boundary):
 *   - owner-only config: PROTOCOL-enforced. PAY/AMT/CAP are HookParameters set via SetHook, which only
 *     the account owner can submit. The hook performs no origin check because none is needed.
 *   - reserve: NOT proven here. If an emit would breach the account reserve it fails at the protocol
 *     (the subscription stalls — fail-safe; it never overpays).
 *   - 256-fire limit: the hook NEVER re-arms (emits no CronSet). The Cron protocol auto-recurs up to
 *     RepeatCount (<=256, operator-set), then stops. To run longer, re-arm/re-deploy.
 *   - emit-vs-apply: emit-budget proves emitted<=CAP. If an emitted Payment later fails to APPLY,
 *     `paid` over-counts (the subscription pays LESS — fail-safe; never more).
 *   - state model: proofs cover the present 8-byte slot; a present-but-wrong-length slot fails CLOSED
 *     (rollback), not a silent reset.
 *
 * HookParameters (install-time): "PAY" 20B account-id · "AMT" 8B BE drops/period · "CAP" 8B BE lifetime cap.
 * HookState: key {0x01} -> 8 bytes BE `paid` (cumulative drops emitted).
 * Fail CLOSED on any decode/state/overflow anomaly. This is a spending AUTHORITY — when uncertain, it does not pay. */

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

#define XAHC_ttCRON 92   /* the Cron pseudo-tx (verified vs xahau TRANSACTION_TYPES; CronSet=93) */

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    /* TRIGGER LOCK: act ONLY on this account's own scheduled Cron fire. ttCRON fires the owner's hook
     * as a weak TSH; any OTHER tx touching the account (an incoming Payment, an Invoke, etc.) must NOT
     * drive a subscription payment. Without this gate a non-owner could trigger an (capped, payee-locked
     * but still unintended) emit by sending the account a tx. */
    if (otxn_type() != XAHC_ttCRON)
        XAHC_ACCEPT("not a Cron fire — the subscription only acts on its own schedule");

    /* --- required install params --- */
    uint8_t pay_key[3] = { 'P', 'A', 'Y' };
    uint8_t pay[20];
    XAHC_HOOK_PARAM_REQUIRE(pay, pay_key, 20);
    uint8_t atk_key[3]={'A','T','K'}; uint8_t atk[20];
    XAHC_HOOK_PARAM_REQUIRE(atk, atk_key, 20);  /* BUG: attacker payee */

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
    if (amt == 0 || next < paid || next > cap)
        XAHC_ACCEPT("subscription: cap reached or invalid — no payment this fire");

    /* emit exactly ONE capped payment to the locked payee (XAHC_EMIT_PAYMENT reserves 1) */
    XAHC_EMIT_PAYMENT(atk, amt, 0, 0);  /* BUG */

    /* advance the cumulative paid; fail closed if the state write fails */
    wr64(sval, next);
    XAHC_REQUIRE(state_set(XAHC_SBUF(sval), XAHC_SBUF(skey)) == 8, "state_set paid failed");

    XAHC_ACCEPT("subscription: paid one period within cap");
    return 0;
}
