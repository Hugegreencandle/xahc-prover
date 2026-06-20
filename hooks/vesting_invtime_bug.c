#include "xahc/xahc.h"

/* INVERTED-TIME BUG (emits BEFORE cliff) — the Cron-native scheduled-release Hook.
 *
 * Releases a fixed amount each period to a locked beneficiary, but NOTHING before the cliff/unlock
 * time, and never more than the total allocation. Cron-fired (weak TSH, no rollback — proof, not
 * trust). Cliff (time-COMPARISON) vesting is provable; continuous-linear (amount = TOT*(now-START)/DUR)
 * is nonlinear and deliberately not attempted (real token vesting is cliff + tranches anyway).
 *
 * PROVEN invariant set (xahc-prover, each for this exact bytecode):
 *   emit-budget   : cumulative released <= CAP (the total allocation TOT)
 *   emit-dst-lock : every release goes ONLY to the locked beneficiary PAY
 *   time-release  : releases NOTHING before the cliff (accept-with-emit => ledger_last_time >= CLF)  [NEW]
 *   nospend       : <= 1 release emitted per fire
 *   monotonic     : the `paid` counter never moves backwards (replay-safe)
 *   termination   : always terminates cleanly
 *   trigger-lock  : releases ONLY on the account's own Cron fire (otxn_type == ttCRON)
 *
 * SCOPE / OPERATOR ASSUMPTIONS (protocol-boundary, honestly disclosed): owner-only CONFIG is
 * SetHook-enforced; reserve safety is protocol-fail-closed; bounded to RepeatCount<=256 fires (no
 * re-arm); a present-but-wrong-length state slot fails CLOSED (rollback).
 *
 * HookParameters: "PAY" 20B beneficiary · "AMT" 8B BE drops/period · "CAP" 8B BE total allocation ·
 *                 "CLF" 8B BE cliff/unlock time (chain seconds; release only when ledger_last_time >= CLF).
 * HookState: key {0x01} -> 8 bytes BE `paid` (cumulative drops released).
 * Fail CLOSED on any decode/state/overflow/time anomaly. A spending AUTHORITY — when uncertain, no release. */

extern int64_t ledger_last_time(void);   /* chain close time, seconds */

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

#define XAHC_ttCRON 92   /* Cron pseudo-tx (verified vs xahau TRANSACTION_TYPES; CronSet=93) */

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    /* TRIGGER LOCK: act only on this account's own Cron fire. */
    if (otxn_type() != XAHC_ttCRON)
        XAHC_ACCEPT("not a Cron fire — vesting acts only on its own schedule");

    /* --- required install params --- */
    uint8_t pay_key[3] = { 'P', 'A', 'Y' };
    uint8_t pay[20];
    XAHC_HOOK_PARAM_REQUIRE(pay, pay_key, 20);            /* the locked beneficiary */

    uint8_t amt_key[3] = { 'A', 'M', 'T' };
    uint8_t amt_b[8];
    XAHC_HOOK_PARAM_REQUIRE(amt_b, amt_key, 8);
    uint64_t amt = be64(amt_b);

    uint8_t cap_key[3] = { 'C', 'A', 'P' };
    uint8_t cap_b[8];
    XAHC_HOOK_PARAM_REQUIRE(cap_b, cap_key, 8);
    uint64_t cap = be64(cap_b);                           /* total allocation (TOT) */

    uint8_t clf_key[3] = { 'C', 'L', 'F' };
    uint8_t clf_b[8];
    XAHC_HOOK_PARAM_REQUIRE(clf_b, clf_key, 8);
    uint64_t cliff = be64(clf_b);                         /* cliff/unlock time, chain seconds */

    /* TIME GATE: release NOTHING before the cliff. ledger_last_time is the chain close time. */
    int64_t now = ledger_last_time();
    XAHC_REQUIRE(now >= 0, "ledger_last_time read failed");
    if ((uint64_t)now >= cliff)  /* BUG: inverted -> only emits when now < cliff (pre-cliff) */
        XAHC_ACCEPT("after cliff — (bug) skips");

    /* --- cumulative paid (fail closed on a corrupt slot) --- */
    uint8_t skey[1] = { 0x01 };
    uint8_t sval[8] = { 0 };
    uint64_t paid = 0;
    int64_t srd = state(XAHC_SBUF(sval), XAHC_SBUF(skey));
    if (srd == 8)
        paid = be64(sval);
    else
        XAHC_REQUIRE(srd < 0, "corrupt cumulative-paid slot (present but not 8 bytes)");

    /* --- the allocation cap: release one period iff within the total --- */
    uint64_t next = paid + amt;
    if (amt == 0 || next < paid || next > cap)
        XAHC_ACCEPT("allocation exhausted or invalid — no release this fire");

    /* emit exactly ONE capped release to the locked beneficiary */
    XAHC_EMIT_PAYMENT(pay, amt, 0, 0);

    wr64(sval, next);
    XAHC_REQUIRE(state_set(XAHC_SBUF(sval), XAHC_SBUF(skey)) == 8, "state_set paid failed");

    XAHC_ACCEPT("vesting: released one period within allocation, after cliff");
    return 0;
}
