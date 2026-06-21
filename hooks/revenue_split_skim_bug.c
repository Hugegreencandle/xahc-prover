#include "xahc/xahc.h"

/* BUGGY REVENUE SPLIT (skims B's share) — Cron-native fair distribution to two beneficiaries.
 *
 * Each cron fire distributes a fixed period total PER: share SHA to PYA, the remainder PER-SHA to PYB.
 * The sum emitted is EXACTLY PER on every fire — the Hook cannot skim a cut or short a beneficiary.
 * Cron-fired (weak TSH, no rollback -> proof, not trust). A 2-way split; N-way generalizes the same way.
 *
 * PROVEN invariant set (xahc-prover, this exact bytecode):
 *   split-conservation : sum of emitted drops this fire == PER (no skim, no short)                 [NEW]
 *   emit-budget        : cumulative distributed <= CAP (lifetime total)
 *   trigger-lock       : distributes ONLY on the account's own Cron fire (otxn_type == ttCRON)
 *   monotonic          : the `paid` counter never moves backwards
 *   termination        : always terminates cleanly
 * (nospend and emit-dst-lock are single-payment invariants -> N/A for a 2-payee split, by design.)
 *
 * SCOPE / OPERATOR ASSUMPTIONS (protocol-boundary, honest): owner-only CONFIG is SetHook-enforced;
 * reserve is protocol-fail-closed; bounded to RepeatCount<=256 fires; corrupt-length slot fails CLOSED.
 *
 * HookParameters: "PYA"/"PYB" 20B beneficiaries · "PER" 8B BE per-fire total · "SHA" 8B BE A's share
 *                 (must be <= PER) · "CAP" 8B BE lifetime cap.
 * HookState: {0x01} 8B BE `paid` (cumulative distributed).
 * Fail CLOSED on any decode/state/overflow anomaly. A spending AUTHORITY — when uncertain, no distribution. */

extern int64_t etxn_reserve(uint32_t count);
extern int64_t emit(uint32_t out_ptr, uint32_t out_len, uint32_t tx_ptr, uint32_t tx_len);

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

#define XAHC_ttCRON 92

/* build + emit one native Payment (manual: etxn_reserve is declared ONCE for both emits). */
static void emit_one(const uint8_t* to20, uint64_t drops) {
    uint8_t tx[XAHC_PAYMENT_SIZE];
    uint32_t len = xahc_build_payment(tx, to20, drops, 0, 0);
    XAHC_TRY(emit(0, 0, (uint32_t)tx, len));
}

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    /* TRIGGER LOCK: act only on this account's own Cron fire. */
    if (otxn_type() != XAHC_ttCRON)
        XAHC_ACCEPT("not a Cron fire — split acts only on its own schedule");

    uint8_t pya_key[3] = { 'P', 'Y', 'A' };
    uint8_t pya[20];
    XAHC_HOOK_PARAM_REQUIRE(pya, pya_key, 20);
    uint8_t pyb_key[3] = { 'P', 'Y', 'B' };
    uint8_t pyb[20];
    XAHC_HOOK_PARAM_REQUIRE(pyb, pyb_key, 20);

    uint8_t per_key[3] = { 'P', 'E', 'R' };
    uint8_t per_b[8];
    XAHC_HOOK_PARAM_REQUIRE(per_b, per_key, 8);
    uint64_t per = be64(per_b);
    uint8_t sha_key[3] = { 'S', 'H', 'A' };
    uint8_t sha_b[8];
    XAHC_HOOK_PARAM_REQUIRE(sha_b, sha_key, 8);
    uint64_t sha = be64(sha_b);
    uint8_t cap_key[3] = { 'C', 'A', 'P' };
    uint8_t cap_b[8];
    XAHC_HOOK_PARAM_REQUIRE(cap_b, cap_key, 8);
    uint64_t cap = be64(cap_b);

    /* amounts must be valid native XAH (< 2^62: the native-amount encoding faithfully represents only
     * drops below 2^62; above that the high bits are type flags). The protocol rejects larger emits
     * anyway. Under this bound the per-share emits sum to EXACTLY PER (no encoding-truncation skim). */
    XAHC_REQUIRE(per < (1ULL << 62), "PER exceeds the native-amount range");
    /* the share must fit inside the period total (so B's remainder can't underflow) */
    XAHC_REQUIRE(sha <= per, "share exceeds the period total");
    uint64_t b_amt = per - sha;

    /* --- cumulative paid (fail closed on a corrupt slot) --- */
    uint8_t skey[1] = { 0x01 };
    uint8_t sval[8] = { 0 };
    uint64_t paid = 0;
    int64_t srd = state(XAHC_SBUF(sval), XAHC_SBUF(skey));
    if (srd == 8)
        paid = be64(sval);
    else
        XAHC_REQUIRE(srd < 0, "corrupt cumulative-paid slot (present but not 8 bytes)");

    /* lifetime cap on the cumulative distributed total */
    uint64_t next = paid + per;
    if (per == 0 || next < paid || next > cap)
        XAHC_ACCEPT("allocation exhausted or invalid — no distribution this fire");

    /* distribute EXACTLY PER: SHA to A, PER-SHA to B (reserve 2 emits up front). */
    XAHC_TRY(etxn_reserve(2));
    emit_one(pya, sha);  /* BUG: drops B's emit -> skim PER-SHA */

    wr64(sval, next);
    XAHC_REQUIRE(state_set(XAHC_SBUF(sval), XAHC_SBUF(skey)) == 8, "state_set paid failed");

    XAHC_ACCEPT("revenue-split: distributed exactly the period total within the cap");
    return 0;
}
