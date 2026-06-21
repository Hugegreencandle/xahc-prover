#include "xahc/xahc.h"

/* BUGGY MULTISIG (releases on first approval, ignores THR) — release ONLY after >= THR distinct authorized signers approve.
 *
 * Each authorized signer (SG1/SG2/SG3) approves by sending a transaction; the Hook sets that signer's
 * bit in an approval mask. Once popcount(mask) reaches THR, it releases AMT to PAY, once. A 3-signer
 * instance; SGM (the designated-bit mask) generalizes the count to M signers. Claim/approval-triggered.
 *
 * PROVEN invariant set (xahc-prover, this exact bytecode):
 *   quorum        : accept-with-emit => popcount(approval_mask & SGM) >= THR (>= THR distinct approvals) [NEW]
 *   emit-dst-lock : the release goes ONLY to the recipient PAY
 *   monotonic     : the released flag never moves backwards (release-once / replay-safe)
 *   nospend       : <= 1 release emitted per trigger
 *   termination   : always terminates cleanly
 * COMPANION (separate authz property): only signer i can set bit i — enforced by the origin check below.
 *
 * SCOPE / OPERATOR ASSUMPTIONS (protocol-boundary, honest): owner-only CONFIG (signers, THR, SGM, PAY,
 * AMT) is SetHook-enforced; reserve is protocol-fail-closed; corrupt-length slot fails CLOSED. The mask
 * is sanitized to SGM on every write, so a junk prior can't inflate the count. Release-once relies on
 * Xahau emit/accept ATOMICITY (emit + released-flag commit together or roll back together).
 *
 * HookParameters: "SG1"/"SG2"/"SG3" 20B signers · "THR" 8B BE threshold · "SGM" 8B BE designated-bit
 *                 mask (e.g. 0x07 for 3 signers) · "PAY" 20B recipient · "AMT" 8B BE drops.
 * HookState: {0x01} 8B BE approval mask · {0x02} 8B BE released (0 = open, 1 = released).
 * Fail CLOSED on any decode/state anomaly. A spending AUTHORITY — when uncertain, no release. */

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

    /* --- config: signers, threshold, designated-bit mask, recipient, amount --- */
    uint8_t sg1_key[3] = { 'S', 'G', '1' }, sg1[20]; XAHC_HOOK_PARAM_REQUIRE(sg1, sg1_key, 20);
    uint8_t sg2_key[3] = { 'S', 'G', '2' }, sg2[20]; XAHC_HOOK_PARAM_REQUIRE(sg2, sg2_key, 20);
    uint8_t sg3_key[3] = { 'S', 'G', '3' }, sg3[20]; XAHC_HOOK_PARAM_REQUIRE(sg3, sg3_key, 20);
    uint8_t thr_key[3] = { 'T', 'H', 'R' }, thr_b[8]; XAHC_HOOK_PARAM_REQUIRE(thr_b, thr_key, 8);
    uint64_t thr = be64(thr_b);
    uint8_t sgm_key[3] = { 'S', 'G', 'M' }, sgm_b[8]; XAHC_HOOK_PARAM_REQUIRE(sgm_b, sgm_key, 8);
    uint64_t sgm = be64(sgm_b);
    uint8_t pay_key[3] = { 'P', 'A', 'Y' }, pay[20]; XAHC_HOOK_PARAM_REQUIRE(pay, pay_key, 20);
    uint8_t amt_key[3] = { 'A', 'M', 'T' }, amt_b[8]; XAHC_HOOK_PARAM_REQUIRE(amt_b, amt_key, 8);
    uint64_t amt = be64(amt_b);

    /* --- release-once: a released treasury never releases again --- */
    uint8_t rkey[1] = { 0x02 }, rval[8] = { 0 };
    uint64_t released = 0;
    int64_t rrd = state(XAHC_SBUF(rval), XAHC_SBUF(rkey));
    if (rrd == 8) released = be64(rval);
    else XAHC_REQUIRE(rrd < 0, "corrupt released slot (present but not 8 bytes)");
    if (released != 0)
        XAHC_ACCEPT("treasury already released — no further action");

    /* --- which authorized signer is approving? (only signer i may set bit i) --- *
     * Three SEPARATE inline compares so each XAHC_GUARD is its own __COUNTER__ guard point (a 3x-called
     * helper would share one guard id and blow its budget). */
    uint8_t origin[20];
    XAHC_OTXN_ACCOUNT(origin);
    int e1 = 1, e2 = 1, e3 = 1;
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i) if (sg1[i] != origin[i]) e1 = 0;
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i) if (sg2[i] != origin[i]) e2 = 0;
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i) if (sg3[i] != origin[i]) e3 = 0;
    uint64_t bit;
    if (e1) bit = 1ULL << 0;
    else if (e2) bit = 1ULL << 1;
    else if (e3) bit = 1ULL << 2;
    else XAHC_ACCEPT("not an authorized signer — no-op");

    /* --- record the approval (sanitize to the designated bits) --- */
    uint8_t mkey[1] = { 0x01 }, mval[8] = { 0 };
    uint64_t mask = 0;
    int64_t mrd = state(XAHC_SBUF(mval), XAHC_SBUF(mkey));
    if (mrd == 8) mask = be64(mval);
    else XAHC_REQUIRE(mrd < 0, "corrupt mask slot (present but not 8 bytes)");
    uint64_t new_mask = (mask | bit) & sgm;        /* junk outside SGM can never count */
    wr64(mval, new_mask);
    XAHC_REQUIRE(state_set(XAHC_SBUF(mval), XAHC_SBUF(mkey)) == 8, "state_set mask failed");

    /* --- count distinct approvals; release only at quorum --- */
    uint64_t count = 0;
    for (int i = 0; XAHC_GUARD(8), i < 8; ++i)
        count += (new_mask >> i) & 1ULL;
    if (count < 1)  /* BUG: releases on the FIRST approval, ignoring THR */
        XAHC_ACCEPT("approval recorded");

    /* --- quorum met: release once to the recipient --- */
    XAHC_EMIT_PAYMENT(pay, amt, 0, 0);
    wr64(rval, 1);
    XAHC_REQUIRE(state_set(XAHC_SBUF(rval), XAHC_SBUF(rkey)) == 8, "state_set released failed");

    XAHC_ACCEPT("multisig treasury: released at quorum");
    return 0;
}
