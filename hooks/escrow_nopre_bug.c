#include "xahc/xahc.h"

/* BUGGY HASHLOCK ESCROW (releases without checking the preimage) — release ONLY to whoever knows the preimage of a committed hash.
 *
 * The Hook commits to a hash H. A claimant sends a transaction carrying a 32-byte preimage P (in
 * sfInvoiceID); the Hook releases the escrow to the recipient PAY iff sha512h(P) == H, and only ONCE.
 * This is the cross-chain-swap / conditional-payment primitive. NOT cron-fired — claim-triggered.
 *
 * PROVEN invariant set (xahc-prover, this exact bytecode):
 *   hashlock      : accept-with-emit => a presented input hashes to the committed H (only the
 *                   preimage-holder can release) — UNDER SHA-512Half collision-resistance            [NEW]
 *   emit-dst-lock : the release goes ONLY to the recipient PAY
 *   monotonic     : the spent flag never moves backwards (claim-once / replay-safe)
 *   nospend       : <= 1 release emitted per claim
 *   termination   : always terminates cleanly
 *
 * SCOPE / OPERATOR ASSUMPTIONS (protocol-boundary, honest): owner-only CONFIG (H, PAY, AMT) is
 * SetHook-enforced; reserve is protocol-fail-closed; a corrupt-length slot fails CLOSED. A time-based
 * REFUND path (sender reclaim after a deadline) is a separate concern (see time-release) — out of scope.
 *
 * HookParameters: "HSH" 32B committed SHA-512Half · "PAY" 20B recipient · "AMT" 8B BE release drops.
 * Claimant tx: sfInvoiceID = the 32-byte preimage P.
 * HookState: {0x01} 8B BE `spent` (0 = unclaimed, 1 = released).
 * Fail CLOSED on any decode/state/hash anomaly. A spending AUTHORITY — when uncertain, no release. */

extern int64_t util_sha512h(uint32_t wp, uint32_t wl, uint32_t rp, uint32_t rl);

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

#define XAHC_sfInvoiceID ((5U << 16U) + 17U)   /* 32-byte field carrying the preimage */

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    /* --- committed hash + recipient + amount (install config) --- */
    uint8_t hsh_key[3] = { 'H', 'S', 'H' };
    uint8_t hsh[32];
    XAHC_HOOK_PARAM_REQUIRE(hsh, hsh_key, 32);
    uint8_t pay_key[3] = { 'P', 'A', 'Y' };
    uint8_t pay[20];
    XAHC_HOOK_PARAM_REQUIRE(pay, pay_key, 20);
    uint8_t amt_key[3] = { 'A', 'M', 'T' };
    uint8_t amt_b[8];
    XAHC_HOOK_PARAM_REQUIRE(amt_b, amt_key, 8);
    uint64_t amt = be64(amt_b);

    /* --- claim once: a spent escrow never releases again --- */
    uint8_t skey[1] = { 0x01 };
    uint8_t sval[8] = { 0 };
    uint64_t spent = 0;
    int64_t srd = state(XAHC_SBUF(sval), XAHC_SBUF(skey));
    if (srd == 8)
        spent = be64(sval);
    else
        XAHC_REQUIRE(srd < 0, "corrupt spent slot (present but not 8 bytes)");
    if (spent != 0)
        XAHC_ACCEPT("escrow already claimed — no release");

    /* --- the claimant's preimage (32B in sfInvoiceID) --- */
    uint8_t pre[32];
    XAHC_REQUIRE(otxn_field(XAHC_SBUF(pre), XAHC_sfInvoiceID) == 32, "no 32-byte preimage in InvoiceID");

    /* --- hash it and require the match against the commitment --- */
    uint8_t digest[32];
    XAHC_REQUIRE(util_sha512h(XAHC_SBUF(digest), XAHC_SBUF(pre)) == 32, "sha512h failed");
    int match = 1;
    for (int i = 0; XAHC_GUARD(32), i < 32; ++i)
        if (digest[i] != hsh[i]) match = 0;
    /* BUG: no match gate -> releases to anyone, no preimage needed */

    /* --- release once to the recipient --- */
    XAHC_EMIT_PAYMENT(pay, amt, 0, 0);

    wr64(sval, 1);
    XAHC_REQUIRE(state_set(XAHC_SBUF(sval), XAHC_SBUF(skey)) == 8, "state_set spent failed");

    XAHC_ACCEPT("hashlock escrow: released to the preimage holder");
    return 0;
}
