#include "xahc/xahc.h"

/* SC05 NEGATIVE CONTROL #1 — DEFERRED ACCOUNTING (must -> COUNTEREXAMPLE on the hook entry).
 *
 * The bug: the hook EMITS a spend but records NOTHING in this invocation — it defers the
 * accounting to cbak (records spent only when the emit settles). A second hook() invocation
 * that lands before cbak fires sees stale state (spent unchanged) and can emit again =>
 * double-spend past the cap. The reserve-before-emit obligation catches it: an accepting
 * path emits amount > 0 yet the persisted `spent'` equals the prior `spent` (no reservation).
 *
 * Same state layout + param as reentrancy_safe.c.
 */

static inline uint64_t be64(const uint8_t* b) {
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8)  | ((uint64_t)b[7]);
}
static inline void wr64(uint8_t* b, uint64_t v) {
    b[0] = (uint8_t)(v >> 56); b[1] = (uint8_t)(v >> 48);
    b[2] = (uint8_t)(v >> 40); b[3] = (uint8_t)(v >> 32);
    b[4] = (uint8_t)(v >> 24); b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >> 8);  b[7] = (uint8_t)(v);
}
static const uint8_t DST[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};

/* Deferred: cbak is where the spend FINALLY gets recorded (too late). */
int64_t cbak(uint32_t what) {
    uint8_t skey[1] = { 0x01 };
    uint8_t sval[16];
    int64_t srd = state(XAHC_SBUF(sval), XAHC_SBUF(skey));
    if (srd == 16) {
        uint64_t reserved = be64(&sval[0]);
        uint64_t spent    = be64(&sval[8]);
        wr64(&sval[0], reserved);
        wr64(&sval[8], spent + reserved);   /* finally counts it — after the fact */
        XAHC_STATE_SET(skey, sval);
    }
    return 0;
}

int64_t hook(uint32_t reserved_arg) {
    XAHC_HOOK_ENTRY();

    if (otxn_type() != XAHC_ttPAYMENT)
        XAHC_ACCEPT("not a payment");

    uint8_t lim_key[3] = { 'L', 'I', 'M' };
    uint8_t lim_b[8];
    XAHC_HOOK_PARAM_REQUIRE(lim_b, lim_key, 8);
    uint64_t lim = be64(lim_b);

    int64_t drops = xahc_otxn_drops();
    XAHC_REQUIRE(drops >= 0, "native only");
    uint64_t amount = (uint64_t)drops;

    uint8_t skey[1] = { 0x01 };
    uint8_t sval[16];
    int64_t srd = state(XAHC_SBUF(sval), XAHC_SBUF(skey));
    uint64_t spent;
    if (srd == 16) {
        spent = be64(&sval[8]);
    } else if (srd < 0) {
        spent = 0;
    } else {
        rollback((uint32_t)"corrupt state", sizeof("corrupt state"), (int64_t)__LINE__);
        return 0;
    }

    uint64_t remaining = (spent <= lim) ? (lim - spent) : 0;
    XAHC_REQUIRE(amount <= remaining, "over cumulative cap");

    /* BUG: emit WITHOUT recording the spend in this invocation. */
    uint8_t tx[XAHC_PAYMENT_SIZE];
    uint32_t l = xahc_build_payment(tx, DST, amount, 0, 0);
    XAHC_TRY(etxn_reserve(1));
    XAHC_TRY(emit(0, 0, (uint32_t)tx, l));

    XAHC_ACCEPT("emitted, accounting deferred to cbak");
    return 0;
}
