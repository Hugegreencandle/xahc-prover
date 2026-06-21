#include "xahc/xahc.h"
/* NEGATIVE CONTROL for prove_qday_freeze. Reads QH (so the invariant APPLIES) but BUGGILY accepts
 * the outgoing tx without requiring the preimage — a quantum thief could drain it. MUST be CEX. */
extern int64_t util_sha512h(uint32_t wp, uint32_t wl, uint32_t rp, uint32_t rl);
#define XAHC_sfInvoiceID ((5U << 16U) + 17U)
int64_t cbak(uint32_t reserved) { return 0; }
int64_t hook(uint32_t reserved){
    XAHC_HOOK_ENTRY();
    uint8_t origin[20], me[20];
    XAHC_OTXN_ACCOUNT(origin);
    hook_account(XAHC_SBUF(me));
    int outgoing=1;
    for(int i=0; XAHC_GUARD(20), i<20; ++i) if(origin[i]!=me[i]) outgoing=0;
    if(!outgoing) XAHC_ACCEPT("incoming");
    uint8_t qh_key[2]={'Q','H'}; uint8_t qh[32];
    XAHC_HOOK_PARAM_REQUIRE(qh, qh_key, 32);
    /* BUG: never reads/hashes a preimage — accepts the outgoing spend unconditionally. */
    (void)qh;
    XAHC_ACCEPT("BUG: outgoing accepted with no preimage check");
    return 0;
}
