#include "xahc/xahc.h"

/* qkey_guard_unsafe — NEGATIVE CONTROL for prove_master_disuse.
 *
 * Reads the SAME inputs as qkey_guard (otxn_type, MPK param, SigningPubKey) so the
 * master-disuse invariant APPLIES — but it is BUGGY: it forgets to reject the master
 * key and accepts the ordinary tx anyway. prove_master_disuse MUST return a
 * COUNTEREXAMPLE here. If it ever reports PROVEN on this hook, the driver is unsound. */

#define tt_SET_REGULAR_KEY 5
#define tt_SIGNER_LIST_SET 12
#define tt_SET_HOOK        22

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    uint8_t origin[20], me[20];
    XAHC_OTXN_ACCOUNT(origin);
    hook_account(XAHC_SBUF(me));
    int outgoing = 1;
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i)
        if (origin[i] != me[i]) outgoing = 0;
    if (!outgoing)
        XAHC_ACCEPT("incoming");

    int64_t tt = otxn_type();
    if (tt == tt_SET_REGULAR_KEY || tt == tt_SIGNER_LIST_SET || tt == tt_SET_HOOK)
        XAHC_ACCEPT("key/hook management");

    uint8_t mpk_key[3] = { 'M', 'P', 'K' };
    uint8_t mpk[33];
    XAHC_HOOK_PARAM_REQUIRE(mpk, mpk_key, 33);

    uint8_t spk[33];
    int64_t spk_len = otxn_field(XAHC_SBUF(spk), sfSigningPubKey);
    if (spk_len != 33)
        XAHC_ACCEPT("multi-signed");

    int is_master = 1;
    for (int i = 0; XAHC_GUARD(33), i < 33; ++i)
        if (spk[i] != mpk[i]) is_master = 0;

    /* BUG: should be XAHC_REQUIRE(!is_master, ...). Accepts master-signed anyway. */
    (void)is_master;
    XAHC_ACCEPT("BUG: accepts regardless of signing key");
    return 0;
}
