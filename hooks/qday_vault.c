#include "xahc/xahc.h"

/* qday_vault — Q-DAY CONTINGENCY vault (post-quantum recovery freeze, Hook form).
 *
 * The on-ledger analog of Ripple's PQC Phase-1 "prove key ownership without the key": the owner
 * commits a quantum-safe secret's hash QH = sha512h(secret) at install. From then on, EVERY outgoing
 * transaction must carry the matching preimage (32 bytes in sfInvoiceID) or it is rolled back. A
 * quantum adversary who has BROKEN the account's ed25519/secp256k1 key with Shor still cannot move
 * funds — they do not know the preimage, and finding one is a hash pre-image search (Grover-only,
 * ~2^128, infeasible). The legitimate owner keeps the secret OFFLINE (quantum-safe) and reveals it
 * only to spend / migrate to a fresh account.
 *
 *   HookParameter "QH" (32-byte committed sha512h of the secret)  REQUIRED
 *   Spending tx: sfInvoiceID = the 32-byte preimage.
 *
 * Decision for an OUTGOING transaction:
 *   - preimage present AND sha512h(preimage) == QH  -> ACCEPT (quantum-safe spend authorized)
 *   - otherwise                                      -> ROLLBACK
 * Incoming transactions are not guarded.
 *
 * Target invariant (xahau-prove `qday-freeze`): accept AND outgoing => a presented input hashes to QH.
 * UNDER sha512h collision-resistance (the engine models util_sha512h as an injective uninterpreted fn).
 *
 * NO management escape hatch BY DESIGN: a quantum attacker with the broken ECC key must not be able to
 * SetRegularKey/SetHook their way around the vault, so those too require the preimage. The cost is that
 * losing the secret loses access — the same contract as losing a private key. This is a cold/high-value
 * insurance Hook, armed deliberately; arming it early is the protection (a dormant lock guards nothing).
 *
 * Audit scope (rides on any cert): the proof shows the spend requires a preimage of the COMMITTED QH; it
 * does NOT verify QH commits to your genuine secret (commit the right one, keep it offline). The
 * no-escape-hatch guarantee assumes HookOn subscribes this hook to fund-moving AND SetRegularKey/SetHook.
 */

extern int64_t util_sha512h(uint32_t wp, uint32_t wl, uint32_t rp, uint32_t rl);

#define XAHC_sfInvoiceID ((5U << 16U) + 17U)   /* 32-byte field carrying the preimage */

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    /* Only guard transactions this account ORIGINATES. */
    uint8_t origin[20], me[20];
    XAHC_OTXN_ACCOUNT(origin);
    hook_account(XAHC_SBUF(me));
    int outgoing = 1;
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i)
        if (origin[i] != me[i]) outgoing = 0;
    if (!outgoing)
        XAHC_ACCEPT("incoming");

    /* Committed quantum-safe hash (install config). */
    uint8_t qh_key[2] = { 'Q', 'H' };
    uint8_t qh[32];
    XAHC_HOOK_PARAM_REQUIRE(qh, qh_key, 32);

    /* The preimage presented by the spender (32B in sfInvoiceID). */
    uint8_t pre[32];
    XAHC_REQUIRE(otxn_field(XAHC_SBUF(pre), XAHC_sfInvoiceID) == 32, "no 32-byte quantum-safe preimage in InvoiceID");

    /* Hash it and require the match against the commitment. */
    uint8_t digest[32];
    XAHC_REQUIRE(util_sha512h(XAHC_SBUF(digest), XAHC_SBUF(pre)) == 32, "sha512h failed");
    int match = 1;
    for (int i = 0; XAHC_GUARD(32), i < 32; ++i)
        if (digest[i] != qh[i]) match = 0;
    XAHC_REQUIRE(match, "wrong preimage — the quantum-safe secret is required to move funds");

    XAHC_ACCEPT("preimage verified — quantum-safe spend authorized");
    return 0;
}
