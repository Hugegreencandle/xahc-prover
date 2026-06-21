#include "xahc/xahc.h"

/* qkey_guard — quantum-readiness key-rotation enforcement Hook.
 *
 * Install on an account to forbid the long-lived MASTER key from signing
 * ordinary transactions, forcing routine activity through a rotatable regular
 * key or signer list. The master key is the one key that can never be rotated
 * (it hashes to the AccountID); minimizing its use is the near-term defense
 * against Harvest-Now-Decrypt-Later. This is an on-ledger guarantee XRPL
 * accounts cannot make — only a Xahau Hook can police the signing key.
 *
 *   HookParameter "MPK" (33-byte master public key)  REQUIRED
 *     The account owner supplies their own master pubkey at install time.
 *     (No host fn derives an AccountID from a pubkey on-chain — RIPEMD160 is
 *      not exposed — so the master key is identified by direct byte compare.)
 *
 * Decision for an OUTGOING transaction:
 *   1. key/hook management (SetRegularKey, SignerListSet, SetHook) -> ACCEPT
 *        (always — the brick-safety escape hatch; the owner can always
 *         (re)establish a rotatable key and can remove this hook)
 *   2. multi-signed (empty SigningPubKey)                          -> ACCEPT
 *   3. SigningPubKey != MPK (regular-key signed)                   -> ACCEPT
 *   4. SigningPubKey == MPK (master signed, non-management)        -> ROLLBACK
 *
 * Target invariant (xahau-prove): accept ⟹ (otxn_type ∈ {5,12,22})
 *   ∨ (SigningPubKey length != 33) ∨ (SigningPubKey != MPK).
 * i.e. no accepted ordinary tx is signed by the master key.
 *
 * Soundness note: the protocol validates a tx's signature before a hook runs,
 * so a single-signed tx always carries a valid 33-byte SigningPubKey and a
 * multi-signed tx carries an empty one — the length != 33 branch is exactly
 * the multi-sign path, not a forgeable bypass.
 *
 * Scope / audit caveats (must ride on any certificate):
 *   - This is master-key DISUSE, not master-key COMPROMISE defense. The
 *     management allowlist (SetRegularKey/SignerListSet/SetHook) is itself
 *     master-signable, so a holder of the master key can still rotate keys or
 *     remove this hook. The guard reduces routine master-key exposure (HNDL);
 *     it does not stop an already-compromised master key.
 *   - Enforcement assumes the SetHook HookOn mask fires this hook on every
 *     non-management tx type. A HookOn that skips a type = no enforcement there;
 *     verify HookOn at deploy time.
 *   - MPK is owner-asserted at install. No host fn derives an AccountID from a
 *     public key on-chain (RIPEMD160 is not exposed), so a wrong MPK silently
 *     disables protection. MPK must be exactly the 33-byte master public key.
 */

#define tt_SET_REGULAR_KEY 5
#define tt_SIGNER_LIST_SET 12
#define tt_SET_HOOK        22

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    /* Only police transactions this account originates. */
    uint8_t origin[20], me[20];
    XAHC_OTXN_ACCOUNT(origin);
    hook_account(XAHC_SBUF(me));
    int outgoing = 1;
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i)
        if (origin[i] != me[i]) outgoing = 0;
    if (!outgoing)
        XAHC_ACCEPT("incoming");

    /* (1) Key/hook management always passes — the account can never be bricked
     * or the hook made irremovable, even if MPK is misconfigured. */
    int64_t tt = otxn_type();
    if (tt == tt_SET_REGULAR_KEY || tt == tt_SIGNER_LIST_SET || tt == tt_SET_HOOK)
        XAHC_ACCEPT("key/hook management");

    /* Required master public key (33 bytes), supplied by the owner at install. */
    uint8_t mpk_key[3] = { 'M', 'P', 'K' };
    uint8_t mpk[33];
    XAHC_HOOK_PARAM_REQUIRE(mpk, mpk_key, 33);

    /* (2) Read the triggering tx's signing public key.
     * Empty (len != 33) => multi-signed via the signer list (rotatable). */
    uint8_t spk[33];
    int64_t spk_len = otxn_field(XAHC_SBUF(spk), sfSigningPubKey);
    if (spk_len != 33)
        XAHC_ACCEPT("multi-signed");

    /* (3)/(4) Is it the unrotatable master key? */
    int is_master = 1;
    for (int i = 0; XAHC_GUARD(33), i < 33; ++i)
        if (spk[i] != mpk[i]) is_master = 0;
    XAHC_REQUIRE(!is_master,
                 "master key may sign only key/hook management — rotate to a regular key");

    XAHC_ACCEPT("regular-key signed");
    return 0;
}
