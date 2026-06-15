#include "xahc/xahc.h"

/* ADVERSARIAL foreign-authz attack — TWO foreign-state writes, but the hook only
 * checks the FIRST one's return code. The SECOND write is unauthorized-capable
 * (its return is ignored), yet the hook accepts. Correct verdict: COUNTEREXAMPLE
 * (2) — an accept is reachable while the second foreign-set was NOT_AUTHORIZED. */

extern int64_t state_foreign_set(uint32_t read_ptr, uint32_t read_len,
                                 uint32_t kread_ptr, uint32_t kread_len,
                                 uint32_t nread_ptr, uint32_t nread_len,
                                 uint32_t aread_ptr, uint32_t aread_len);

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    uint8_t val[8]  = {0,0,0,0,0,0,0,1};
    uint8_t key[4]  = {'F','K','E','Y'};
    uint8_t ns[32]  = {0};
    uint8_t acctA[20] = {0xAA,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19};
    uint8_t acctB[20] = {0xBB,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19};

    int64_t rc1 = state_foreign_set((uint32_t)val, sizeof(val),
                                    (uint32_t)key, sizeof(key),
                                    (uint32_t)ns, sizeof(ns),
                                    (uint32_t)acctA, sizeof(acctA));
    XAHC_REQUIRE(rc1 >= 0, "first foreign write not authorized");

    /* BUG: second foreign write's return is IGNORED. */
    state_foreign_set((uint32_t)val, sizeof(val),
                      (uint32_t)key, sizeof(key),
                      (uint32_t)ns, sizeof(ns),
                      (uint32_t)acctB, sizeof(acctB));

    XAHC_ACCEPT("accepted (second foreign write unchecked!)");
    return 0;
}
