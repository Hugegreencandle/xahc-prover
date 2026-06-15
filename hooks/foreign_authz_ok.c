#include "xahc/xahc.h"

/* CORRECT foreign-state write: the hook writes ANOTHER account's state via
 * state_foreign_set and CHECKS the host return — if the target account has not
 * authorized this hook with a HookGrant, the host returns NOT_AUTHORIZED (-34)
 * and the hook rolls back. Only an authorized (granted) write proceeds to accept. */

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
    uint8_t ns[32]  = {0};                 /* namespace */
    uint8_t acct[20] = {0xAA,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19}; /* foreign account A */

    int64_t rc = state_foreign_set((uint32_t)val, sizeof(val),
                                   (uint32_t)key, sizeof(key),
                                   (uint32_t)ns, sizeof(ns),
                                   (uint32_t)acct, sizeof(acct));
    /* AUTHORIZATION CHECK: a negative return = NOT_AUTHORIZED (no grant) -> reject. */
    XAHC_REQUIRE(rc >= 0, "foreign-state write not authorized");

    XAHC_ACCEPT("authorized foreign-state write");
    return 0;
}
