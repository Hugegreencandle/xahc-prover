#include "xahc/xahc.h"

/* ADVERSARIAL foreign-authz attack — the hook checks the WRONG sentinel. It only
 * rejects when rc == -34 exactly, but ACCEPTS on any other return, including other
 * negative (failure) returns. The engine models the host return as fully symbolic;
 * `granted := ret >= 0`. So an accept is reachable with ret < 0 and ret != -34
 * (still unauthorized/failed). Correct verdict: COUNTEREXAMPLE (2). */

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
    uint8_t acct[20] = {0xAA,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19};

    int64_t rc = state_foreign_set((uint32_t)val, sizeof(val),
                                   (uint32_t)key, sizeof(key),
                                   (uint32_t)ns, sizeof(ns),
                                   (uint32_t)acct, sizeof(acct));
    /* BUG: only rejects the exact -34 sentinel; accepts on any other value
     * including other negative failure codes. */
    XAHC_REQUIRE(rc != -34, "not authorized (exact -34)");

    XAHC_ACCEPT("accepted (wrong sentinel check)");
    return 0;
}
