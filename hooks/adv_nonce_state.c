#include "xahc/xahc.h"

/* ADVERSARIAL nonce attack — the nonce is laundered THROUGH STATE. The hook reads
 * the ledger nonce, writes it to its own state, reads it back, and gates the accept
 * on the read-back value. In real Xahau semantics, a state read in the same hook
 * invocation sees the value just written, so the accept STILL depends on the nonce.
 *
 * Correct verdict: COUNTEREXAMPLE (2) — the accept hinges on grindable randomness,
 * merely routed through a state slot. If the engine models state-read as a fresh
 * symbolic value (decoupled from the staged write), the nonce symbols never appear
 * in the accept constraint and the dependence query would falsely PROVEN. */

extern int64_t ledger_nonce(uint32_t write_ptr, uint32_t write_len);
extern int64_t state(uint32_t write_ptr, uint32_t write_len,
                     uint32_t kread_ptr, uint32_t kread_len);
extern int64_t state_set(uint32_t read_ptr, uint32_t read_len,
                         uint32_t kread_ptr, uint32_t kread_len);

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    uint8_t n[32];
    ledger_nonce((uint32_t)n, sizeof(n));

    uint8_t key[3] = {'N','C','E'};
    /* stage the nonce into state */
    state_set((uint32_t)n, 8, (uint32_t)key, sizeof(key));

    /* read it back (same invocation sees the staged value on Xahau) */
    uint8_t r[8];
    state((uint32_t)r, sizeof(r), (uint32_t)key, sizeof(key));

    /* accept hinges on the laundered nonce */
    XAHC_REQUIRE(r[0] == 0, "you lose (laundered nonce)");

    XAHC_ACCEPT("you win (nonce via state)");
    return 0;
}
