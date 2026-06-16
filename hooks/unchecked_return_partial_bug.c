#include "xahc/xahc.h"
/* SC06 ADVERSARIAL: checks the return but with a TOO-LENIENT bound — rolls back only on
 * rc < -100, letting genuine failures in [-100,-1] slip through to accept. Must -> CEX. */
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t key[1] = { 0x01 };
    uint8_t val[8] = { 0,0,0,0,0,0,0,1 };
    int64_t rc = state_set(XAHC_SBUF(val), XAHC_SBUF(key));
    if (rc < -100) rollback(0, 0, (int64_t)__LINE__);   /* BUG: -1..-100 not caught */
    XAHC_ACCEPT("partial check");
    return 0;
}
