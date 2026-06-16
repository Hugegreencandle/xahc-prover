#include "xahc/xahc.h"
/* SC06 NEGATIVE CONTROL: raw state_set, return IGNORED, then accept -> COUNTEREXAMPLE. */
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t key[1] = { 0x01 };
    uint8_t val[8] = { 0,0,0,0,0,0,0,1 };
    state_set(XAHC_SBUF(val), XAHC_SBUF(key));   /* BUG: ignores the return code */
    XAHC_ACCEPT("unchecked state_set");
    return 0;
}
