#include "xahc/xahc.h"
/* SC06 reference: state_set return is CHECKED (XAHC_STATE_SET = XAHC_TRY) -> PROVEN. */
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t key[1] = { 0x01 };
    uint8_t val[8] = { 0,0,0,0,0,0,0,1 };
    XAHC_STATE_SET(key, val);              /* rolls back if state_set < 0 */
    XAHC_ACCEPT("checked state_set");
    return 0;
}
