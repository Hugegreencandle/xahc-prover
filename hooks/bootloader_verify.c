#include "xahc/xahc.h"
/* Bootloader verify-core — a REFERENCE MODEL, not a deployed hook. Models the loader's go/no-go
 * gate: ACCEPT (=> hand control to stage-2) ONLY when the candidate bundle hash equals the pinned
 * hash, all 32 bytes. Params: PIN (32-byte pinned SHA-512Half), CAN (32-byte candidate hash the
 * wallet computed). NOTE: Xahau's on-chain SetBoot stores the blob verbatim and verifies nothing —
 * the pin/compare modeled here is a wallet-side convention, not protocol-enforced. */
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t pk[3]={'P','I','N'}, ck[3]={'C','A','N'};
    uint8_t pin[32], can[32];
    XAHC_HOOK_PARAM_REQUIRE(pin, pk, 32);
    XAHC_HOOK_PARAM_REQUIRE(can, ck, 32);
    int ok = 1;
    for (int i = 0; XAHC_GUARD(32), i < 32; ++i)
        if (pin[i] != can[i]) ok = 0;
    XAHC_REQUIRE(ok, "hash mismatch — refuse to load stage-2");
    XAHC_ACCEPT("verified: candidate == pinned");
    return 0;
}
