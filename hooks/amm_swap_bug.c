#include "xahc/xahc.h"

/* BUGGY (no k guard) AMM swap, NATIVE-PRODUCT regime. Reserves RX,RY in state; swap params
 * DX,DY. Requires reserves + dx bounded so RX*RY fits a u64 natively (no 128-bit mul) — keeps the
 * k-check inside z3's tractable range. Enforces newRX*newRY >= oldRX*oldRY => k can't drop (no drain).
 * prove_constant_product => COUNTEREXAMPLE. */

#define RMAX 0xFFFFFULL   /* 2^20-1: reserves bounded so products stay << 2^64 (z3-tractable) */

static void put_u64(uint8_t* b, uint64_t v){ for(int i=7;i>=0;--i){ b[i]=(uint8_t)v; v>>=8; } }
static uint64_t be8(const uint8_t* b){ uint64_t v=0; for(int i=0;i<8;++i) v=(v<<8)|b[i]; return v; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();
    uint8_t kx[2]={'R','X'}, ky[2]={'R','Y'}, kdx[2]={'D','X'}, kdy[2]={'D','Y'};
    uint64_t oldRX = xahc_state_u64(kx,2,0);
    uint64_t oldRY = xahc_state_u64(ky,2,0);
    uint8_t dxb[8]={0}, dyb[8]={0};
    hook_param(XAHC_SBUF(dxb), XAHC_SBUF(kdx));
    hook_param(XAHC_SBUF(dyb), XAHC_SBUF(kdy));
    uint64_t dx=be8(dxb), dy=be8(dyb);

    XAHC_REQUIRE(oldRX <= RMAX && oldRY <= RMAX && dx <= RMAX, "reserves in native-product regime");
    XAHC_REQUIRE(dy <= oldRY, "RY underflow");
    uint64_t newRX = oldRX + dx;
    uint64_t newRY = oldRY - dy;

    /* native u64 product (operands bounded => no overflow); k must not drop */
    /* BUG: no constant-product guard */

    uint8_t bx[8], by[8]; put_u64(bx,newRX); put_u64(by,newRY);
    XAHC_STATE_SET(kx, bx);
    XAHC_STATE_SET(ky, by);
    XAHC_ACCEPT("swap preserves constant product");
    return 0;
}
