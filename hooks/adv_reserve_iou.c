#include "xahc/xahc.h"

/* ADVERSARIAL reserve fail-closed probe — a reserve-param-reading hook that emits
 * an ISSUED (IOU) payment. The native-drops parser returns None for an IOU emit, so
 * outflow is unbounded -> the reserve driver must FAIL CLOSED (INCONCLUSIVE, 3),
 * never PROVEN. (An IOU emit does not move native XAH, but the point is to confirm
 * the unparsed/None-emit gate precedes any PROVEN.) */

static const uint8_t DST[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
static const uint8_t CUR[20] = {0,0,0,0,0,0,0,0,0,0,0,0,'U','S','D',0,0,0,0,0};
static const uint8_t ISS[20] = {9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9};

int64_t cbak(uint32_t reserved) { return 0; }

static uint64_t be8(const uint8_t* b) {
    return ((uint64_t)b[0]<<56)|((uint64_t)b[1]<<48)|((uint64_t)b[2]<<40)|((uint64_t)b[3]<<32)
         | ((uint64_t)b[4]<<24)|((uint64_t)b[5]<<16)|((uint64_t)b[6]<<8)|((uint64_t)b[7]);
}

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    uint8_t bal[8], ownc[8], rsvb[8], rsvi[8];
    uint8_t kBAL[3]={'B','A','L'}, kOWN[4]={'O','W','N','C'},
            kRSB[4]={'R','S','V','B'}, kRSI[4]={'R','S','V','I'};
    XAHC_REQUIRE(hook_param(XAHC_SBUF(bal),  XAHC_SBUF(kBAL)) == 8, "BAL");
    XAHC_REQUIRE(hook_param(XAHC_SBUF(ownc), XAHC_SBUF(kOWN)) == 8, "OWNC");
    XAHC_REQUIRE(hook_param(XAHC_SBUF(rsvb), XAHC_SBUF(kRSB)) == 8, "RSVB");
    XAHC_REQUIRE(hook_param(XAHC_SBUF(rsvi), XAHC_SBUF(kRSI)) == 8, "RSVI");
    (void)be8(bal);(void)be8(ownc);(void)be8(rsvb);(void)be8(rsvi);

    int64_t xfl = float_set(0, 1000000);
    XAHC_EMIT_PAYMENT_IOU(DST, xfl, CUR, ISS, 0, 0);   /* IOU emit -> native parser None */
    XAHC_ACCEPT("iou emit");
    return 0;
}
