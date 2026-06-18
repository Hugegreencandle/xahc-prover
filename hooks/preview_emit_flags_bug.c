#include "xahc/xahc.h"
#include "xahc/emit/payment.h"
extern int64_t ledger_last_time(void);
/* Hand-rolled native Payment blob, byte-for-byte the template layout
 * (markers 0x12@0, 0x61@35, 0x68@44, 0x83 0x14 @110..111, dest@112),
 * BUT the Flags value word (offset 4..7) is set from ledger entropy.
 * The wallet preview shows Flags; the engine's _emit_observable_native
 * does NOT extract Flags, so this slips through if the fix is incomplete. */
int64_t cbak(uint32_t r){return 0;}
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t acc[20];
    hook_account((uint32_t)acc, 20);
    uint32_t cls = (uint32_t)ledger_seq();
    uint32_t flags = (uint32_t)ledger_last_time();   /* ENTROPY into Flags (BUG) */
    uint8_t buf[XAHC_PAYMENT_SIZE];
    uint8_t* p = buf;
    *p++ = 0x12; *p++ = 0x00; *p++ = 0x00;                          /* TT Payment @0 */
    *p++ = 0x22; *p++ = (flags>>24); *p++ = (flags>>16); *p++ = (flags>>8); *p++ = flags; /* Flags @4..7 ENTROPY */
    *p++ = 0x23; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;            /* SourceTag @9..12 */
    *p++ = 0x24; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;            /* Sequence */
    *p++ = 0x2E; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;            /* DestTag @19..22 */
    *p++ = 0x20; *p++ = 0x1A; *p++ = (cls+1)>>24; *p++ = (cls+1)>>16; *p++ = (cls+1)>>8; *p++ = (cls+1); /* FLS */
    *p++ = 0x20; *p++ = 0x1B; *p++ = (cls+5)>>24; *p++ = (cls+5)>>16; *p++ = (cls+5)>>8; *p++ = (cls+5); /* LLS */
    *p++ = 0x61;                                                    /* Amount @35 */
    *p++ = 0x40; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0x03; *p++ = 0xE8; /* 1000 drops @36..43 */
    uint8_t* fee_ptr = p;
    *p++ = 0x68; *p++ = 0x40; for (int i=0;i<7;++i) *p++ = 0;       /* Fee @44 */
    *p++ = 0x73; *p++ = 0x21; for (int i=0;i<33;++i) *p++ = 0;      /* SigningPubKey null */
    *p++ = 0x81; *p++ = 0x14; for (int i=0;i<20;++i) *p++ = acc[i]; /* Account @88 */
    *p++ = 0x83; *p++ = 0x14;                                       /* Dest marker @110..111 */
    for (int i=0;i<20;++i) *p++ = (uint8_t)(i+1);                   /* Destination @112 (fixed) */
    int64_t edlen = etxn_details((uint32_t)p, XAHC_PAYMENT_SIZE - (uint32_t)(p - buf));
    if (edlen < 0) rollback(0, 0, (int64_t)__LINE__);
    p += edlen;
    uint32_t len = (uint32_t)(p - buf);
    int64_t fee = etxn_fee_base((uint32_t)buf, len);
    if (fee < 0) rollback(0, 0, (int64_t)__LINE__);
    fee_ptr[1] = 0x40 | ((fee>>56)&0x3F);
    fee_ptr[2] = fee>>48; fee_ptr[3] = fee>>40; fee_ptr[4] = fee>>32; fee_ptr[5] = fee>>24;
    fee_ptr[6] = fee>>16; fee_ptr[7] = fee>>8; fee_ptr[8] = fee;
    etxn_reserve(1);
    XAHC_TRY(emit(0, 0, (uint32_t)buf, len));
    XAHC_ACCEPT("emit entropy flags");
    return 0;
}
