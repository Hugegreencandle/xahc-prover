#include "xahc/xahc.h"
#include "xahc/emit/payment.h"
extern int64_t ledger_last_time(void);
/* Native Payment, template layout intact (all markers exact), with an InvoiceID
 * field (sfInvoiceID = 0x50 11, a 32-byte hash) inserted in canonical order
 * (after Amount/Fee region the canonical position of InvoiceID is before Account).
 * Here we keep the parser's marker offsets (0x61@35,0x68@44,0x83 0x14@110..111)
 * by placing the InvoiceID AFTER the Destination, carrying entropy. InvoiceID is a
 * user-observable payment reference shown by wallets; the parser ignores it. */
int64_t cbak(uint32_t r){return 0;}
int64_t hook(uint32_t r){
    XAHC_HOOK_ENTRY();
    uint8_t acc[20];
    hook_account((uint32_t)acc, 20);
    uint32_t cls = (uint32_t)ledger_seq();
    uint8_t buf[XAHC_PAYMENT_SIZE];
    uint8_t* p = buf;
    *p++ = 0x12; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x22; *p++ = 0x80; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x23; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
    *p++ = 0x24; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
    *p++ = 0x2E; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
    *p++ = 0x20; *p++ = 0x1A; *p++ = (cls+1)>>24; *p++ = (cls+1)>>16; *p++ = (cls+1)>>8; *p++ = (cls+1);
    *p++ = 0x20; *p++ = 0x1B; *p++ = (cls+5)>>24; *p++ = (cls+5)>>16; *p++ = (cls+5)>>8; *p++ = (cls+5);
    *p++ = 0x61;
    *p++ = 0x40; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0x03; *p++ = 0xE8;
    uint8_t* fee_ptr = p;
    *p++ = 0x68; *p++ = 0x40; for (int i=0;i<7;++i) *p++ = 0;
    *p++ = 0x73; *p++ = 0x21; for (int i=0;i<33;++i) *p++ = 0;
    *p++ = 0x81; *p++ = 0x14; for (int i=0;i<20;++i) *p++ = acc[i];
    *p++ = 0x83; *p++ = 0x14; for (int i=0;i<20;++i) *p++ = (uint8_t)(i+1); /* dest @112 fixed */
    /* InvoiceID @132: sfInvoiceID id 0x50 0x11? actual = type5 nth17 -> 0x51 0x... ; use 0x50 marker,
     * 32 bytes, first byte from entropy. Wallet shows InvoiceID; parser ignores it. */
    *p++ = 0x50;
    *p++ = (uint8_t)ledger_last_time();  /* ENTROPY into InvoiceID (BUG) */
    for (int i=0;i<31;++i) *p++ = 0;
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
    XAHC_ACCEPT("emit entropy invoiceid");
    return 0;
}
