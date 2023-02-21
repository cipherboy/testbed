#include <stdint.h>

#include <plstr.h>
#include <secitem.h>
#include <secmod.h>
#include <keyhi.h>
#include <pk11func.h>
#include <nspr.h>
#include <pkcs11.h>
#include <pkcs11t.h>
#include <base64.h>
#include <nss.h>

#pragma once

typedef enum {
    TEST_OK,
    TEST_SKIP,
    TEST_ERROR,
} test_ret_t;

SECStatus randUint(uint32_t *value);
SECStatus nextUint(uint32_t *value, uint32_t minimum, uint32_t maximum);
SECStatus randChoice(void **choice, void **pile, uint32_t count);

test_ret_t doAESECBOp(PK11SlotInfo *slot, PK11SymKey *key, const unsigned char *data, unsigned int dataLen);
test_ret_t doAESCBCOp(PK11SlotInfo *slot, PK11SymKey *key, const unsigned char *data, unsigned int dataLen, const unsigned char *iv, unsigned int ivLen);
test_ret_t doAESCBCPadOp(PK11SlotInfo *slot, PK11SymKey *key, const unsigned char *data, unsigned int dataLen, const unsigned char *iv, unsigned int ivLen);
test_ret_t doAESCTROp(PK11SlotInfo *slot, PK11SymKey *key, const unsigned char *data, unsigned int dataLen, unsigned int ctrLen, const unsigned char *iv, unsigned int ivLen);
test_ret_t doAESGCMOp(PK11SlotInfo *slot, PK11SymKey *key, const unsigned char *data, unsigned int dataLen, const unsigned char *iv, unsigned int ivLen, const unsigned char *aad, unsigned int aadLen);

test_ret_t testAESOp(PK11SlotInfo *slot, PK11SymKey *key, CK_MECHANISM_TYPE mech);
test_ret_t testHMACOp(PK11SlotInfo *slot, PK11SymKey *key, CK_MECHANISM_TYPE mech);
