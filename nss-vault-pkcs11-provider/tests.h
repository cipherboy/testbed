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

PRBool ensureAllDoMech(PK11SlotInfo **slots, size_t num_slots, CK_MECHANISM_TYPE mech);
SECStatus establishSymKeyOnSlots(PK11SlotInfo **slots, size_t num_slots, CK_MECHANISM_TYPE mech, unsigned int bits, CK_FLAGS opFlags, PK11SymKey **keys);

test_ret_t testAESOp(PK11SlotInfo **slots, size_t num_slots, CK_MECHANISM_TYPE mech);
test_ret_t testHMACOp(PK11SlotInfo **slots, size_t num_slots, CK_MECHANISM_TYPE mech);
test_ret_t testRSAEncOp(PK11SlotInfo **slots, size_t num_slots, CK_MECHANISM_TYPE mech);
test_ret_t testRSASignOp(PK11SlotInfo **slots, size_t num_slots, CK_MECHANISM_TYPE mech);
