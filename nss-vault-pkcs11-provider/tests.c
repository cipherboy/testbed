#include <stdint.h>
#include <stdbool.h>

#include <plstr.h>
#include <secitem.h>
#include <secmod.h>
#include <keyhi.h>
#include <keythi.h>
#include <pk11func.h>
#include <nspr.h>
#include <pkcs11.h>
#include <pkcs11t.h>
#include <base64.h>
#include <nss.h>
#include <secport.h>

#include "tests.h"

#define MAX_OBJECT_ATTRS 15
#define MAX_ATTEMPTS 10
#define MAX_HMAC_OUTPUT_LEN 512
#define MAX_RSA_OUTPUT_LEN 8192

// secmodi.h from the NSS distribution.
SECStatus PK11_CreateNewObject(PK11SlotInfo *slot, CK_SESSION_HANDLE session,
                               const CK_ATTRIBUTE *theTemplate, int count,
                               PRBool token, CK_OBJECT_HANDLE *objectID);
CK_SESSION_HANDLE pk11_GetNewSession(PK11SlotInfo *slot, PRBool *owner);
void pk11_CloseSession(PK11SlotInfo *slot, CK_SESSION_HANDLE sess, PRBool own);

SECStatus randUint(uint32_t *value) {
    return PK11_GenerateRandom((unsigned char *)value, sizeof(uint32_t)/sizeof(unsigned char));
}

SECStatus nextUint(uint32_t *value, uint32_t minimum, uint32_t maximum) {
    // See: https://cs.opensource.google/go/go/+/refs/tags/go1.20.1:src/math/rand/rand.go
    if (minimum > maximum) {
        return nextUint(value, maximum, minimum);
    }

    uint32_t delta = maximum - minimum;
    if ((delta&(delta-1)) == 0) {
        // Power of two; can simply mask.
        if (randUint(value) != SECSuccess) {
            return SECFailure;
        }

        *value = (*value & (delta - 1)) + minimum;
        return SECSuccess;
    }

    if (randUint(value) != SECSuccess) {
        return SECFailure;
    }
    uint32_t v = (uint32_t)*value;
    uint64_t prod = ((uint64_t)v) * ((uint64_t)delta);
    uint32_t low = (uint32_t)prod;

    if (low < (uint32_t)delta) {
        uint32_t thresh = ((uint32_t)-delta) % ((uint32_t)delta);
        while (low < thresh) {
            if (randUint(value) != SECSuccess) {
                return SECFailure;
            }

            v = (uint32_t)*value;
            prod = ((uint64_t)v) * ((uint64_t)delta);
            low = (uint32_t)prod;
        }
    }

    *value = ((int)(prod >> 32)) + minimum;
    return SECSuccess;
}

SECStatus randChoice(void **choice, void **pile, uint32_t count) {
    uint32_t index = 0;
    if (nextUint(&index, 0, count) != SECSuccess) {
        return SECFailure;
    }

    *choice = pile + (size_t)index;
    return SECSuccess;
}

PRBool ensureAllDoMech(PK11SlotInfo **slots, size_t num_slots, CK_MECHANISM_TYPE mech) {
    for (size_t index = 0; index < num_slots; index++) {
        if (PK11_DoesMechanism(slots[index], mech) == PR_FALSE) {
            return PR_FALSE;
        }
    }

    return PR_TRUE;
}

void reduceTemplate(CK_ATTRIBUTE *template, int *count) {
    int offset = 0;
    for (int i = 0; i < *count; i++) {
        if (template[i].pValue != NULL && i != offset) {
            template[offset] = template[i];
            offset += 1;
        }
    }

    *count = offset;
}

SECStatus establishSymKeyOnSlots(PK11SlotInfo **slots, size_t num_slots, CK_MECHANISM_TYPE mech, unsigned int bits, CK_FLAGS opFlags, PK11SymKey **keys) {
    if (ensureAllDoMech(slots, num_slots, mech) == PR_FALSE) {
        fprintf(stderr, "One or more slots don't do the requested mechanism: %lx.\n", mech);
        return SECFailure;
    }

    PK11SlotInfo *default_slot = slots[0];
    PK11SymKey *key = PK11_TokenKeyGenWithFlags(default_slot, mech, NULL, bits, NULL, opFlags, 0, NULL);
    if (key == NULL) {
        PRErrorCode code = PORT_GetError();
        const char *message = PORT_ErrorToString(code);
        fprintf(stderr, "[Slot %s / Token %s] Failed to generate symmetric key with mechanism %lx: (%d) %s\n", PK11_GetSlotName(default_slot), PK11_GetTokenName(default_slot), mech, code, message);
        return SECFailure;
    }

    keys[0] = key;

    for (size_t index = 1; index < num_slots; index++) {
        CK_ATTRIBUTE_TYPE mode = CKA_ENCRYPT;
        if ((opFlags & CKF_SIGN) == CKF_SIGN) {
            mode = CKA_SIGN;
        }

        PK11SlotInfo *dest_slot = slots[index];
        PK11SymKey *dest_key = PK11_MoveSymKey(dest_slot, mode, opFlags, PR_TRUE, key);
        if (dest_key == NULL) {
            PRErrorCode code = PORT_GetError();
            const char *message = PORT_ErrorToString(code);
            fprintf(stderr, "[Slot %s / Token %s]->[Slot %s / Token %s] Failed to move symmetric key with mechanism %lx to destination slot via PK11_MoveSymKey(...): (%d) %s\n", PK11_GetSlotName(default_slot), PK11_GetTokenName(default_slot), PK11_GetSlotName(dest_slot), PK11_GetTokenName(dest_slot), mech, code, message);

            // The above very likely will fail, as vault-pkcs11-provider
            // lacks the ability to wrap keys currently. So we try
            // creating an object directly on the slot.
            CK_ATTRIBUTE *template = calloc(MAX_OBJECT_ATTRS + 1, sizeof(CK_ATTRIBUTE));
            template[ 0].type = CKA_CLASS;
            template[ 1].type = CKA_KEY_TYPE;
            template[ 2].type = CKA_VALUE;
            template[ 3].type = CKA_VALUE_LEN;
            template[ 4].type = CKA_TOKEN;
            template[ 5].type = CKA_ENCRYPT;
            template[ 6].type = CKA_DECRYPT;
            template[ 7].type = CKA_SIGN;
            template[ 8].type = CKA_VERIFY;
            template[ 9].type = CKA_WRAP;
            template[10].type = CKA_UNWRAP;
            template[11].type = CKA_MODULUS;
            template[12].type = CKA_PUBLIC_EXPONENT;
            template[13].type = CKA_SENSITIVE;
            template[14].type = CKA_EXTRACTABLE;
            if (PK11_ReadRawAttributes(NULL, PK11_TypeSymKey, key, template, MAX_OBJECT_ATTRS) != SECSuccess) {
                PRErrorCode code = PORT_GetError();
                const char *message = PORT_ErrorToString(code);
                fprintf(stderr, "[Slot %s / Token %s] Failed to read symmetric key attributes to attempt move: (%d) %s\n", PK11_GetSlotName(default_slot), PK11_GetTokenName(default_slot), code, message);
                return SECFailure;
            }

            PRBool owner = PR_TRUE;
            PRBool *token = template[4].pValue;
            if (token == NULL) {
                token = malloc(sizeof(PRBool));
                *token = PR_FALSE;
            }

            int attrs = MAX_OBJECT_ATTRS;
            reduceTemplate(template, &attrs);

            bool haveValue = false;
            bool haveClass = false;
            for (int i = 0; i < attrs; i++) {
                if (template[attrs].type == CKA_VALUE) {
                    haveValue = true;
                }
                if (template[attrs].type == CKA_CLASS) {
                    haveClass = true;
                }
            }

            // No value on key when read from KMIP.
            if (!haveValue) {
                char fakeKey[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x00};
                template[attrs].type = CKA_VALUE;
                template[attrs].pValue = (char *)fakeKey;
                template[attrs].ulValueLen = 16;
                attrs += 1;
            }

            // No CK_CLASS returned from KMIP.
            if (!haveClass) {
                CK_OBJECT_CLASS ckClass = CKO_SECRET_KEY;
                template[attrs].type = CKA_CLASS;
                template[attrs].pValue = &ckClass;
                template[attrs].ulValueLen = sizeof(ckClass);
                attrs += 1;
            }

            CK_SESSION_HANDLE sess = pk11_GetNewSession(dest_slot, &owner);
            CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
            SECStatus ret = PK11_CreateNewObject(dest_slot, sess, template, attrs, *token, &obj);
            code = PORT_GetError();
            message = PORT_ErrorToString(code);
            pk11_CloseSession(dest_slot, sess, owner);

            if (ret != SECSuccess || obj == CK_INVALID_HANDLE) {
                fprintf(stderr, "[Slot %s / Token %s]->[Slot %s / Token %s] Failed to recreate symmetric key with mechanism %lx to destination slot via PK11_CreateNewObject(...) with %d attributes: (%d) %s\n", PK11_GetSlotName(default_slot), PK11_GetTokenName(default_slot), PK11_GetSlotName(dest_slot), PK11_GetTokenName(dest_slot), mech, MAX_OBJECT_ATTRS, code, message);
                return SECFailure;
            }

            free(template);

            dest_key = PK11_SymKeyFromHandle(dest_slot, NULL, PK11_OriginGenerated, CKM_AES_ECB, obj, PR_TRUE, NULL);
            if (dest_key == NULL) {
                PRErrorCode code = PORT_GetError();
                const char *message = PORT_ErrorToString(code);
                fprintf(stderr, "[Slot %s / Token %s]->[%zu Slot %s / Token %s] Failed to turn symmetric key from handle into object: (%d) %s\n", PK11_GetSlotName(default_slot), PK11_GetTokenName(default_slot), index, PK11_GetSlotName(dest_slot), PK11_GetTokenName(dest_slot), code, message);
                return SECFailure;
            }
        }

        keys[index] = dest_key;
    }

    return SECSuccess;
}

test_ret_t doAESOp(PK11SlotInfo **slots, PK11SymKey **keys, size_t num_slots, CK_MECHANISM_TYPE mech, SECItem *param, const unsigned char *data, unsigned int dataLen) {
    if (PK11_DoesMechanism(slots[0], mech) != PR_TRUE) {
        fprintf(stderr, "[Slot %s / Token %s] Default slot does not support AES mechanism %lx: skipping.\n", PK11_GetSlotName(slots[0]), PK11_GetTokenName(slots[0]), mech);
        return TEST_SKIP;
    }

    unsigned int *ciphertextLens = calloc(num_slots, sizeof(unsigned int));
    unsigned int maxLen = dataLen + 128; // Overhead for included IV, if any.
    unsigned char **ciphertexts = calloc(num_slots, sizeof(unsigned char *));

    for (size_t index = 0; index < num_slots; index++) {
        PK11SlotInfo *slot = slots[index];
        PK11SymKey *key = keys[index];

        ciphertexts[0] = calloc(maxLen, sizeof(unsigned char));

        if (PK11_Encrypt(key, mech, param, ciphertexts[index], ciphertextLens + index, maxLen, data, dataLen) != SECSuccess) {
            PRErrorCode code = PORT_GetError();
            const char *message = PORT_ErrorToString(code);
            fprintf(stderr, "[Slot %s / Token %s] Failed to do AES encrypt operation %lx: (%d) %s\n", PK11_GetSlotName(slot), PK11_GetTokenName(slot), mech, code, message);
            return TEST_ERROR;
        }

        if (ciphertextLens[index] == dataLen && memcmp(data, ciphertexts[index], dataLen) == 0) {
            fprintf(stderr, "[Slot %s / Token %s] Encryption %lx did nothing: ciphertext same as plaintext.\n", PK11_GetSlotName(slot), PK11_GetTokenName(slot), mech);
            return TEST_ERROR;
        }

        // We don't store this between calls since this is a known-answer.
        unsigned int plaintextLen = 0;
        unsigned char *plaintext = calloc(maxLen, sizeof(unsigned char));
        if (PK11_Decrypt(key, mech, param, plaintext, &plaintextLen, maxLen, ciphertexts[index], ciphertextLens[index]) != SECSuccess) {
            PRErrorCode code = PORT_GetError();
            const char *message = PORT_ErrorToString(code);
            fprintf(stderr, "[Slot %s / Token %s] Failed to do AES decrypt operation %lx: (%d) %s\n", PK11_GetSlotName(slot), PK11_GetTokenName(slot), mech, code, message);
            return TEST_ERROR;
        }

        if (plaintextLen != dataLen || memcmp(data, plaintext, dataLen) != 0) {
            fprintf(stderr, "[%zu Slot %s / Token %s] Round-tripping failed: different plaintext/ciphertext: %u / %u\n\tPlaintext: %s\n\tData: %s\n", index, PK11_GetSlotName(slot), PK11_GetTokenName(slot), plaintextLen, dataLen, plaintext, data);
            return TEST_ERROR;
        }

        free(plaintext);
    }

    unsigned int ciphertextLen = ciphertextLens[0];
    unsigned char *ciphertext = ciphertexts[0];
    for (size_t index = 1; index < num_slots; index++) {
        PK11SlotInfo *slot = slots[index];
        unsigned int otherLen = ciphertextLens[index];
        unsigned char *other = ciphertexts[index];

        if (otherLen != ciphertextLen || memcmp(ciphertext, other, ciphertextLen) != 0) {
            fprintf(stderr, "[%d Slot %s / Token %s] vs [%zu Slot %s / Token %s] Comparison test failed: different ciphertexts: %u / %u\n\tDefault Ciphertext: %s\n\tOther Ciphertext: %s\n", 0, PK11_GetSlotName(slots[0]), PK11_GetTokenName(slots[0]), index, PK11_GetSlotName(slot), PK11_GetTokenName(slot), ciphertextLen, otherLen, ciphertext, other);
            return TEST_ERROR;
        }

        free(other);
    }

    free(ciphertexts[0]);
    free(ciphertextLens);
    free(ciphertexts);
    return TEST_OK;
}

test_ret_t doAESECBOp(PK11SlotInfo **slots, PK11SymKey **keys, size_t num_slots, const unsigned char *data, unsigned int dataLen) {
    if ((dataLen % 16) != 0) {
        return TEST_SKIP;
    }

    return doAESOp(slots, keys, num_slots, CKM_AES_ECB, NULL, data, dataLen);
}

SECItem *getIVParam(const unsigned char *iv, unsigned int ivLen) {
    SECItem *param = malloc(sizeof(SECItem));
    param->type = siBuffer;
    param->len = ivLen;
    param->data = calloc(ivLen, sizeof(unsigned char));
    memcpy(param->data, iv, ivLen);
    return param;
}

void freeIVParam(SECItem *param) {
    free(param->data);
    free(param);
}

test_ret_t doAESCBCOp(PK11SlotInfo **slots, PK11SymKey **keys, size_t num_slots, const unsigned char *data, unsigned int dataLen, const unsigned char *iv, unsigned int ivLen) {
    if ((dataLen % 16) != 0) {
        return TEST_SKIP;
    }

    if (ivLen != 16) {
        return TEST_SKIP;
    }

    SECItem *ivParam = getIVParam(iv, ivLen);
    test_ret_t ret = doAESOp(slots, keys, num_slots, CKM_AES_CBC_PAD, ivParam, data, dataLen);
    freeIVParam(ivParam);

    return ret;
}

test_ret_t doAESCBCPadOp(PK11SlotInfo **slots, PK11SymKey **keys, size_t num_slots, const unsigned char *data, unsigned int dataLen, const unsigned char *iv, unsigned int ivLen) {
    if (ivLen != 16) {
        return TEST_SKIP;
    }

    SECItem *ivParam = getIVParam(iv, ivLen);
    test_ret_t ret = doAESOp(slots, keys, num_slots, CKM_AES_CBC_PAD, ivParam, data, dataLen);
    freeIVParam(ivParam);

    return ret;
}

test_ret_t doAESCTROp(PK11SlotInfo **slots, PK11SymKey **keys, size_t num_slots, const unsigned char *data, unsigned int dataLen, unsigned int ctrLen, const unsigned char *iv, unsigned int ivLen) {
    if (ivLen != 16) {
        return TEST_SKIP;
    }

    if (ctrLen > 128) {
        return TEST_SKIP;
    }

    CK_AES_CTR_PARAMS ctr;
    ctr.ulCounterBits = ctrLen;
    memcpy(ctr.cb, iv, 16);
    SECItem ctrParam = {siBuffer, (unsigned char *)&ctr, sizeof(ctr)};

    return doAESOp(slots, keys, num_slots, CKM_AES_CTR, &ctrParam, data, dataLen);
}

test_ret_t doAESGCMOp(PK11SlotInfo **slots, PK11SymKey **keys, size_t num_slots, const unsigned char *data, unsigned int dataLen, const unsigned char *iv, unsigned int ivLen, const unsigned char *aad, unsigned int aadLen) {
    if (ivLen != 96/8) {
        return TEST_SKIP;
    }

    CK_GCM_PARAMS_V3 gcm = {
        (unsigned char *)iv,
        96/8,
        96,
        (unsigned char *)aad,
        aadLen,
        128,
    };
    SECItem gcmParam = {siBuffer, (unsigned char *)&gcm, sizeof(gcm)};

    return doAESOp(slots, keys, num_slots, CKM_AES_GCM, &gcmParam, data, dataLen);
}

test_ret_t testAESOp(PK11SlotInfo **slots, size_t num_slots, CK_MECHANISM_TYPE mech) {
    PK11SymKey **keys = calloc(num_slots, sizeof(PK11SymKey *));
    CK_FLAGS opFlags = CKF_ENCRYPT | CKF_DECRYPT;
    if (establishSymKeyOnSlots(slots, num_slots, CKM_AES_KEY_GEN, 16, opFlags, keys) == SECFailure) {
        fprintf(stderr, "Failed to generate fresh AES keys on slots.\n");
        return TEST_ERROR;
    }

    for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        unsigned int dataLen = 0;
        unsigned int upperBound = 8192;
        unsigned int multiple = 1;
        switch (mech) {
        case CKM_AES_ECB:
        case CKM_AES_CBC:
        case CKM_AES_CTR: // Is broken.
            upperBound = 8192/16;
            multiple = 16;
            break;
        }

        if (nextUint(&dataLen, 1, upperBound) == SECFailure) {
            fprintf(stderr, "Error reading data length in range [%u, %u).\n", 1, upperBound);
            return TEST_ERROR;
        }

        dataLen *= multiple;
        unsigned char *data = calloc(dataLen + 1, sizeof(unsigned char));
        if (PK11_GenerateRandom(data, dataLen) != SECSuccess) {
            fprintf(stderr, "Error reading data of length %u.\n", dataLen);
            return TEST_ERROR;
        }

        unsigned int ivLen = 0;
        switch (mech) {
        case CKM_AES_CBC:
        case CKM_AES_CBC_PAD:
        case CKM_AES_CTR:
            ivLen = 16;
            break;
        case CKM_AES_GCM:
            ivLen = 96/8;
        }
        unsigned char *iv = calloc(ivLen + 1, sizeof(unsigned char));
        if (PK11_GenerateRandom(iv, ivLen) != SECSuccess) {
            return TEST_ERROR;
        }

        unsigned int aadLen;
        if (nextUint(&aadLen, 0, 256) == SECFailure) {
            return TEST_ERROR;
        }

        unsigned char *aad = calloc(aadLen + 1, sizeof(unsigned char));
        if (PK11_GenerateRandom(aad, aadLen) != SECSuccess) {
            return TEST_ERROR;
        }

        unsigned int ctrLen = 0;
        unsigned int ctrMin = 1;
        if (dataLen > 4000) {
            ctrMin = 2;
        }
        if (nextUint(&ctrLen, ctrMin, 8) == SECFailure) {
            return TEST_ERROR;
        }
        ctrLen *= 8; // Bits, not bytes.

        fprintf(stderr, "Dispatching mechanism %lu: dataLen=%u, ivLen=%u, aadLen=%u, ctrLen=%u\n", mech, dataLen, ivLen, aadLen, ctrLen);

        test_ret_t ret;
        switch (mech) {
        case CKM_AES_ECB:
            ret = doAESECBOp(slots, keys, num_slots, data, dataLen);
            break;
        case CKM_AES_CBC:
            ret = doAESCBCOp(slots, keys, num_slots, data, dataLen, iv, ivLen);
            break;
        case CKM_AES_CBC_PAD:
            ret = doAESCBCPadOp(slots, keys, num_slots, data, dataLen, iv, ivLen);
            break;
        case CKM_AES_CTR:
            ret = doAESCTROp(slots, keys, num_slots, data, dataLen, ctrLen, iv, ivLen);
            break;
        case CKM_AES_GCM:
            ret = doAESGCMOp(slots, keys, num_slots, data, dataLen, iv, ivLen, aad, aadLen);
            break;
        default:
            fprintf(stderr, "Unknown mechanism to testAESOp: %lx\n", mech);
            ret = TEST_ERROR;
        }

        free(data);
        free(iv);
        free(aad);

        if (ret == TEST_SKIP) {
            fprintf(stderr, "Skipping mechanism this time due to incorrect parameters...\n");
            continue;
        }

        return ret;
    }

    fprintf(stderr, "Skipped all attempts at this mechanism; failing.\n");
    return TEST_ERROR;
}

test_ret_t doHMACOp(PK11SlotInfo **slots, PK11SymKey **keys, size_t num_slots, CK_MECHANISM_TYPE mech, const unsigned char *data, unsigned int dataLen) {
    if (PK11_DoesMechanism(slots[0], mech) != PR_TRUE) {
        fprintf(stderr, "Default Slot [Slot %s / Token %s] does not support HMAC mechanism %lx: skipping.\n", PK11_GetSlotName(slots[0]), PK11_GetTokenName(slots[0]), mech);
        return TEST_SKIP;
    }

    unsigned int *signatureLens = calloc(num_slots, sizeof(unsigned int));
    unsigned int maxLen = MAX_HMAC_OUTPUT_LEN;
    unsigned char **signatures = calloc(num_slots, sizeof(unsigned char *));

    for (size_t index = 0; index < num_slots; index++) {
        PK11SlotInfo *slot = slots[index];
        PK11SymKey *key = keys[index];
        signatures[index] = calloc(maxLen, sizeof(unsigned char));
        SECItem nullParam = {siBuffer, NULL, 0};

        PK11Context *sign = PK11_CreateContextBySymKey(mech, CKA_SIGN, key, &nullParam);
        if (sign == NULL) {
            PRErrorCode code = PORT_GetError();
            const char *message = PORT_ErrorToString(code);
            fprintf(stderr, "[%zu Slot %s / Token %s] Failed to create HMAC sign context for %lx: (%d) %s\n", index, PK11_GetSlotName(slot), PK11_GetTokenName(slot), mech, code, message);
            return TEST_ERROR;
        }

        if (PK11_DigestOp(sign, data, dataLen) != SECSuccess) {
            PRErrorCode code = PORT_GetError();
            const char *message = PORT_ErrorToString(code);
            fprintf(stderr, "[%zu Slot %s / Token %s] Failed to do HMAC sign for %lx: (%d) %s\n", index, PK11_GetSlotName(slot), PK11_GetTokenName(slot), mech, code, message);
            return TEST_ERROR;
        }

        if (PK11_DigestFinal(sign, signatures[index], signatureLens + index, maxLen) != SECSuccess) {
            PRErrorCode code = PORT_GetError();
            const char *message = PORT_ErrorToString(code);
            fprintf(stderr, "[%zu Slot %s / Token %s] Failed to finalize HMAC sign for %lx: (%d) %s\n", index, PK11_GetSlotName(slot), PK11_GetTokenName(slot), mech, code, message);
            return TEST_ERROR;
        }

        if (signatureLens[index] == dataLen && memcmp(data, signatures[index], dataLen) == 0) {
            fprintf(stderr, "[%zu Slot %s / Token %s] Signature %lx did nothing: signature same as plaintext.\n", index, PK11_GetSlotName(slot), PK11_GetTokenName(slot), mech);
            return TEST_ERROR;
        }

        PK11_DestroyContext(sign, PR_TRUE);
    }

    free(signatureLens);
    free(signatures);
    return TEST_OK;
}

test_ret_t testHMACOp(PK11SlotInfo **slots, size_t num_slots, CK_MECHANISM_TYPE mech) {
    /* SoftHSM requires keys to be pre-hashed, if they are too long. */
    /* This appears to violate the PKCS#11 spec. */
    unsigned int keyLen = 16;
    CK_MECHANISM_TYPE keyGenType = CKM_SHA256_KEY_GEN;
    switch (mech) {
    case CKM_SHA224_HMAC:
    case CKM_SHA512_224_HMAC:
        keyLen = 224/8;
        keyGenType = CKM_SHA224_KEY_GEN;
        break;
    case CKM_SHA256_HMAC:
    case CKM_SHA512_256_HMAC:
        keyLen = 256/8;
        keyGenType = CKM_SHA256_KEY_GEN;
        break;
    case CKM_SHA384_HMAC:
        keyLen = 384/8;
        keyGenType = CKM_SHA384_KEY_GEN;
        break;
    case CKM_SHA512_HMAC:
        keyLen = 512/8;
        keyGenType = CKM_SHA512_KEY_GEN;
        break;
    }

    if (PK11_DoesMechanism(slots[0], keyGenType) == PR_FALSE) {
        keyGenType = CKM_GENERIC_SECRET_KEY_GEN;
        if (PK11_DoesMechanism(slots[0], keyGenType) == PR_FALSE) {
            keyGenType = CKM_AES_KEY_GEN;
            keyLen = 256/8;
        }
    }

    PK11SymKey **keys = calloc(num_slots, sizeof(PK11SymKey *));
    CK_FLAGS opFlags = CKF_SIGN | CKF_VERIFY;
    if (establishSymKeyOnSlots(slots, num_slots, keyGenType, keyLen, opFlags, keys) == SECFailure) {
        fprintf(stderr, "Failed to generate fresh HMAC keys on slots.\n");
        return TEST_ERROR;
    }

    for (int attempt = 0; attempt < 10; attempt++) {
        unsigned int dataLen = 0;
        unsigned int upperBound = 8192;

        if (nextUint(&dataLen, 1, upperBound) == SECFailure) {
            fprintf(stderr, "Error reading data length in range [%u, %u).\n", 1, upperBound);
            return TEST_ERROR;
        }

        unsigned char *data = calloc(dataLen + 1, sizeof(unsigned char));
        if (PK11_GenerateRandom(data, dataLen) != SECSuccess) {
        fprintf(stderr, "Error reading data of length %u.\n", dataLen);
            return TEST_ERROR;
        }

        test_ret_t ret = doHMACOp(slots, keys, num_slots, mech, data, dataLen);
        free(data);
        if (ret == TEST_SKIP) {
            fprintf(stderr, "Skipping mechanism this time due to incorrect parameters...\n");
            continue;
        }

        return ret;
    }

    fprintf(stderr, "Skipped all attempts at this mechanism; failing.\n");
    return TEST_ERROR;
}

SECStatus establishPrivKeyOnSlots(PK11SlotInfo **slots, size_t num_slots, CK_MECHANISM_TYPE mech, unsigned int bits, SECKEYPrivateKey **privs) {
    for (size_t index = 0; index < num_slots; index++) {
        PK11SlotInfo *slot = slots[index];
        PK11RSAGenParams rsa = { bits, 65537 };
        SECKEYPublicKey *pub = NULL;
        SECKEYPrivateKey *priv = PK11_GenerateKeyPair(slot, mech, &rsa, &pub, PR_FALSE, PR_FALSE, NULL);
        if (priv == NULL) {
            PRErrorCode code = PORT_GetError();
            const char *message = PORT_ErrorToString(code);
            fprintf(stderr, "[%zu Slot %s / Token %s] Failed to generate key with mechanism %lx and %d bits: (%d) %s\n", index, PK11_GetSlotName(slot), PK11_GetTokenName(slot), mech, bits, code, message);
            return SECFailure;
        }
        privs[index] = priv;
    }

    return SECSuccess;
}

test_ret_t doRSAEncOp(PK11SlotInfo **slots, SECKEYPrivateKey **privs, size_t num_slots, CK_MECHANISM_TYPE mech, SECItem *param, const unsigned char *data, unsigned int dataLen) {
    // RSA is public/private key encryption/decryption. This means we need
    // to port each public key to each other slot, do the encryption, and
    // then do an encryption with the private key. We do this for every
    // slot pair as each slot has its own private key, making this O(n^2).
    // We need to also do it this way as public keys can be easily ported
    // across module boundaries, but private keys cannot; plus, encryption
    // and signatures use random entropy, so we can't simply dispatch the
    // same op on different slots (with the same keys) and get the exact
    // same answer for a memcmp(...) type test.
    for (size_t slot_index = 0; slot_index < num_slots; slot_index++) {
        PK11SlotInfo *slot = slots[slot_index];
        SECKEYPrivateKey *priv = privs[slot_index];
        for (size_t other_slot_index = 0; other_slot_index < num_slots; other_slot_index++) {
            PK11SlotInfo *dest_slot = slots[other_slot_index];
            SECKEYPublicKey *pub = SECKEY_ConvertToPublicKey(priv);
            if (PK11_ImportPublicKey(dest_slot, pub, PR_FALSE) == CK_INVALID_HANDLE) {
                PRErrorCode code = PORT_GetError();
                const char *message = PORT_ErrorToString(code);
                fprintf(stderr, "Unable to import private key from [%zu Slot %s / Token %s] to [%zu Slot %s / Token %s]: (%d) %s\n", slot_index, PK11_GetSlotName(slot), PK11_GetTokenName(slot), other_slot_index, PK11_GetSlotName(dest_slot), PK11_GetTokenName(dest_slot), code, message);
                return TEST_ERROR;
            }

            if (pub->pkcs11Slot != dest_slot) {
                fprintf(stderr, "Failed to import private key's public counterpart from [%zu Slot %s / Token %s] to [%zu Slot %s / Token %s]: was actually on [Slot %s / Token %s]\n", slot_index, PK11_GetSlotName(slot), PK11_GetTokenName(slot), other_slot_index, PK11_GetSlotName(dest_slot), PK11_GetTokenName(dest_slot), PK11_GetSlotName(pub->pkcs11Slot), PK11_GetTokenName(pub->pkcs11Slot));
                return TEST_ERROR;
            }

            unsigned int ciphertextLen = 0;
            unsigned int maxLen = MAX_RSA_OUTPUT_LEN;
            unsigned char *ciphertext = calloc(maxLen, sizeof(unsigned char));

            if (PK11_PubEncrypt(pub, mech, param, ciphertext, &ciphertextLen, maxLen, data, dataLen, NULL) == SECFailure) {
                PRErrorCode code = PORT_GetError();
                const char *message = PORT_ErrorToString(code);
                fprintf(stderr, "With Private Key from [%zu Slot %s / Token %s] and public key on [%zu Slot %s / Token %s]: failed encrypting data with mechanism %lx: (%d) %s\n", slot_index, PK11_GetSlotName(slot), PK11_GetTokenName(slot), other_slot_index, PK11_GetSlotName(dest_slot), PK11_GetTokenName(dest_slot), mech, code, message);
                return TEST_ERROR;
            }

            if (ciphertextLen == dataLen && memcmp(data, ciphertext, dataLen) == 0) {
                fprintf(stderr, "With Private Key from [%zu Slot %s / Token %s] and public key on [%zu Slot %s / Token %s]: failed encrypting data with mechanism %lx: got same ciphertext as plaintext!\n", slot_index, PK11_GetSlotName(slot), PK11_GetTokenName(slot), other_slot_index, PK11_GetSlotName(dest_slot), PK11_GetTokenName(dest_slot), mech);
                return TEST_ERROR;
            }

            unsigned int plaintextLen = 0;
            unsigned char *plaintext = calloc(maxLen, sizeof(unsigned char));
            if (PK11_PrivDecrypt(priv, mech, param, plaintext, &plaintextLen, maxLen, ciphertext, ciphertextLen) == SECFailure) {
                PRErrorCode code = PORT_GetError();
                const char *message = PORT_ErrorToString(code);
                fprintf(stderr, "With Private Key from [%zu Slot %s / Token %s] and public key on [%zu Slot %s / Token %s]: failed decrypting data with mechanism %lx: (%d) %s\n", slot_index, PK11_GetSlotName(slot), PK11_GetTokenName(slot), other_slot_index, PK11_GetSlotName(dest_slot), PK11_GetTokenName(dest_slot), mech, code, message);
                return TEST_ERROR;
            }

            if (plaintextLen != dataLen || memcmp(data, plaintext, dataLen) != 0) {
                fprintf(stderr, "With Private Key from [%zu Slot %s / Token %s] and public key on [%zu Slot %s / Token %s]: failed decrypting data with mechanism %lx: expecting round-trip test to work; got different plaintext and original data: plaintextLen %d vs dataLen: %d\n\tplaintext: %s\n\tdata: %s\n\t", slot_index, PK11_GetSlotName(slot), PK11_GetTokenName(slot), other_slot_index, PK11_GetSlotName(dest_slot), PK11_GetTokenName(dest_slot), mech, plaintextLen, dataLen, plaintext, data);
                return TEST_ERROR;
            }
        }
    }

    return TEST_OK;
}

test_ret_t testRSAEncOp(PK11SlotInfo **slots, size_t num_slots, CK_MECHANISM_TYPE mech) {
    unsigned int bits = 2048;
    SECKEYPrivateKey **privs = calloc(num_slots, sizeof(SECKEYPrivateKey *));
    if (establishPrivKeyOnSlots(slots, num_slots, CKM_RSA_PKCS_KEY_PAIR_GEN, bits, privs) == SECFailure) {
        fprintf(stderr, "Failed to generate fresh RSA keys on slots.\n");
        return TEST_ERROR;
    }

    for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        unsigned int dataLen = 0;
        unsigned int upperBound = bits/8/4;

        if (nextUint(&dataLen, 1, upperBound) == SECFailure) {
            fprintf(stderr, "Error reading data length in range [%u, %u).\n", 1, upperBound);
            return TEST_ERROR;
        }

        unsigned char *data = calloc(dataLen + 1, sizeof(unsigned char));
        if (PK11_GenerateRandom(data, dataLen) != SECSuccess) {
        fprintf(stderr, "Error reading data of length %u.\n", dataLen);
            return TEST_ERROR;
        }

        uint32_t choice;
        CK_MECHANISM_TYPE hashAlgs[] = {CKM_SHA256, CKM_SHA384, CKM_SHA512};
        CK_MECHANISM_TYPE hashAlg;

        if (nextUint(&choice, 0, sizeof(hashAlgs)/sizeof(hashAlgs[0])) == SECFailure) {
            fprintf(stderr, "Error reading hash algorithm in range [%u, %lu).\n", 0, sizeof(hashAlgs)/sizeof(hashAlgs[0]));
            return TEST_ERROR;
        }

        hashAlg = hashAlgs[choice];

        // MUST BE IN SAME ORDER AS hashAlgs above!
        CK_RSA_PKCS_MGF_TYPE mgfs[] = {
            /* CKG_MGF1_SHA1,*/
            CKG_MGF1_SHA256,
            CKG_MGF1_SHA384,
            CKG_MGF1_SHA512,
            /*CKG_MGF1_SHA224,
            CKG_MGF1_SHA3_224,
            CKG_MGF1_SHA3_256,
            CKG_MGF1_SHA3_384,
            CKG_MGF1_SHA3_512*/
        };
        /* Require MGF == hashAlg due to Go requirements. */
        CK_RSA_PKCS_MGF_TYPE mgf = mgfs[choice];


        /*if (nextUint(&choice, 0, sizeof(mgfs)/sizeof(mgfs[0])) == SECFailure) {
            fprintf(stderr, "Error reading MGF in range [%u, %lu).\n", 0, sizeof(mgfs)/sizeof(mgfs[0]));
            return TEST_ERROR;
        }

        mgf = mgfs[choice];*/

        CK_RSA_PKCS_OAEP_PARAMS oaep = {
            hashAlg,
            mgf,
            CKZ_DATA_SPECIFIED, /* source */
            NULL, /* sourceData */
            0, /* sourceDataLen */
        };
        SECItem oaepParams = {siBuffer, (unsigned char *)&oaep, sizeof(oaep)};

        test_ret_t ret;
        switch (mech) {
        case CKM_RSA_PKCS:
            ret = doRSAEncOp(slots, privs, num_slots, mech, NULL, data, dataLen);
            break;
        case CKM_RSA_PKCS_OAEP:
            ret = doRSAEncOp(slots, privs, num_slots, mech, &oaepParams, data, dataLen);
            if (ret != TEST_OK) {
                fprintf(stderr, "OAEP hashAlg: %lu / mgf: %lu\n", hashAlg, mgf);
            }
            break;
        default:
            fprintf(stderr, "Unknown mechanism to testRSAEncOp: %lx\n", mech);
            ret = TEST_ERROR;
        }
        free(data);

        if (ret == TEST_SKIP) {
            fprintf(stderr, "Skipping mechanism this time due to incorrect parameters...\n");
            continue;
        }

        return ret;
    }

    return TEST_OK;
}

test_ret_t doRSASignOp(PK11SlotInfo **slots, SECKEYPrivateKey **privs, size_t num_slots, CK_MECHANISM_TYPE mech, SECItem *param, unsigned char *data, unsigned int dataLen) {
    // See note in doRSAEncOp.
    for (size_t slot_index = 0; slot_index < num_slots; slot_index++) {
        PK11SlotInfo *slot = slots[slot_index];
        SECKEYPrivateKey *priv = privs[slot_index];
        for (size_t other_slot_index = 0; other_slot_index < num_slots; other_slot_index++) {
            PK11SlotInfo *dest_slot = slots[other_slot_index];
            SECKEYPublicKey *pub = SECKEY_ConvertToPublicKey(priv);
            if (PK11_ImportPublicKey(dest_slot, pub, PR_FALSE) == CK_INVALID_HANDLE) {
                PRErrorCode code = PORT_GetError();
                const char *message = PORT_ErrorToString(code);
                fprintf(stderr, "Unable to import private key from [%zu Slot %s / Token %s] to [%zu Slot %s / Token %s]: (%d) %s\n", slot_index, PK11_GetSlotName(slot), PK11_GetTokenName(slot), other_slot_index, PK11_GetSlotName(dest_slot), PK11_GetTokenName(dest_slot), code, message);
                return TEST_ERROR;
            }

            if (pub->pkcs11Slot != dest_slot) {
                fprintf(stderr, "Failed to import private key's public counterpart from [%zu Slot %s / Token %s] to [%zu Slot %s / Token %s]: was actually on [Slot %s / Token %s]\n", slot_index, PK11_GetSlotName(slot), PK11_GetTokenName(slot), other_slot_index, PK11_GetSlotName(dest_slot), PK11_GetTokenName(dest_slot), PK11_GetSlotName(pub->pkcs11Slot), PK11_GetTokenName(pub->pkcs11Slot));
                return TEST_ERROR;
            }

            unsigned int sigLen = 0;
            unsigned int maxLen = MAX_RSA_OUTPUT_LEN;
            unsigned char *sig = calloc(maxLen, sizeof(unsigned char));
            SECItem sigParam = {siBuffer, sig, maxLen};
            SECItem hashParam = {siBuffer, data, dataLen};

            if (PK11_SignWithMechanism(priv, mech, param, &sigParam, &hashParam) == SECFailure) {
                PRErrorCode code = PORT_GetError();
                const char *message = PORT_ErrorToString(code);
                fprintf(stderr, "With Private Key from [%zu Slot %s / Token %s] and public key on [%zu Slot %s / Token %s]: failed signing data with mechanism %lx: (%d) %s\n", slot_index, PK11_GetSlotName(slot), PK11_GetTokenName(slot), other_slot_index, PK11_GetSlotName(dest_slot), PK11_GetTokenName(dest_slot), mech, code, message);
                return TEST_ERROR;
            }

            sigLen = sigParam.len;

            if (sigLen == dataLen && memcmp(data, sig, dataLen) == 0) {
                fprintf(stderr, "With Private Key from [%zu Slot %s / Token %s] and public key on [%zu Slot %s / Token %s]: failed signing data with mechanism %lx: got same signature as plaintext!\n", slot_index, PK11_GetSlotName(slot), PK11_GetTokenName(slot), other_slot_index, PK11_GetSlotName(dest_slot), PK11_GetTokenName(dest_slot), mech);
                return TEST_ERROR;
            }

            if (PK11_VerifyWithMechanism(pub, mech, param, &sigParam, &hashParam, NULL) == SECFailure) {
                PRErrorCode code = PORT_GetError();
                const char *message = PORT_ErrorToString(code);
                fprintf(stderr, "With Private Key from [%zu Slot %s / Token %s] and public key on [%zu Slot %s / Token %s]: failed verifying data with mechanism %lx: (%d) %s\n", slot_index, PK11_GetSlotName(slot), PK11_GetTokenName(slot), other_slot_index, PK11_GetSlotName(dest_slot), PK11_GetTokenName(dest_slot), mech, code, message);
                return TEST_ERROR;
            }
        }
    }

    return TEST_OK;
}

test_ret_t testRSASignOp(PK11SlotInfo **slots, size_t num_slots, CK_MECHANISM_TYPE mech) {
    unsigned int bits = 2048;
    SECKEYPrivateKey **privs = calloc(num_slots, sizeof(SECKEYPrivateKey *));
    if (establishPrivKeyOnSlots(slots, num_slots, CKM_RSA_PKCS_KEY_PAIR_GEN, bits, privs) == SECFailure) {
        fprintf(stderr, "Failed to generate fresh RSA keys on slots.\n");
        return TEST_ERROR;
    }

    for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        uint32_t choice;
        CK_MECHANISM_TYPE hashAlgs[] = {CKM_SHA256, CKM_SHA384, CKM_SHA512};
        CK_MECHANISM_TYPE hashAlg;

        switch (mech) {
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS_PSS:
            choice = 0;
            break;
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS_PSS:
            choice = 1;
            break;
        case CKM_SHA512_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS_PSS:
            choice = 2;
            break;
        default:
            if (nextUint(&choice, 0, sizeof(hashAlgs)/sizeof(hashAlgs[0])) == SECFailure) {
                fprintf(stderr, "Error reading hash algorithm in range [%u, %lu).\n", 0, sizeof(hashAlgs)/sizeof(hashAlgs[0]));
                return TEST_ERROR;
            }
            break;
        }

        hashAlg = hashAlgs[choice];

        // MUST BE IN SAME ORDER AS hashAlgs above!
        CK_RSA_PKCS_MGF_TYPE mgfs[] = {
            /* CKG_MGF1_SHA1,*/
            CKG_MGF1_SHA256,
            CKG_MGF1_SHA384,
            CKG_MGF1_SHA512,
            /*CKG_MGF1_SHA224,
            CKG_MGF1_SHA3_224,
            CKG_MGF1_SHA3_256,
            CKG_MGF1_SHA3_384,
            CKG_MGF1_SHA3_512*/
        };
        /* Require MGF == hashAlg due to Go requirements. */
        CK_RSA_PKCS_MGF_TYPE mgf = mgfs[choice];

        // MUST BE IN SAME ORDER AS hashAlgs above!
        unsigned int hashLengths[] = {
            256/8,
            384/8,
            512/8,
        };
        unsigned int hashedLen = 0;
        unsigned int dataLen = 0;

        switch (mech) {
        case CKM_RSA_PKCS:
        case CKM_RSA_PKCS_PSS:
            dataLen = hashLengths[choice];
            hashedLen = dataLen;
            break;
        default:
            hashedLen = hashLengths[choice];
            if (nextUint(&dataLen, 0, MAX_RSA_OUTPUT_LEN) == SECFailure) {
                fprintf(stderr, "Error reading hash algorithm in range [%u, %u).\n", 0, MAX_RSA_OUTPUT_LEN);
                return TEST_ERROR;
            }
        }

        // PKCS#11 expects "data" here to be a pre-hashed value to sign. We
        // just generate a random value and assume data != hash(data), which
        // should be safe for any cryptographic hash function. In particular,
        // this lets us differentiate between bad sig mechanisms, where it
        // sig(data) := sig(hash(data)), whereas PKCS#11 says the token should
        // elide that hash (and treat data as if it was the output of a hash).
        unsigned char *data = calloc(dataLen + 1, sizeof(unsigned char));
        if (PK11_GenerateRandom(data, dataLen) != SECSuccess) {
        fprintf(stderr, "Error reading data of length %u.\n", dataLen);
            return TEST_ERROR;
        }

        uint32_t saltLengthLower = 0;
        uint32_t saltLengthUpper = ((bits-1)/8) - hashedLen - 2; // Inclusive upper bound on RNG.
        uint32_t saltLength = 0;
        if (nextUint(&saltLength, saltLengthLower, saltLengthUpper + 1 /* exclusive */) == SECFailure) {
            fprintf(stderr, "Error reading signature bits in range [%u, %u).\n", saltLengthLower, saltLengthUpper+1);
            return TEST_ERROR;
        }

        CK_RSA_PKCS_PSS_PARAMS pss = {
            hashAlg,
            mgf,
            (CK_ULONG) saltLength,
        };
        SECItem pssParams = {siBuffer, (unsigned char *)&pss, sizeof(pss)};

        test_ret_t ret;
        switch (mech) {
        case CKM_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS:
            ret = doRSASignOp(slots, privs, num_slots, mech, NULL, data, dataLen);
            break;
        case CKM_RSA_PKCS_PSS:
        case CKM_SHA256_RSA_PKCS_PSS:
        case CKM_SHA384_RSA_PKCS_PSS:
        case CKM_SHA512_RSA_PKCS_PSS:
            ret = doRSASignOp(slots, privs, num_slots, mech, &pssParams, data, dataLen);
            if (ret != TEST_OK) {
                fprintf(stderr, "PSS hashAlg: %lu / mgf: %lu / salt length: %u\n", hashAlg, mgf, saltLength);
            }
            break;
        default:
            fprintf(stderr, "Unknown mechanism to testRSASignOp: %lx\n", mech);
            ret = TEST_ERROR;
        }
        free(data);

        if (ret == TEST_SKIP) {
            fprintf(stderr, "Skipping mechanism this time due to incorrect parameters...\n");
            continue;
        }

        return ret;
    }

    return TEST_OK;
}
