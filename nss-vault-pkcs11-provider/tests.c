#include <stdint.h>
#include <stdbool.h>

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

#include "tests.h"

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

test_ret_t doAESOp(PK11SlotInfo *slot, PK11SymKey *key, CK_MECHANISM_TYPE mech, SECItem *param, const unsigned char *data, unsigned int dataLen) {
    if (PK11_DoesMechanism(slot, mech) != PR_TRUE) {
        fprintf(stderr, "Slot %s / Token %s does not support mechanism %lx: skipping.\n", PK11_GetSlotName(slot), PK11_GetTokenName(slot), mech);
        return TEST_SKIP;
    }

    unsigned int ciphertextLen = 0;
    unsigned int maxLen = dataLen + 128; // Overhead for included IV, if any.
    unsigned char *ciphertext = calloc(maxLen, sizeof(unsigned char));

    if (PK11_Encrypt(key, mech, param, ciphertext, &ciphertextLen, maxLen, data, dataLen) != SECSuccess) {
        PRErrorCode code = PORT_GetError();
        const char *message = PORT_ErrorToString(code);
        fprintf(stderr, "[Slot %s / Token %s] Failed to do AES encrypt operation %lx: (%d) %s\n", PK11_GetSlotName(slot), PK11_GetTokenName(slot), mech, code, message);
        return TEST_ERROR;
    }

    if (ciphertextLen == dataLen && memcmp(data, ciphertext, dataLen) == 0) {
        fprintf(stderr, "[Slot %s / Token %s] Encryption %lx did nothing: ciphertext same as plaintext.\n", PK11_GetSlotName(slot), PK11_GetTokenName(slot), mech);
        return TEST_ERROR;
    }

    unsigned int plaintextLen = 0;
    unsigned char *plaintext = calloc(maxLen, sizeof(unsigned char));

    if (PK11_Decrypt(key, mech, param, plaintext, &plaintextLen, maxLen, ciphertext, ciphertextLen) != SECSuccess) {
        PRErrorCode code = PORT_GetError();
        const char *message = PORT_ErrorToString(code);
        fprintf(stderr, "[Slot %s / Token %s] Failed to do AES decrypt operation %lx: (%d) %s\n", PK11_GetSlotName(slot), PK11_GetTokenName(slot), mech, code, message);
        return TEST_ERROR;
    }

    if (plaintextLen != dataLen || memcmp(data, plaintext, dataLen) != 0) {
        fprintf(stderr, "[Slot %s / Token %s] Round-tripping failed: different plaintext/ciphertext: %u / %u\n\tPlaintext: %s\n\tData: %s\n", PK11_GetSlotName(slot), PK11_GetTokenName(slot), plaintextLen, dataLen, plaintext, data);
        return TEST_ERROR;
    }

    free(ciphertext);
    free(plaintext);

    return TEST_OK;
}

test_ret_t doAESECBOp(PK11SlotInfo *slot, PK11SymKey *key, const unsigned char *data, unsigned int dataLen) {
    if ((dataLen % 16) != 0) {
        return TEST_SKIP;
    }

    return doAESOp(slot, key, CKM_AES_ECB, NULL, data, dataLen);
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

test_ret_t doAESCBCOp(PK11SlotInfo *slot, PK11SymKey *key, const unsigned char *data, unsigned int dataLen, const unsigned char *iv, unsigned int ivLen) {
    if ((dataLen % 16) != 0) {
        return TEST_SKIP;
    }

    if (ivLen != 16) {
        return TEST_SKIP;
    }

    SECItem *ivParam = getIVParam(iv, ivLen);
    test_ret_t ret = doAESOp(slot, key, CKM_AES_CBC_PAD, ivParam, data, dataLen);
    freeIVParam(ivParam);

    return ret;
}

test_ret_t doAESCBCPadOp(PK11SlotInfo *slot, PK11SymKey *key, const unsigned char *data, unsigned int dataLen, const unsigned char *iv, unsigned int ivLen) {
    if (ivLen != 16) {
        return TEST_SKIP;
    }

    SECItem *ivParam = getIVParam(iv, ivLen);
    test_ret_t ret = doAESOp(slot, key, CKM_AES_CBC_PAD, ivParam, data, dataLen);
    freeIVParam(ivParam);

    return ret;
}

test_ret_t doAESCTROp(PK11SlotInfo *slot, PK11SymKey *key, const unsigned char *data, unsigned int dataLen, unsigned int ctrLen, const unsigned char *iv, unsigned int ivLen) {
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

    return doAESOp(slot, key, CKM_AES_CTR, &ctrParam, data, dataLen);
}

test_ret_t doAESGCMOp(PK11SlotInfo *slot, PK11SymKey *key, const unsigned char *data, unsigned int dataLen, const unsigned char *iv, unsigned int ivLen, const unsigned char *aad, unsigned int aadLen) {
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

    return doAESOp(slot, key, CKM_AES_GCM, &gcmParam, data, dataLen);
}

test_ret_t testAESOp(PK11SlotInfo *slot, PK11SymKey *key, CK_MECHANISM_TYPE mech) {
    while (true) {
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
            ret = doAESECBOp(slot, key, data, dataLen);
            break;
        case CKM_AES_CBC:
            ret = doAESCBCOp(slot, key, data, dataLen, iv, ivLen);
            break;
        case CKM_AES_CBC_PAD:
            ret = doAESCBCPadOp(slot, key, data, dataLen, iv, ivLen);
            break;
        case CKM_AES_CTR:
            ret = doAESCTROp(slot, key, data, dataLen, ctrLen, iv, ivLen);
            break;
        case CKM_AES_GCM:
            ret = doAESGCMOp(slot, key, data, dataLen, iv, ivLen, aad, aadLen);
            break;
        default:
            fprintf(stderr, "Unknown mechanism to testAESOp: %lx\n", mech);
            ret = TEST_ERROR;
        }

        if (ret == TEST_SKIP) {
            fprintf(stderr, "Skipping mechanism...\n");
            continue;
        }

        return ret;
    }

    return TEST_ERROR;
}
