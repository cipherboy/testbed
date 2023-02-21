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

#define MAX_ATTEMPTS 10
#define MAX_HMAC_OUTPUT_LEN 512

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
            fprintf(stderr, "[Slot %s / Token %s]->[Slot %s / Token %s] Failed to move symmetric key with mechanism %lx to destination slot: (%d) %s\n", PK11_GetSlotName(default_slot), PK11_GetTokenName(default_slot), PK11_GetSlotName(dest_slot), PK11_GetTokenName(dest_slot), mech, code, message);
            return SECFailure;
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
    PK11SymKey **keys = calloc(num_slots, sizeof(PK11SymKey *));
    CK_FLAGS opFlags = CKF_SIGN | CKF_VERIFY;
    if (establishSymKeyOnSlots(slots, num_slots, CKM_SHA256_HMAC, 16, opFlags, keys) == SECFailure) {
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
