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

#include <stdbool.h>

#include "algids.h"

#define NUM_MECH_IDS 15
#define NUM_KEY_BITS 15

static NTBValuePair_s NTBToMechId_vp[NUM_MECH_IDS] = {
    { "rsa-1024", CKM_RSA_PKCS },
    { "rsa-2048", CKM_RSA_PKCS },
    { "rsa-3072", CKM_RSA_PKCS },
    { "rsa-4096", CKM_RSA_PKCS },
    { "rsa-8192", CKM_RSA_PKCS },
    { "ed25519", CKM_EDDSA },
    { "ecdsa-p192", CKM_EDDSA },
    { "ecdsa-p224", CKM_EDDSA },
    { "ecdsa-p256", CKM_EDDSA },
    { "ecdsa-p384", CKM_EDDSA },
    { "ecdsa-p512", CKM_EDDSA },
    { "aes128-gcm96", CKM_AES_GCM },
    { "aes192-gcm96", CKM_AES_GCM },
    { "aes256-gcm96", CKM_AES_GCM },
    { "chacha20-poly1305", CKM_CHACHA20 },
};

static NTBValuePair_s NTBToKeyBits_vp[NUM_KEY_BITS] = {
    { "rsa-1024", 1024 },
    { "rsa-2048", 2048 },
    { "rsa-3072", 3072 },
    { "rsa-4096", 4096 },
    { "rsa-8192", 8192 },
    { "ecdsa-p192", 192 },
    { "ecdsa-p224", 224 },
    { "ecdsa-p256", 256 },
    { "ecdsa-p384", 384 },
    { "ecdsa-p512", 512 },
    { "aes128-gcm96", 128 },
    { "aes192-gcm96", 192 },
    { "aes256-gcm96", 256 },
    { "chacha20-poly1305", 256 },
};

void parseImportArgs(int argc, int *offset, const char **argv, const char **name, const char **file) {
    for (; *offset < argc; *offset = (*offset) + 1) {
        if (strcmp("-h", argv[*offset]) == 0) {
            *offset = -1;
            return;
        } else if (*name == NULL) {
            *name = argv[*offset];
        } else if (*file == NULL) {
            *file = argv[*offset];
        } else {
            break;
        }
    }
}

int doImport(int argc, int *offset, const char **argv) {
    const char *name = NULL;
    const char *file = NULL;

    parseImportArgs(argc, offset, argv, &name, &file);
    if (*offset == -1 || name == NULL || file == NULL) {
        fprintf(stderr, "Usage: %s import NAME /path/to/key\n", argv[0]);
        return 2;
    }

    uint8_t *der = NULL;
    size_t der_len = 0;
    der = ParsePEMKeyToDER(&der_len, file);
    if (der == NULL) {
        fprintf(stderr, "Failed to parse key to DER.\n");
        return 1;
    }

    // NASTY HACK: I can't find any way to _import_ a public key into
    // NSS.
    //
    // So we abuse the format of the SubjectPublicKeyInfo of a certificate
    // and assume that our parsed PEM->DER roughly aligns to it.
    SECItem item = { siBuffer, der, (unsigned int)der_len };
    CERTSubjectPublicKeyInfo *spki = SECKEY_DecodeDERSubjectPublicKeyInfo(&item);
    if (spki == NULL) {
        PRErrorCode code = PORT_GetError();
        const char *message = PORT_ErrorToString(code);
        fprintf(stderr, "CERTSubjectPublicKeyInfo(\n%s\n) failed with code (%d): %s\n", HexFormatByteBuffer(der, der_len, 20), code, message);
        return 1;
    }

    SECKEYPublicKey *pkey = SECKEY_ExtractPublicKey(spki);
    if (pkey == NULL) {
        PRErrorCode code = PORT_GetError();
        const char *message = PORT_ErrorToString(code);
        fprintf(stderr, "SECKEY_ExtractPublicKey(spki) failed with code (%d): %s\n", code, message);
        return 1;
    }

    PK11SlotInfo *slot = PK11_GetInternalKeySlot();
    if (slot == NULL) {
        PRErrorCode code = PORT_GetError();
        const char *message = PORT_ErrorToString(code);
        fprintf(stderr, "PK11_GetInternalKeySlot() failed with code (%d): %s\n", code, message);
        return 1;
    }

    if (PK11_NeedLogin(slot)) {
        fprintf(stderr, "PK11_NeedLogin(slot) -> true\n");
        return 99;
    }

    CK_OBJECT_HANDLE handle = PK11_ImportPublicKey(slot, pkey, PR_TRUE);
    if (handle == CK_INVALID_HANDLE) {
        PRErrorCode code = PORT_GetError();
        const char *message = PORT_ErrorToString(code);
        fprintf(stderr, "PK11_ImportPublicKey(slot, pkey, true) failed with code (%d): %s\n", code, message);
        return 1;
    }

    CK_BBOOL cktrue = CK_TRUE;
    SECItem emptyItem = {0, &cktrue, sizeof(cktrue)};
    if (PK11_WriteRawAttribute(PK11_TypePubKey, pkey, CKA_WRAP, &emptyItem) != SECSuccess) {
        PRErrorCode code = PORT_GetError();
        const char *message = PORT_ErrorToString(code);
        fprintf(stderr, "PK11_WriteRawAttribute(pkey, CKA_WRAP) failed with code (%d): %s\n", code, message);
        return 1;
    }
    if (PK11_WriteRawAttribute(PK11_TypePubKey, pkey, CKA_ENCRYPT, &emptyItem) != SECSuccess) {
        PRErrorCode code = PORT_GetError();
        const char *message = PORT_ErrorToString(code);
        fprintf(stderr, "PK11_WriteRawAttribute(pkey, CKA_ENCRYPT) failed with code (%d): %s\n", code, message);
        return 1;
    }

    if (PK11_SetPublicKeyNickname(pkey, name) != SECSuccess) {
        PRErrorCode code = PORT_GetError();
        const char *message = PORT_ErrorToString(code);
        fprintf(stderr, "PK11_SetPublicKeyNickname(pkey, \"%s\") failed with code (%d): %s\n", name, code, message);
        return 1;
    }

    fprintf(stdout, "Imported Nickname: %s\n", PK11_GetPublicKeyNickname(pkey));

    return 0;
}

void parseGenerateArgs(int argc, int *offset, const char **argv, const char **name, const char **type) {
    for (; *offset < argc; *offset = (*offset) + 1) {
        if (strcmp("-h", argv[*offset]) == 0) {
            *offset = -1;
            return;
        } else if (*name == NULL) {
            *name = argv[*offset];
        } else if (*type == NULL) {
            *type = argv[*offset];
        } else {
            break;
        }
    }
}

int doGenerate(int argc, int *offset, const char **argv) {
    const char *name = NULL;
    const char *type = NULL;

    parseImportArgs(argc, offset, argv, &name, &type);
    if (*offset == -1 || name == NULL || type == NULL) {
        fprintf(stderr, "Usage: %s generate NAME TYPE\n", argv[0]);
        fprintf(stderr, "Known types:\n");
        for (size_t index = 0; index < NUM_MECH_IDS; index++) {
            fprintf(stderr, " - %s\n", NTBToMechId_vp[index].key);
        }
        return 2;
    }

    CK_MECHANISM_TYPE mech = NTBFindPair(NTBToMechId_vp, NUM_MECH_IDS, type);
    if (mech == 0) {
        fprintf(stderr, "Unknown mechanism for type: %s\n", type);
        return 1;
    }

    CK_ULONG bits = NTBFindPair(NTBToKeyBits_vp, NUM_KEY_BITS, type);

    PK11SlotInfo *slot = PK11_GetInternalKeySlot();
    if (slot == NULL) {
        PRErrorCode code = PORT_GetError();
        const char *message = PORT_ErrorToString(code);
        fprintf(stderr, "PK11_GetInternalKeySlot() failed with code (%d): %s\n", code, message);
        return 1;
    }

    SECKEYPrivateKey *private = NULL;
    SECKEYPublicKey *public = NULL;

    if (mech == CKM_RSA_PKCS) {
        PK11RSAGenParams rsaparams;
        rsaparams.keySizeInBits = bits;
        rsaparams.pe = 65537;

        private = PK11_GenerateKeyPair(slot, CKM_RSA_PKCS_KEY_PAIR_GEN, &rsaparams, &public, PR_TRUE, PR_FALSE, NULL);
        if (private == NULL) {
            PRErrorCode code = PORT_GetError();
            const char *message = PORT_ErrorToString(code);
            fprintf(stderr, "PK11_GenerateKeyPair() failed with code (%d): %s\n", code, message);
            return 1;
        }
    }

    if (private != NULL && public != NULL) {
        if (PK11_SetPrivateKeyNickname(private, name) != SECSuccess) {
            PRErrorCode code = PORT_GetError();
            const char *message = PORT_ErrorToString(code);
            fprintf(stderr, "PK11_SetPublicKeyNickname(pkey, \"%s\") failed with code (%d): %s\n", name, code, message);
            return 1;
        }

        if (PK11_SetPublicKeyNickname(public, name) != SECSuccess) {
            PRErrorCode code = PORT_GetError();
            const char *message = PORT_ErrorToString(code);
            fprintf(stderr, "PK11_SetPublicKeyNickname(pkey, \"%s\") failed with code (%d): %s\n", name, code, message);
            return 1;
        }

        SECItem *publicItem = PK11_DEREncodePublicKey(public);
        fprintf(stdout, "Generated Nickname: %s\n", PK11_GetPublicKeyNickname(public));
        fprintf(stdout, "Generated Key:\n%s\n", HexFormatByteBuffer(publicItem->data, publicItem->len, 0));
    }

    return 0;
}

void parseExportArgs(int argc, int *offset, const char **argv, int *aes_bits, int *hash_bits, int *mgf_bits, const char **signWith, const char **toSign) {
    for (; *offset < argc; *offset = (*offset) + 1) {
        if (strcmp("-h", argv[*offset]) == 0) {
            *offset = -1;
            return;
        } else if (strcmp("-b", argv[*offset]) == 0) {
            *offset += 1;
            if (*offset >= argc) {
                fprintf(stderr, "Option -b requires an argument (number of bits); none was given\n");
                *offset = -1;
                return;
            }

            *aes_bits = atoi(argv[*offset]);
            if (*aes_bits != 128 && *aes_bits != 192 && *aes_bits != 256) {
                fprintf(stderr, "Option -b only accepts 128/192/256 bits; got %s -> %d\n", argv[*offset], *aes_bits);
                *offset = -1;
                return;
            }
        } else if (strcmp("-h", argv[*offset]) == 0) {
            *offset += 1;
            if (*offset >= argc) {
                fprintf(stderr, "Option -h requires an argument (number of bits in hash function); none was given\n");
                *offset = -1;
                return;
            }

            *hash_bits = atoi(argv[*offset]);
            if (*hash_bits != 160 && *hash_bits != 224 && *hash_bits != 256 && *hash_bits != 384 && *hash_bits != 512) {
                fprintf(stderr, "Option -h only accepts 160/224/256/384/512 bits; got %s -> %d\n", argv[*offset], *aes_bits);
                *offset = -1;
                return;
            }
        } else if (strcmp("-m", argv[*offset]) == 0) {
            *offset += 1;
            if (*offset >= argc) {
                fprintf(stderr, "Option -m requires an argument (number of bits in MGF hash function); none was given\n");
                *offset = -1;
                return;
            }

            *mgf_bits = atoi(argv[*offset]);
            if (*hash_bits != 160 && *hash_bits != 224 && *hash_bits != 256 && *hash_bits != 384 && *hash_bits != 512) {
                fprintf(stderr, "Option -m only accepts 160/224/256/384/512 bits; got %s -> %d\n", argv[*offset], *aes_bits);
                *offset = -1;
                return;
            }
        } else if (*signWith == NULL) {
            *signWith = argv[*offset];
        } else if (*toSign == NULL) {
            *toSign = argv[*offset];
        } else {
            break;
        }
    }
}

SECKEYPublicKey *findPublicKeyWithName(PK11SlotInfo *slot, char *signWith) {
    SECKEYPublicKey *outer = NULL;
    SECKEYPublicKeyList *pub_list = PK11_ListPublicKeysInSlot(slot, signWith);
    SECKEYPublicKeyListNode *pub_head = PUBKEY_LIST_HEAD(pub_list);
    while (!PUBKEY_LIST_END(pub_head, pub_list)) {
        if (outer == NULL) {
            outer = pub_head->key;
        } else {
            fprintf(stderr, "Too many outer wrapping keys with same name: %s\n", signWith);
            return NULL;
        }
        pub_head = PUBKEY_LIST_NEXT(pub_head);
    }

    return outer;
}

SECKEYPrivateKey *findPrivateKeyWithName(PK11SlotInfo *slot, char *toSign) {
    SECKEYPrivateKey *candidate = NULL;
    SECKEYPrivateKeyList *priv_list = PK11_ListPrivKeysInSlot(slot, toSign, NULL);
    SECKEYPrivateKeyListNode *priv_head = PRIVKEY_LIST_HEAD(priv_list);
    while (!PRIVKEY_LIST_END(priv_head, priv_list)) {
        if (candidate == NULL) {
            candidate = priv_head->key;
        } else {
            fprintf(stderr, "Too many inner private keys with same name: %s (%p!=%p)\n", toSign, candidate, priv_head->key);

            char *empty = "\0";
            char *candidateName = empty;
            if (candidate->pkcs11Slot != NULL) {
                candidateName = PK11_GetPrivateKeyNickname(candidate);
            }
            SECKEYPublicKey *candidateKey = SECKEY_ConvertToPublicKey(candidate);
            char *candidatePublicName = empty;
            if (candidateKey->pkcs11Slot != NULL) {
                // SLOT may be NULL due to SECKEY_ConvertToPublicKey.
                candidatePublicName = PK11_GetPublicKeyNickname(candidateKey);
            }
            SECItem *candidateItem = PK11_DEREncodePublicKey(candidateKey);

            char *nextName = empty;
            if (priv_head->key->pkcs11Slot != NULL) {
                nextName = PK11_GetPrivateKeyNickname(priv_head->key);
            }
            SECKEYPublicKey *nextKey = SECKEY_ConvertToPublicKey(priv_head->key);
            char *nextPublicName = empty;
            if (nextKey->pkcs11Slot != NULL) {
                nextPublicName = PK11_GetPublicKeyNickname(nextKey);
            }
            SECItem *nextItem = PK11_DEREncodePublicKey(nextKey);

            fprintf(stderr, "First (%s->%s):\n%s\nSecond (%s->%s):\n%s\n", candidateName, candidatePublicName, HexFormatByteBuffer(candidateItem->data, candidateItem->len, 0), nextName, nextPublicName, HexFormatByteBuffer(nextItem->data, nextItem->len, 0));
            return NULL;
        }
        priv_head = PRIVKEY_LIST_NEXT(priv_head);
    }

    return candidate;
}

CK_MECHANISM_TYPE hashBitsToMech(int bits) {
    switch (bits) {
        case 160:
            return CKM_SHA_1;
        case 224:
            return CKM_SHA224;
        case 256:
            return CKM_SHA256;
        case 384:
            return CKM_SHA384;
        case 512:
            return CKM_SHA512;
    }
    return 0;
}

CK_RSA_PKCS_MGF_TYPE mgfBitsToMech(int bits) {
    switch (bits) {
        case 160:
            return CKG_MGF1_SHA1;
        case 224:
            return CKG_MGF1_SHA256;
        case 256:
            return CKG_MGF1_SHA256;
        case 384:
            return CKG_MGF1_SHA384;
        case 512:
            return CKG_MGF1_SHA512;
    }
    return 0;
}

PK11SymKey *findSymmetricKeyWithName(PK11SlotInfo *slot, char *toSign) {
    PK11SymKey *candidate = PK11_ListFixedKeysInSlot(slot, toSign, NULL);
    return candidate;
}

int doExport(int argc, int *offset, const char **argv) {
    int aes_bits = 128;
    int hash_bits = 256;
    int mgf_bits = 256;
    const char *signWith = NULL;
    const char *toSign = NULL;

    parseExportArgs(argc, offset, argv, &aes_bits, &hash_bits, &mgf_bits, &signWith, &toSign);
    if (*offset == -1 || signWith == NULL || toSign == NULL) {
        fprintf(stderr, "Usage: %s export [-b AES_BITS] SIGNWITH TOSIGN\n", argv[0]);
        return 2;
    }

    fprintf(stdout, "AES key bits: %d\n", aes_bits);
    fprintf(stdout, "hash bits: %d\n", hash_bits);
    fprintf(stdout, "mgf1 bits: %d\n", mgf_bits);

    // Grab the slot.
    PK11SlotInfo *slot = PK11_GetInternalKeySlot();
    if (slot == NULL) {
        PRErrorCode code = PORT_GetError();
        const char *message = PORT_ErrorToString(code);
        fprintf(stderr, "PK11_GetInternalKeySlot() failed with code (%d): %s\n", code, message);
        return 1;
    }

    // Find the keys.
    SECKEYPublicKey *outer = findPublicKeyWithName(slot, (char *)signWith);
    if (outer == NULL) {
        fprintf(stderr, "Unable to find outer wrapping key with name: %s\n", signWith);
        return 1;
    }

    SECKEYPrivateKey *asymCandidate = findPrivateKeyWithName(slot, (char *)toSign);
    PK11SymKey *symCandidate = findSymmetricKeyWithName(slot, (char *)toSign);

    if (asymCandidate == NULL && symCandidate == NULL) {
        fprintf(stderr, "Unable to find inner private or asymmetric key with name: %s\n", toSign);
        return 1;
    } else if (asymCandidate != NULL && symCandidate != NULL) {
        fprintf(stderr, "Found both inner private and asymmetric key with name: %s\n", toSign);
        return 1;
    }

    // Now, wrap wrap wrap. Start by generating a new AES key for wrapping.
    // It turns out that NSS only allows wrap->wrap and doesn't have a
    // one-shot helper for this call.
    PK11SymKey *transient = PK11_KeyGen(slot, CKM_AES_KEY_GEN, NULL, aes_bits/8, NULL);
    if (transient == NULL) {
        PRErrorCode code = PORT_GetError();
        const char *message = PORT_ErrorToString(code);
        fprintf(stderr, "Unable to generate transient wrapping key (%d): %s\n", code, message);
        return 1;
    }

    SECItem wrappedTransient;
    wrappedTransient.len = 4096;
    wrappedTransient.data = PR_Calloc(wrappedTransient.len, sizeof(uint8_t));

    CK_RSA_PKCS_OAEP_PARAMS oaep_params = {hashBitsToMech(hash_bits),
                                           mgfBitsToMech(mgf_bits),
                                           CKZ_DATA_SPECIFIED, NULL, 0};

    SECItem param;
    param.data = (unsigned char *)&oaep_params;
    param.len = sizeof(oaep_params);

    if (PK11_PubWrapSymKeyWithMechanism(outer, CKM_RSA_PKCS_OAEP, &param, transient, &wrappedTransient) != SECSuccess) {
        PRErrorCode code = PORT_GetError();
        const char *message = PORT_ErrorToString(code);
        fprintf(stderr, "Unable to wrap transient wrapping key (%d): %s\n", code, message);
        return 1;
    }

    SECItem wrappedCandidate;
    wrappedCandidate.len = 40960;
    wrappedCandidate.data = PR_Calloc(wrappedCandidate.len, sizeof(uint8_t));

    if (asymCandidate != NULL) {
        if (PK11_WrapPrivKey(slot, transient, asymCandidate, CKM_AES_KEY_WRAP_KWP, NULL, &wrappedCandidate, NULL) != SECSuccess) {
            PRErrorCode code = PORT_GetError();
            const char *message = PORT_ErrorToString(code);
            fprintf(stderr, "Unable to wrap transient wrapping key (%d): %s\n", code, message);
            return 1;
        }
    }

    size_t totalLen = wrappedTransient.len + wrappedCandidate.len;
    uint8_t *allData = calloc(wrappedTransient.len + wrappedCandidate.len, sizeof(uint8_t));
    memcpy(allData, wrappedTransient.data, wrappedTransient.len);
    memcpy(allData + wrappedTransient.len, wrappedCandidate.data, wrappedCandidate.len);

    fprintf(stdout, "Wrapped data (%u + %u = %zu bytes):\n%s", wrappedTransient.len, wrappedCandidate.len, totalLen, BTOA_DataToAscii(allData, totalLen));

    return 0;
}

void parseMainArgs(int argc, int *offset, const char **argv, const char **database, const char **operation) {
    for (; *offset < argc; *offset = (*offset) + 1) {
        if (strcmp("-h", argv[*offset]) == 0) {
            *offset = -1;
            return;
        } else if (strcmp("-d", argv[*offset]) == 0) {
            *offset += 1;
            if (*offset >= argc) {
                fprintf(stderr, "Option -d requires an argument (nss db directory path); none was given\n");
                *offset = -1;
                return;
            }
            *database = argv[*offset];
        } else if (*operation == NULL) {
            *operation = argv[*offset];
            *offset += 1;
            return;
        } else {
            fprintf(stderr, "Unknown option (%s)", argv[*offset]);
            *offset = -1;
            return;
        }
    }
}

int main(int argc, const char **argv) {
    const char *dir = "/etc/pki/nssdb";
    const char *operation = NULL;

    int offset = 1;
    bool initialized = false;

    while (true) {
        parseMainArgs(argc, &offset, argv, &dir, &operation);
        if (offset == -1 || operation == NULL) {
            if (initialized) {
                break;
            }

            fprintf(stderr, "Usage: %s [-d /path/to/nssdb] COMMAND\n", argv[0]);
            fprintf(stderr, "Commands:\n");
            fprintf(stderr, " import NAME /path/to/key\n");
            fprintf(stderr, " generate NAME TYPE\n");
            fprintf(stderr, " export SIGNWITH TOSIGN\n");
            return 2;
        }

        if (!initialized) {
            fprintf(stdout, "Loading NSS DB Directory: %s\n", dir);

            int rv = NSS_Initialize(dir, "", "", SECMOD_DB, NSS_INIT_PK11THREADSAFE);
            if (rv != SECSuccess) {
                PRErrorCode code = PORT_GetError();
                const char *message = PORT_ErrorToString(code);
                fprintf(stderr, "NSS_initialize(\"%s\") failed with code (%d): %s\n", dir, code, message);
                return 1;
            }

            initialized = true;
        }

        int ret = 0;
        if (strcmp(operation, "import") == 0) {
            ret = doImport(argc, &offset, argv);
        } else if (strcmp(operation, "generate") == 0) {
            ret = doGenerate(argc, &offset, argv);
        } else if (strcmp(operation, "export") == 0) {
            ret = doExport(argc, &offset, argv);
        }

        if (ret != 0) {
            return ret;
        }

        operation = NULL;
    }

    NSS_Shutdown();

    return 0;
}
