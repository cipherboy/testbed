#include <plstr.h>
#include <secitem.h>
#include <secmod.h>
#include <keyhi.h>
#include <pk11func.h>
#include <nspr.h>
#include <pkcs11.h>
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

    if (PK11_SetPublicKeyNickname(pkey, name) != SECSuccess) {
        PRErrorCode code = PORT_GetError();
        const char *message = PORT_ErrorToString(code);
        fprintf(stderr, "PK11_SetPublicKeyNickname(pkey, \"%s\") failed with code (%d): %s\n", name, code, message);
        return 1;
    }

    fprintf(stdout, "Imported Nickname: %s\n", PK11_GetPublicKeyNickname(pkey));

    PK11_FreeSlot(slot);
    SECKEY_DestroyPublicKey(pkey);

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

        fprintf(stdout, "Generated Nickname: %s\n", PK11_GetPublicKeyNickname(public));
    }

    return 0;
}

void parseExportArgs(int argc, int *offset, const char **argv, int *aes_bits, const char **signWith, const char **toSign) {
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
        } else if (*signWith == NULL) {
            *signWith = argv[*offset];
        } else if (*toSign == NULL) {
            *toSign = argv[*offset];
        } else {
            break;
        }
    }
}

int doExport(int argc, int *offset, const char **argv) {
    int aes_bits = 128;
    const char *signWith = NULL;
    const char *toSign = NULL;

    parseExportArgs(argc, offset, argv, &aes_bits, &signWith, &toSign);
    if (*offset == -1 || signWith == NULL || toSign == NULL) {
        fprintf(stderr, "Usage: %s export [-b AES_BITS] SIGNWITH TOSIGN\n", argv[0]);
        return 2;
    }

    // Grab the slot.
    PK11SlotInfo *slot = PK11_GetInternalKeySlot();
    if (slot == NULL) {
        PRErrorCode code = PORT_GetError();
        const char *message = PORT_ErrorToString(code);
        fprintf(stderr, "PK11_GetInternalKeySlot() failed with code (%d): %s\n", code, message);
        return 1;
    }

    // Find the keys.
    SECKEYPublicKey *outer = NULL;
    SECKEYPublicKeyList *pub_list = PK11_ListPublicKeysInSlot(slot, (char *)signWith);
    SECKEYPublicKeyListNode *pub_head = PUBKEY_LIST_HEAD(pub_list);
    while (!PUBKEY_LIST_END(pub_head, pub_list)) {
        if (outer == NULL) {
            outer = pub_head->key;
        } else {
            fprintf(stderr, "Too many outer wrapping keys with same name: %s\n", signWith);
            return 1;
        }
        pub_head = PUBKEY_LIST_NEXT(pub_head);
    }

    if (outer == NULL) {
        fprintf(stderr, "Unable to find outer wrapping key with name: %s\n", signWith);
        return 1;
    }

    SECKEYPrivateKey *candidate = NULL;
    SECKEYPrivateKeyList *priv_list = PK11_ListPrivKeysInSlot(slot, (char *)toSign, NULL);
    SECKEYPrivateKeyListNode *priv_head = PRIVKEY_LIST_HEAD(priv_list);
    while (!PRIVKEY_LIST_END(priv_head, priv_list)) {
        if (candidate == NULL) {
            candidate = priv_head->key;
        } else {
            fprintf(stderr, "Too many inner private keys with same name: %s (%p!=%p)\n", toSign, candidate, priv_head->key);
            return 1;
        }
        priv_head = PRIVKEY_LIST_NEXT(priv_head);
    }

    if (candidate == NULL) {
        fprintf(stderr, "Unable to find inner private key with name: %s\n", toSign);
        return 1;
    }

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
