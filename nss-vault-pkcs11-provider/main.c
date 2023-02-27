#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <assert.h>

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

#include "allmechs.h"
#include "tests.h"

char *strdup(const char *s) {
    int len = strlen(s);
    char *ret = calloc(len+1, sizeof(char));
    memcpy(ret, s, len+1);
    return ret;
}

void parseMainArgs(int argc, const char **argv, int *offset, const char **database, size_t *num_slots, char **slot_names, char **pins, int *iters) {
    size_t max_slots = *num_slots;
    *num_slots = 0;
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
        } else if (strcmp("-s", argv[*offset]) == 0) {
            *offset += 1;
            if (*offset >= argc) {
                fprintf(stderr, "Option -s requires an argument (nss slot info); none was given\n");
                *offset = -1;
                return;
            }
            if (*num_slots >= max_slots) {
                fprintf(stderr, "More than %zu -s options given; this is more than this program was compiled with. Recompile to test more slots.\n", max_slots);
                *offset = -1;
                return;
            }
            slot_names[*num_slots] = strdup(argv[*offset]);
            *num_slots = (*num_slots) + 1;
        } else if (strcmp("-p", argv[*offset]) == 0) {
            *offset += 1;
            if (*offset >= argc) {
                fprintf(stderr, "Option -p requires an argument (slot pin); none was given\n");
                *offset = -1;
                return;
            }
            pins[*num_slots] = strdup(argv[*offset]);
        } else if (strcmp("-i", argv[*offset]) == 0) {
            *offset += 1;
            if (*offset >= argc) {
                fprintf(stderr, "Option -i requires an argument (iterations per operation); none was given\n");
                *offset = -1;
                return;
            }
            *iters = atoi(argv[*offset]);
            if (*iters <= 0) {
                fprintf(stderr, "Option -i requires a positive integer argument (iterations per operation); but was given non-integer or zero value '%s'.\n", argv[*offset]);
                *offset = -1;
                return;
            }
        } else {
            fprintf(stderr, "Unknown option (%s)", argv[*offset]);
            *offset = -1;
            return;
        }
    }
}

char *staticPassFunc(PK11SlotInfo *, PRBool retry, void *arg) {
    if (retry == PR_TRUE) {
        fprintf(stderr, "Password was invalid; asked to retry.\n");
        return NULL;
    }

    return strdup((char *)arg);
}

PK11SlotInfo *findSlot(const char *slot_name) {
    PK11SlotList *list = PK11_FindSlotsByNames(NULL, slot_name, NULL, PR_TRUE);
    if (list == NULL) {
        return NULL;
    }

    PK11SlotInfo *slot = NULL;
    for (PK11SlotListElement *le = PK11_GetFirstSafe(list); le; le = PK11_GetNextSafe(list, le, PR_TRUE)) {
        if (slot == NULL) {
            slot = PK11_ReferenceSlot(le->slot);
        } else {
            fprintf(stderr, "More than one slot with requested name.\n");
            return NULL;
        }
    }

    PK11_FreeSlotList(list);
    return slot;
}

void listSlotInfo(PK11SlotInfo *slot) {
    fprintf(stdout, "Supported Mechanisms:\n");
    for (size_t index = 0; index < sizeof(AllInfo)/sizeof(AllInfo[0]); index++) {
        MechInfo info = AllInfo[index];
        if (PK11_DoesMechanism(slot, info.value) == PR_TRUE) {
            fprintf(stdout, " - %s\n", info.name);
        }
    }
}

void listAllSlotInfos(PK11SlotInfo **slots, size_t num_slots) {
    if (num_slots == 1) {
        return;
    }

    fprintf(stdout, "Common mechanisms across all tokens:\n");
    for (size_t index = 0; index < sizeof(AllInfo)/sizeof(AllInfo[0]); index++) {
        MechInfo info = AllInfo[index];
        if (ensureAllDoMech(slots, num_slots, info.value) == PR_TRUE) {
            fprintf(stdout, " - %s\n", info.name);
        }
    }
}

int doAESTests(PK11SlotInfo **slots, size_t num_slots, int iterations) {
    CK_MECHANISM_TYPE mechs[] = {
        CKM_AES_ECB,
        CKM_AES_CBC,
        CKM_AES_CBC_PAD,
        /* CKM_AES_OFB, */ // Not supported by NSS.
        /* CKM_AES_CFB128, */ // Not supported by NSS.
        CKM_AES_CTR,
        CKM_AES_GCM,
    };

    for (size_t mech_index = 0; mech_index < sizeof(mechs)/sizeof(mechs[0]); mech_index++) {
        CK_MECHANISM_TYPE mech = mechs[mech_index];
        if (PK11_DoesMechanism(slots[0], mech) == PR_FALSE) {
            fprintf(stderr, "Skipping AES mechanism [%zu] %lx: not supported by default token.\n", mech_index, mech);
            continue;
        }

        for (int i = 0; i < iterations; i++) {
            test_ret_t ret = testAESOp(slots, num_slots, mech);
            if (ret != TEST_OK) {
                fprintf(stderr, "[%zu/%d] Failed to do AES mechanism test: %lx - %d\n", mech_index, i, mech, ret);
                return 2;
            }
        }
    }

    return 0;
}

int doHMACTests(PK11SlotInfo **slots, size_t num_slots, int iterations) {
    CK_MECHANISM_TYPE mechs[] = {
        CKM_SHA224_HMAC,
        CKM_SHA256_HMAC,
        CKM_SHA384_HMAC,
        CKM_SHA512_HMAC,
        CKM_SHA512_224_HMAC,
        CKM_SHA512_256_HMAC,
    };

    for (size_t mech_index = 0; mech_index < sizeof(mechs)/sizeof(mechs[0]); mech_index++) {
        CK_MECHANISM_TYPE mech = mechs[mech_index];
        if (PK11_DoesMechanism(slots[0], mech) == PR_FALSE) {
            fprintf(stderr, "Skipping HMAC mechanism [%zu] %lx: not supported by default token.\n", mech_index, mech);
            continue;
        }

        for (int i = 0; i < iterations; i++) {
            test_ret_t ret = testHMACOp(slots, num_slots, mech);
            if (ret != TEST_OK) {
                fprintf(stderr, "[%zu/%d] Failed to do HMAC mechanism test: %lx - %d\n", mech_index, i, mech, ret);
                return 2;
            }
        }
    }

    return 0;
}

int doRSAEncTests(PK11SlotInfo **slots, size_t num_slots, int iterations) {
    CK_MECHANISM_TYPE mechs[] = {
        CKM_RSA_PKCS,
        CKM_RSA_PKCS_OAEP,
    };

    for (size_t mech_index = 0; mech_index < sizeof(mechs)/sizeof(mechs[0]); mech_index++) {
        CK_MECHANISM_TYPE mech = mechs[mech_index];
        if (PK11_DoesMechanism(slots[0], mech) == PR_FALSE) {
            fprintf(stderr, "Skipping RSA encryption mechanism [%zu] %lx: not supported by default token.\n", mech_index, mech);
            continue;
        }

        for (int i = 0; i < iterations; i++) {
            test_ret_t ret = testRSAEncOp(slots, num_slots, mech);
            if (ret != TEST_OK) {
                fprintf(stderr, "[%zu/%d] Failed to do RSA encryption mechanism test: %lx - %d\n", mech_index, i, mech, ret);
                return 2;
            }
        }
    }

    return 0;
}

int doRSASignTests(PK11SlotInfo **slots, size_t num_slots, int iterations) {
    CK_MECHANISM_TYPE mechs[] = {
        CKM_SHA256_RSA_PKCS,
        CKM_SHA384_RSA_PKCS,
        CKM_SHA512_RSA_PKCS,
        CKM_SHA256_RSA_PKCS_PSS,
        CKM_SHA384_RSA_PKCS_PSS,
        CKM_SHA512_RSA_PKCS_PSS,
        /* CKM_RSA_PKCS, // Not supported by module right now.
        CKM_RSA_PKCS_PSS,*/
    };

    for (size_t mech_index = 0; mech_index < sizeof(mechs)/sizeof(mechs[0]); mech_index++) {
        CK_MECHANISM_TYPE mech = mechs[mech_index];
        if (PK11_DoesMechanism(slots[0], mech) == PR_FALSE) {
            fprintf(stderr, "Skipping RSA signature mechanism [%zu] %lx: not supported by default token.\n", mech_index, mech);
            continue;
        }

        for (int i = 0; i < iterations; i++) {
            test_ret_t ret = testRSASignOp(slots, num_slots, mech);
            if (ret != TEST_OK) {
                fprintf(stderr, "[%zu/%d] Failed to do RSA signature mechanism test: %lx - %d\n", mech_index, i, mech, ret);
                return 2;
            }
        }
    }

    return 0;
}


int doRSATests(PK11SlotInfo **slots, size_t num_slots, int iterations) {
    int ret = /*doRSAEncTests(slots, num_slots, iterations);
    if (ret != 0) {
        fprintf(stderr, "Failed RSA encryption tests.\n");
        return ret;
    }

    ret = */doRSASignTests(slots, num_slots, iterations);
    if (ret != 0) {
        fprintf(stderr, "Failed RSA signature tests.\n");
        return ret;
    }

    return 0;
}

int doTests(PK11SlotInfo **slots, size_t num_slots, int iterations) {
    int ret = /*doAESTests(slots, num_slots, iterations);
    if (ret != 0) {
        fprintf(stderr, "Failed AES tests.\n");
        return ret;
    }

    ret = doHMACTests(slots, num_slots, iterations);
    if (ret != 0) {
        fprintf(stderr, "Failed HMAC tests.\n");
        return ret;
    }

    ret = */doRSATests(slots, num_slots, iterations);
    if (ret != 0) {
        fprintf(stderr, "Failed RSA tests.\n");
        return ret;
    }

    return 0;
}

int main(int argc, const char **argv) {
    const char *dir = "/etc/pki/nssdb";
    char *default_slot_name = "NSS Internal Cryptographic Services";
    char *default_password = strdup("12345");

    const size_t max_num_slots = 8;
    size_t num_slots = max_num_slots;
    char *slot_names[] = { default_slot_name, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
    char *passwords[] = { default_password, NULL, NULL, NULL, NULL, NULL, NULL, NULL };

    static_assert(sizeof(slot_names)/sizeof(slot_names[0]) == max_num_slots);
    static_assert(sizeof(passwords)/sizeof(passwords[0]) == max_num_slots);

    int iterations = 1;
    int offset = 1;
    parseMainArgs(argc, argv, &offset, &dir, &num_slots, (char **)&slot_names, (char **)&passwords, &iterations);
    if (offset == -1) {
        fprintf(stderr, "Usage: %s [-d /path/to/nssdb] [-s slot-name] [-p pin] [-i iterations-count]\n", argv[0]);
        return 2;
    }

    if (num_slots == 0) {
        fprintf(stderr, "Using default slots...\n");
        num_slots = 1;
    }

    fprintf(stdout, "Loading NSS DB Directory: %s\n", dir);

    int rv = NSS_Initialize(dir, "", "", SECMOD_DB, NSS_INIT_PK11THREADSAFE);
    if (rv != SECSuccess) {
        PRErrorCode code = PORT_GetError();
        const char *message = PORT_ErrorToString(code);
           fprintf(stderr, "NSS_initialize(\"%s\") failed with code (%d): %s\n", dir, code, message);
        return 1;
    }

    PK11SlotInfo *slots[] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    for (size_t slot_index = 0; slot_index < max_num_slots && slot_index < num_slots; slot_index++) {
        char *slot_name = slot_names[slot_index];
        char *password = passwords[slot_index];
        if (slot_name == NULL) {
            break;
        }

        PK11SlotInfo *slot = findSlot(slot_name);
        if (slot == NULL) {
            fprintf(stderr, "No slot found for name: %s.\n", slot_name);
            return 1;
        }

        if (PK11_IsLoggedIn(slot, NULL) != PR_TRUE) {
            fprintf(stderr, "Slot is not logged in.\n");

            PK11_SetPasswordFunc(staticPassFunc);
            if (PK11_Authenticate(slot, PR_FALSE, password) != SECSuccess) {
                fprintf(stderr, "Unable to authenticate.\n");
                return 1;
            }
        }

        fprintf(stdout, "[%zu] Adding slot: slot:%s token:%s.\n", slot_index, PK11_GetSlotName(slot), PK11_GetTokenName(slot));
        listSlotInfo(slot);
        slots[slot_index] = slot;
    }

    listAllSlotInfos(slots, num_slots);

    if (doTests(slots, num_slots, iterations) != 0) {
        fprintf(stderr, "Tests failed.\n");
        return 1;
    }

    PK11_FreeSlot(slots[0]);
    NSS_Shutdown();
    return 0;
}
