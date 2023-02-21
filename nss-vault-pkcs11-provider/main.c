#include <string.h>
#include <strings.h>
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

#include "allmechs.h"
#include "tests.h"

char *strdup(const char *s) {
    int len = strlen(s);
    char *ret = calloc(len+1, sizeof(char));
    memcpy(ret, s, len+1);
    return ret;
}

void parseMainArgs(int argc, int *offset, const char **argv, const char **database, const char **slot_name, char **pin, int *iters) {
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
            *slot_name = argv[*offset];
        } else if (strcmp("-p", argv[*offset]) == 0) {
            *offset += 1;
            if (*offset >= argc) {
                fprintf(stderr, "Option -p requires an argument (slot pin); none was given\n");
                *offset = -1;
                return;
            }
            *pin = strdup(argv[*offset]);
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

int doAESTests(PK11SlotInfo *slot, int iterations) {
    CK_FLAGS opFlags = CKF_ENCRYPT | CKF_DECRYPT;
    PK11SymKey *key = PK11_TokenKeyGenWithFlags(slot, CKM_AES_KEY_GEN, NULL, 16, NULL, opFlags, 0, NULL);
    if (key == NULL) {
        fprintf(stderr, "Failed to generate AES key.\n");
        return 1;
    }

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
        for (int i = 0; i < iterations; i++) {
            test_ret_t ret = testAESOp(slot, key, mech);
            if (ret != TEST_OK) {
                fprintf(stderr, "[%d] Failed to do mechanism test: %lx - %d\n", i, mech, ret);
                return 2;
            }
        }
    }

    PK11_FreeSymKey(key);
    return 0;
}

int doEncryptTests(PK11SlotInfo *slot, int iterations) {
    return doAESTests(slot, iterations);
}

int main(int argc, const char **argv) {
    const char *dir = "/etc/pki/nssdb";
    const char *slot_name = "NSS Internal Cryptographic Services";
    char *password = "12345";
    int iterations = 1;

    int offset = 1;
    parseMainArgs(argc, &offset, argv, &dir, &slot_name, &password, &iterations);
    if (offset == -1) {
        fprintf(stderr, "Usage: %s [-d /path/to/nssdb] [-s slot-name] [-p pin] [-i iterations-count]\n", argv[0]);
        return 2;
    }

    fprintf(stdout, "Loading NSS DB Directory: %s\n", dir);

    int rv = NSS_Initialize(dir, "", "", SECMOD_DB, NSS_INIT_PK11THREADSAFE);
    if (rv != SECSuccess) {
        PRErrorCode code = PORT_GetError();
        const char *message = PORT_ErrorToString(code);
           fprintf(stderr, "NSS_initialize(\"%s\") failed with code (%d): %s\n", dir, code, message);
        return 1;
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

    fprintf(stdout, "Operating on slot: slot:%s token:%s.\n", PK11_GetSlotName(slot), PK11_GetTokenName(slot));
    listSlotInfo(slot);

    fprintf(stdout, "sizeof(CK_MECHANISM_TYPE) = %zu\n", sizeof(CK_MECHANISM_TYPE));

    if (doEncryptTests(slot, iterations) != 0) {
        fprintf(stderr, "Encryption tests failed.\n");
        return 1;
    }

    PK11_FreeSlot(slot);
    NSS_Shutdown();
    return 0;
}
