/* System includes */
#include <stdio.h>

/* NSS Includes */
#include <nss.h>
#include <nspr.h>
#include <pk11pub.h>
#include <secerr.h>
#include <blapi.h>

#define FATAL(msg) fprintf(stderr, "[FATAL] %s\n\tCode: [%u] | Name [%s]\n", \
        msg, \
        PR_GetError(), \
        PR_ErrorToName(PR_GetError()));

int main(int argc, char **argv) {
    /* Need at least one argument: NSS DB path. */
    if (argc <= 1) {
        FATAL("Usage: a.out /path/to/NSSDB");
        return 1;
    }

    /* Initialize NSS with NSS DB from argv[1]. */
    if (NSS_Init(argv[1]) != SECSuccess) {
        FATAL("Expected NSS Initialization to succeed.\n");
        return 2;
    }

    /* Validate that we're actually in FIPS mode. */
    if (!PK11_IsFIPS()) {
        FATAL("Expected NSS DB to be in FIPS mode but wasn't.\n");
        return 3;
    }

    /* Hard coded, static key to import. */
    uint8_t key[AES_128_KEY_LENGTH] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE,
                                       0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88,
                                       0x09, 0xCF, 0x4F, 0x3C};

    SECItem key_item = {siBuffer, key, AES_128_KEY_LENGTH};
    SECItem data_item = {siBuffer, NULL, 0};

    /* Get the internal slot -- this is the FIPS slot when running in FIPS
     * mode. */
    PK11SlotInfo *slot = PK11_GetInternalSlot();
    if (slot == NULL) {
        FATAL("Expected slot to be non-NULL but was NULL.");
        return 4;
    }

    /* Import our symmetric key. Returns NULL in the event of failure. */
    PK11SymKey *pk11_key = PK11_ImportSymKey(slot, CKM_AES_CBC,
                                             PK11_OriginUnwrap, CKA_SIGN,
                                             &key_item, NULL);
    if (key == NULL) {
        FATAL("Expected slot to be non-NULL but was NULL.");
        return 5;
    }

    /* At this point, our key is usable anywhere from the PKCS#11 API. */
    printf("Succeeded in importing key.\n");

    return 0;

}

