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

    /* Hard coded, static key to import -- see kTestPrivateKeyInfoDER
     * from nss/gtests/pk11_gtest/pk11_find_certs_unittest.cc. */
    uint8_t priv_key[138] = {
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
        0x21, 0x91, 0x40, 0x3d, 0x57, 0x10, 0xbf, 0x15, 0xa2, 0x65, 0x81, 0x8c,
        0xd4, 0x2e, 0xd6, 0xfe, 0xdf, 0x09, 0xad, 0xd9, 0x2d, 0x78, 0xb1, 0x8e,
        0x7a, 0x1e, 0x9f, 0xeb, 0x95, 0x52, 0x47, 0x02, 0xa1, 0x44, 0x03, 0x42,
        0x00, 0x04, 0x4f, 0xbf, 0xbb, 0xbb, 0x61, 0xe0, 0xf8, 0xf9, 0xb1, 0xa6,
        0x0a, 0x59, 0xac, 0x87, 0x04, 0xe2, 0xec, 0x05, 0x0b, 0x42, 0x3e, 0x3c,
        0xf7, 0x2e, 0x92, 0x3f, 0x2c, 0x4f, 0x79, 0x4b, 0x45, 0x5c, 0x2a, 0x69,
        0xd2, 0x33, 0x45, 0x6c, 0x36, 0xc4, 0x11, 0x9d, 0x07, 0x06, 0xe0, 0x0e,
        0xed, 0xc8, 0xd1, 0x93, 0x90, 0xd7, 0x99, 0x1b, 0x7b, 0x2d, 0x07, 0xa3,
        0x04, 0xea, 0xa0, 0x4a, 0xa6, 0xc0
    };

    SECItem priv_key_item = {siBuffer, priv_key, 138};
    SECItem nickname = {siBuffer, "nickname", 9};

    /* Get the internal slot -- this is the FIPS slot when running in FIPS
     * mode. */
    PK11SlotInfo *slot = PK11_GetInternalSlot();
    if (slot == NULL) {
        FATAL("Expected slot to be non-NULL but was NULL.");
        return 4;
    }

    /* Import our private key. Returns NULL in the event of failure. */
    SECStatus ret;
    SECKEYPrivateKey *key = NULL;
    ret = PK11_ImportDERPrivateKeyInfoAndReturnKey(slot, &priv_key_item, &nickname, NULL, PR_FALSE, PR_TRUE, 0, &key, NULL);

    if (ret != SECSuccess) {
        FATAL("Expected result to be SECSuccess but was SECFailure.");
        return 5;
    }

    if (key == NULL) {
        FATAL("Expected key to be non-NULL but was NULL.");
        return 6;
    }

    /* At this point, our key is usable anywhere from the PKCS#11 API. */
    printf("Succeeded in importing private key.\n");

    return 0;

}
