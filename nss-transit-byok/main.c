#include <plstr.h>
#include <secitem.h>
#include <secmod.h>
#include <keyhi.h>
#include <pk11func.h>
#include <nspr.h>
#include <pkcs11.h>
#include <nss.h>

#include "algids.h"

int parseMainArgs(int argc, int offset, const char **argv, const char **database, const char **operation) {
    for (; offset < argc; offset++) {
        if (strcmp("-h", argv[offset]) == 0) {
            return -1;
        } else if (strcmp("-d", argv[offset]) == 0) {
            offset += 1;
            if (offset >= argc) {
                fprintf(stderr, "Option -d requires an argument; none was given\n");
                return -1;
            }
            *database = argv[offset];
        } else if (*operation == NULL) {
            *operation = argv[offset];
            break;
        }
    }

    return offset;
}

int main(int argc, const char **argv) {
    const char *dir = "/etc/pki/nssdb";
    const char *operation = NULL;

    int offset = parseMainArgs(argc, 1, argv, &dir, &operation);
    if (offset == -1 || operation == NULL) {
        fprintf(stderr, "Usage: %s [-d /path/to/nssdb] COMMAND\n", argv[0]);
        fprintf(stderr, "Commands:\n");
        fprintf(stderr, " import /path/to/key\n");
        return 2;
    }

    int rv = NSS_Initialize(dir, "", "", SECMOD_DB, NSS_INIT_PK11THREADSAFE);
    if (rv != SECSuccess) {
        PRErrorCode code = PORT_GetError();
        const char *message = PORT_ErrorToString(code);
        fprintf(stderr, "NSS_initialize(\"%s\") failed with code (%d): %s\n", dir, code, message);
        return 1;
    }

    /*if (strcmp(operation, "import") == 0) {
        doImport();
    }*/

    return 0;
}
