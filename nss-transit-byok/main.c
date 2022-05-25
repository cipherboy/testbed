#include <plstr.h>
#include <secitem.h>
#include <secmod.h>
#include <keyhi.h>
#include <pk11func.h>
#include <nspr.h>
#include <pkcs11.h>
#include <nss.h>

#include "algids.h"

int parseImportArgs(int argc, int offset, const char **argv, const char **name, const char **file) {
    for (; offset < argc; offset++) {
        if (strcmp("-h", argv[offset]) == 0) {
            return -1;
        } else if (*name == NULL) {
            *name = argv[offset];
        } else if (*file == NULL) {
            *file = argv[offset];
        } else {
            break;
        }
    }

    return offset;
}

int doImport(int argc, int offset, const char **argv) {
    const char *name = NULL;
    const char *file = NULL;

    offset = parseImportArgs(argc, offset, argv, &name, &file);
    if (offset == -1 || name == NULL || file == NULL) {
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

    fprintf(stdout, "Handle: %lu\n", handle);
    fprintf(stdout, "Nickname: %s\n", PK11_GetPublicKeyNickname(pkey));

    return 0;
}

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
        } else {
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
        fprintf(stderr, " import NAME /path/to/key\n");
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

    if (strcmp(operation, "import") == 0) {
        return doImport(argc, offset, argv);
    }

    return 0;
}
