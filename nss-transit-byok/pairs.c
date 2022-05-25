#include "algids.h"

NTBValuePair_s NTBToMechId_vp[NUM_MECH_IDS] = {
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

NTBValuePair_s NTBToKeyBits_vp[NUM_KEY_BITS] = {
    { "rsa-1024", 1024 },
    { "rsa-2048", 2048 },
    { "rsa-3072", 3072 },
    { "rsa-4096", 4096 },
    { "rsa-8192", 8192 },
    { "ed25519", 0 },
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

CK_ULONG NTBFindPair(NTBValuePair_s *elements, size_t num_elems, char *key) {
    for (size_t index = 0; index < num_elems; index++) {
        if (strcmp(elements[index].key, key) == 0) {
            return elements[index].value;
        }
    }

    return 0;
}
