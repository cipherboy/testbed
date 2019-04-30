#include <assert.h>
#include <openssl/ec.h>
#include <openssl/objects.h>

int main() {
    BN_CTX *bnctx = BN_CTX_new();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    EC_POINT *point = EC_POINT_new(group);

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    // This point simulates the identity point on many curves.
    // Allowing it frequently means that the shared key is 0 (e.g., in
    // EAP-PWD).
    BN_hex2bn(&x, "0");
    BN_hex2bn(&y, "0");

    assert (!EC_POINT_set_affine_coordinates_GFp(group, point, x, y, bnctx));
    return 0;
}
