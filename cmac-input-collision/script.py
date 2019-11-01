#!/usr/bin/python3

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

NUM_SAMPLES = 256*256*256
INPUT_LEN=14

def gen_key():
    return os.urandom(16)

def shiftleftone(data):
    out = [None] * len(data)
    for i in range(0, len(data) - 1):
        out[i] = (data[i] << 1) & 0xFF
        out[i] |= data[i+1] >> 7
    out[len(data)-1] = (data[len(data) - 1] << 1) & 0xFF

    return out

def gen_subkeys(key):
    """
    6.1 Subkey Generation
    """

    assert len(key) == 16
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Step 1: L = CIPH_K(0^b)
    L = encryptor.update(bytes([0x00] * 16))
    assert len(L) == 16

    K1 = shiftleftone(L)
    if (L[0] & 0x80) == 0x80:
        K1[len(K1) - 1] ^= 0x87
    K1 = bytes(K1)

    K2 = shiftleftone(K1)
    if (K1[0] & 0x80) == 0x80:
        K2[len(K2) - 1] ^= 0x87
    K2 = bytes(K2)

    return K1, K2

def main():
    valid = 0
    for sample in range(0, NUM_SAMPLES):
        key = gen_key()
        K1, K2 = gen_subkeys(key)

        k1s = K1[INPUT_LEN:]
        k2s = list(K2[INPUT_LEN:])
        k2s[0] ^= 0x80
        k2s = bytes(k2s)

        if k1s == k2s:
            valid += 1

    print(f"{valid}/{NUM_SAMPLES}")


if __name__ == "__main__":
    main()
