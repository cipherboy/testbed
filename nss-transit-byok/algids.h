#include <plstr.h>
#include <secitem.h>
#include <secmod.h>
#include <keyhi.h>
#include <pk11func.h>
#include <nspr.h>
#include <pkcs11.h>
#include <nss.h>

#include <stdio.h>

#pragma once

typedef struct NTBValuePair_s {
    char *key;
    CK_ULONG value;
} NTBValuePair_s;

CK_ULONG NTBFindPair(NTBValuePair_s *elements, size_t num_elems, char *key);

#define NUM_MECH_IDS 15
#define NUM_KEY_BITS 15

char *HexFormatByteBuffer(uint8_t *buffer, size_t length, size_t width);

uint8_t *ReadFile(size_t *ret_size, const char *path);

uint8_t *ParsePEM(size_t *base64_size, uint8_t **header, size_t *header_size, uint8_t *file_contents, size_t file_size);

uint8_t *ParsePEMKeyToDER(size_t *der_len, const char *path);
