#include <plstr.h>
#include <secitem.h>
#include <secmod.h>
#include <keyhi.h>
#include <pk11func.h>
#include <nspr.h>
#include <pkcs11.h>
#include <nss.h>

#pragma once

typedef struct NTBValuePair_s {
    char *key;
    CK_ULONG value;
} NTBValuePair_s;

CK_ULONG NTBFindPair(NTBValuePair_s *elements, size_t num_elems, char *key);

#define NUM_MECH_IDS 15
#define NUM_KEY_BITS 15
