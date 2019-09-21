#pragma once

#include "diamondhsm-cng-ksp.h"
#include "diamondhsm-ksp.h"

LPCSTR DKEYKspGetUserPin();
LPCSTR DKEYKspGetHostAddr();

DKEY_KSP_PROVIDER *DKEYKspValidateProvHandle(
	__in    NCRYPT_PROV_HANDLE hProvider);

DKEY_KSP_KEY *DKEYKspValidateKeyHandle(
	__in    NCRYPT_KEY_HANDLE hKey);