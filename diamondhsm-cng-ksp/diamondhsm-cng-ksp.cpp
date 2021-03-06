// Copyright 2019 Diamond Key Security, NFP
// All Rights Reserved
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met :
//
// -Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// - Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// - Neither the name of the NORDUnet nor the names of its contributors may
// be used to endorse or promote products derived from this software
// without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES(INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT(INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// diamondhsm-cng-ksp.cpp : Defines the exported functions for the DLL application.
//
#include "stdafx.h"

#include "diamondhsm-cng-ksp.h"
#include "internal.h"

extern "C"
{
#include "../cryptech-libhal/hal.h"
#include "../cryptech-libhal/hal_internal.h"
}

NCRYPT_KEY_STORAGE_FUNCTION_TABLE FunctionTable =
{
	NCRYPT_KEY_STORAGE_INTERFACE_VERSION,
	OpenProvider,
	OpenKey,
	CreatePersistedKey,
	GetProviderProperty,
	GetKeyProperty,
	SetProviderProperty,
	SetKeyProperty,
	FinalizeKey,
	DeleteKey,
	FreeProvider,
	FreeKey,
	FreeBuffer,
	Encrypt,
	Decrypt,
	IsAlgSupported,
	EnumAlgorithms,
	EnumKeys,
	ImportKey,
	ExportKey,
	SignHash,
	VerifySignature,
	PromptUser,
	NotifyChangeKey,
	SecretAgreement,
	DeriveKey,
	FreeSecret
};

_Check_return_ NTSTATUS WINAPI GetKeyStorageInterface(
	_In_   LPCWSTR pszProviderName,
	_Out_  NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
	_In_   DWORD dwFlags
)
{
	// don't worry about unused parameters
	UNREFERENCED_PARAMETER(pszProviderName);
	UNREFERENCED_PARAMETER(dwFlags);

	// return the table
	if (ppFunctionTable != NULL)
	{
		*ppFunctionTable = &FunctionTable;
	}

	return ERROR_SUCCESS;
}

static BOOL g_bConnectionOpen = FALSE;
static DWORD g_dwNumOpenProviders = 0;

// Initializes the provider.It is implemented by your key storage provider(KSP) and called by the NCryptOpenStorageProvider function.
// Parameters
// phProvider[out] - A pointer to a NCRYPT_PROV_HANDLE variable that receives the provider handle.
//
// pszProviderName[in] -  A pointer to a null - terminated Unicode string that contains the name of the provider.
//
// dwFlags[in] - Flags that modify the behavior of the function.These flags are passed directly from the NCryptOpenStorageProvider function.
//
// Return value
// Your implementation of this function in a CNG key storage provider(KSP) must return ERROR_SUCCESS if the function succeeds.
// Otherwise, return an error code. All status codes are logged then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS      The function was successful.
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI OpenProvider(
	_Out_   NCRYPT_PROV_HANDLE *phProvider,
	_In_opt_ LPCWSTR pszProviderName,
	_In_    DWORD   dwFlags)
{
	SECURITY_STATUS status = NTE_INTERNAL_ERROR;
	DKEY_KSP_PROVIDER *pProvider = NULL;
    CK_SESSION_HANDLE hSession = 0;
	DWORD cbLength = 0;
	size_t cbProviderName = 0;
    CK_RV pk11_result;
	UNREFERENCED_PARAMETER(dwFlags);

	// Validate input parameters.
	if (phProvider == NULL)
	{
		status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}
	if (pszProviderName == NULL)
	{
		status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}

	// check for a valid provider name
	if (wcscmp(pszProviderName, DKEY_KSP_PROVIDER_NAME) != 0)
	{
		status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}

    *phProvider = NULL;

	// Allocate memory for provider object.
	cbLength = sizeof(DKEY_KSP_PROVIDER);
	pProvider = (DKEY_KSP_PROVIDER*)HeapAlloc(GetProcessHeap(), 0, cbLength);;
	if (NULL == pProvider)
	{
		status = NTE_NO_MEMORY;
		goto cleanup;
	}

	//Assign values to fields of the provider handle.
	pProvider->cbLength = cbLength;
	pProvider->dwMagic = DKEY_KSP_PROVIDER_MAGIC;
	pProvider->dwFlags = 0;
	pProvider->pszContext = NULL;
	pProvider->hal_user = HAL_USER_NORMAL;
    pProvider->client = hal_client_handle_t { 0 }; // this is always 0
    pProvider->session = hal_session_handle_t { 0 };

    // connect to the HSM
    if (g_bConnectionOpen == FALSE)
    {
        status = ConnectToHSM(pProvider->client);
        if (status != ERROR_SUCCESS)
        {
            goto cleanup;
        }
        else
        {
            g_bConnectionOpen = TRUE;
        }
    }

    pk11_result = C_OpenSession(0, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
    if (pk11_result != CKR_OK)
    {
        status = NTE_INTERNAL_ERROR;
        goto cleanup;
    }
    pProvider->session.handle = (uint32_t)hSession;

    char pin_buffer[256];
    DKEYKspGetUserPin(pin_buffer, sizeof(pin_buffer) / sizeof(char));

    pk11_result = C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)pin_buffer, strlen(pin_buffer));
    if (pk11_result != CKR_OK && pk11_result != CKR_USER_ALREADY_LOGGED_IN)
    {
        status = NTE_INTERNAL_ERROR;
        goto cleanup;
    }

	//Assign the output value.
	*phProvider = (NCRYPT_PROV_HANDLE)pProvider;
	pProvider = NULL;
	status = ERROR_SUCCESS;

    ++g_dwNumOpenProviders;

cleanup:
	if (pProvider)
	{
		HeapFree(GetProcessHeap(), 0, pProvider);
	}
    if (status != ERROR_SUCCESS)
    {
        if (hSession != 0)
        {
            C_CloseSession(hSession);
        }

        if (g_bConnectionOpen == TRUE &&
            g_dwNumOpenProviders == 0)
        {
            // we had an error there shouldn't be any open providers
            CloseConnectionToHSM();

            g_bConnectionOpen = FALSE;
        }
    }
	return status;
}

// Opens an existing key.It is implemented by your key storage provider(KSP) and called by the NCryptOpenKey function.
// Parameters
// hProvider[in] - The handle of the key storage provider.
//
// phKey[out] - A pointer to an NCRYPT_KEY_HANDLE variable that receives the key handle.
//
// pszKeyName[in] - A pointer to a null - terminated Unicode string that contains the name of the key to retrieve.This name is not case sensitive.
//
// dwLegacyKeySpec[in] - A legacy identifier that specifies the type of key.This can be one of the following values.
//                       Value            Meaning
//                       AT_KEYEXCHANGE   The key is a key exchange key.
//                       AT_SIGNATURE     The key is a signature key.
//                       0                The key is none of the above types.
//
// dwFlags[in] - A set of flags that modify the behavior of this function.This can be zero or a combination of one
//               or more of the following values.
//               Value                    Meaning
//               NCRYPT_MACHINE_KEY_FLAG  Open the key for the local computer. If this flag is not present, the current user key is opened.
//               NCRYPT_SILENT_FLAG       Do not display any user interface. This flag may not be suitable for all key types.
//
//
// Return value
// Your implementation of this function in a CNG key storage provider(KSP) must return ERROR_SUCCESS if the function succeeds.
// Return NTE_UI_REQUIRED if a user interface must be displayed. Otherwise, return an error code. All status codes are logged
// then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS    The function was successful.
// NTE_UI_REQUIRED  Indicates that a user interface must be displayed in the client
//                  application process. For more information, see Remarks.
//
// Note:  If the calling application sets the dwFlags parameter to NCRYPT_SILENT_FLAG but your KSP requires
//        that a user interface be displayed, the router fails and returns NTE_SILENT_CONTEXT to the caller.
//
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI OpenKey(
	_In_    NCRYPT_PROV_HANDLE hProvider,
	_Out_   NCRYPT_KEY_HANDLE *phKey,
	_In_    LPCWSTR pszKeyName,
	_In_opt_ DWORD  dwLegacyKeySpec,
	_In_    DWORD   dwFlags)
{
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    DKEY_KSP_PROVIDER *pProvider = NULL;
    DKEY_KSP_KEY *pKey = NULL;
    DWORD cbObject = 0;
    unsigned int state = 0;
    unsigned int result_len = 0;
    hal_error_t result = HAL_OK;
    PVOID pCurrent;

    hal_uuid_t uuid_none, uuid_list[2];
    ZeroMemory(&uuid_none, sizeof(hal_uuid_t));

    //
    // Validate input parameters.
    //
    UNREFERENCED_PARAMETER(dwLegacyKeySpec);
    UNREFERENCED_PARAMETER(dwFlags);

    pProvider = DKEYKspValidateProvHandle(hProvider);

    if (pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if ((phKey == NULL) || (pszKeyName == NULL))
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    *phKey = NULL;

    // create, give extra space for alg type and name
    cbObject = sizeof(DKEY_KSP_KEY) + (sizeof(pszKeyName)+32) * sizeof(WCHAR);
    pKey = (DKEY_KSP_KEY *)HeapAlloc(GetProcessHeap(), 0, cbObject);
    if (pKey == NULL)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }
    ZeroMemory(pKey, cbObject);

    pKey->cbLength = cbObject;
    pKey->dwMagic = DKEY_KSP_KEY_MAGIC;
    pKey->phProvider = pProvider;

    pCurrent = (PVOID)(pKey + 1);
    CopyMemory(pCurrent, pszKeyName, (wcslen(pszKeyName) + 1) * sizeof(WCHAR));
    pKey->pszKeyName = (LPWSTR)pCurrent;
    pCurrent = ((PBYTE)pCurrent) + (wcslen(pszKeyName) + 1) * sizeof(WCHAR);

    // find key by name, must convert for HAL
    hal_pkey_attribute_t attr_name;
    attr_name.type = CKA_LABEL;
    char name_buffer[1024];
    size_t num_converted;
    wcstombs_s(&num_converted, name_buffer, pszKeyName, sizeof(name_buffer));
    if (num_converted != wcslen(pszKeyName)+1)
    {
        Status = NTE_BUFFER_TOO_SMALL;
        goto cleanup;
    }
    attr_name.value = name_buffer;
    attr_name.length = strlen(name_buffer);

    result = hal_rpc_pkey_match(pProvider->client, pProvider->session,
        HAL_KEY_TYPE_NONE, HAL_CURVE_NONE,
        0,
        0,
        &attr_name, 1, &state, uuid_list, &result_len,
        sizeof(uuid_list) / sizeof(hal_uuid_t), &uuid_none);

    if (result != HAL_OK ||
        result_len != 2)
    {
        Status = NTE_NOT_FOUND;
        goto cleanup;
    }

    for (int i = 0; i < result_len; ++i)
    {
        hal_pkey_handle_t handle;
        hal_key_type_t key_type = HAL_KEY_TYPE_NONE;
        hal_curve_name_t key_curve = HAL_CURVE_NONE;
        result = hal_rpc_pkey_open(pProvider->client, pProvider->session, &handle, &uuid_list[i]);
        if (result != HAL_OK)
        {
            Status = NTE_INTERNAL_ERROR;
            goto cleanup;
        }

        hal_rpc_pkey_get_key_type(handle, &key_type);
        if (key_type == HAL_KEY_TYPE_EC_PRIVATE || key_type == HAL_KEY_TYPE_RSA_PRIVATE) pKey->hPrivateKey = handle;
        else if (key_type == HAL_KEY_TYPE_EC_PUBLIC || key_type == HAL_KEY_TYPE_RSA_PUBLIC) pKey->hPublicKey = handle;
        else
        {
            Status = NTE_INTERNAL_ERROR;
            goto cleanup;
        }

        if (key_type == HAL_KEY_TYPE_RSA_PRIVATE)
        {
            CopyMemory(pCurrent, NCRYPT_RSA_ALGORITHM, sizeof(NCRYPT_RSA_ALGORITHM));
            pKey->pszAlgID = (LPWSTR)pCurrent;

            // no mechanism to get RSA key length at this time
            pKey->dwLength = 0;
        }
        else if (key_type == HAL_KEY_TYPE_EC_PRIVATE)
        {
            hal_rpc_pkey_get_key_curve(handle, &key_curve);
            if (key_curve == HAL_CURVE_P256)
            {
                CopyMemory(pCurrent, BCRYPT_ECDSA_P256_ALGORITHM, sizeof(BCRYPT_ECDSA_P256_ALGORITHM));
                pKey->dwLength = 256;
            }
            else if (key_curve == HAL_CURVE_P384)
            {
                CopyMemory(pCurrent, BCRYPT_ECDSA_P384_ALGORITHM, sizeof(BCRYPT_ECDSA_P384_ALGORITHM));
                pKey->dwLength = 384;
            }
            else if (key_curve == HAL_CURVE_P521)
            {
                CopyMemory(pCurrent, BCRYPT_ECDSA_P521_ALGORITHM, sizeof(BCRYPT_ECDSA_P521_ALGORITHM));
                pKey->dwLength = 521;
            }
            else CopyMemory(pCurrent, TEXT("ECDSA"), sizeof(TEXT("ECDSA")));

            pKey->pszAlgID = (LPWSTR)pCurrent;
        }
        else
        {
            CopyMemory(&(pKey->public_uuid), &uuid_list[i], sizeof(hal_uuid_t));
        }
    }

    pKey->bFinalized = TRUE;
    *phKey = (NCRYPT_KEY_HANDLE)pKey;
    pKey = NULL;
    Status = ERROR_SUCCESS;

cleanup:

    if (pKey)
    {
        if (pKey->hPrivateKey.handle != 0) hal_rpc_pkey_close(pKey->hPrivateKey);
        if (pKey->hPublicKey.handle != 0) hal_rpc_pkey_close(pKey->hPublicKey);

        HeapFree(GetProcessHeap(), 0, pKey);
    }

    return Status;
}

// Creates and stores a key.It is implemented by your key storage provider(KSP) and called by the NCryptCreatePersistedKey function.
// Parameters
// hProvider[in] - The handle of the key storage provider to create the key in.
//
// phKey[out] - The address of an NCRYPT_KEY_HANDLE variable that receives the handle of the key.
//              This handle will be passed to the NCryptDeleteKeyFn function when it is no longer needed.
//
// pszAlgId[in] - A pointer to a null-terminated Unicode string that contains the identifier of the cryptographic
//                algorithm to create the key.This can be one of the standard CNG Algorithm Identifiers or the
//                identifier for another registered algorithm.
//
// pszKeyName[in, optional] - A pointer to a null-terminated Unicode string that contains the name of the key.
//                            If this parameter is NULL, this function must create an ephemeral key that is not persisted.
//
// dwLegacyKeySpec[in] - A legacy identifier that specifies the type of key.This can be one of the following values.
//                       Value           Meaning
//                       AT_KEYEXCHANGE  The key is a key exchange key.
//                       AT_SIGNATURE    The key is a signature key.
//                       0               The key is none of the above types.
//
// dwFlags[in] - A set of flags that modify the behavior of this function. This can be zero or a combination of one
//               or more of the following values.
//               Value                      Meaning
//               NCRYPT_MACHINE_KEY_FLAG    The key applies to the local computer.If this flag is not present, the key applies to the current user.
//               NCRYPT_OVERWRITE_KEY_FLAG  If a key already exists in the container with the specified name, the existing key will be overwritten.If this flag is not specified and a key with the specified name already exists, this function will return NTE_EXISTS.
//
// Return value
// Your implementation of this function in a CNG key storage provider(KSP) must return ERROR_SUCCESS if the function succeeds.
// Otherwise, return an error code.All status codes are logged then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI CreatePersistedKey(
	_In_    NCRYPT_PROV_HANDLE hProvider,
	_Out_   NCRYPT_KEY_HANDLE *phKey,
	_In_    LPCWSTR pszAlgId,
	_In_opt_ LPCWSTR pszKeyName,
	_In_    DWORD   dwLegacyKeySpec,
	_In_    DWORD   dwFlags)
{
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    DKEY_KSP_PROVIDER *pProvider = NULL;
    CK_RV result = CKR_OK;
    CK_SESSION_HANDLE hSession = 0;
    char algorithm[32];
    char label[256];
    size_t num_chars_converted;
    CK_ULONG bits;
    CK_ULONG expsize = 0;
    CK_OBJECT_HANDLE hPublicKey = 0;
    CK_OBJECT_HANDLE hPrivateKey = 0;

    pProvider = DKEYKspValidateProvHandle(hProvider);

    //
    // Validate parameters
    //
    if (pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if ((phKey == NULL) || (pszKeyName == NULL))
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    *phKey = NULL;

    hSession = (CK_SESSION_HANDLE)pProvider->session.handle;
    if (hSession == 0)
    {
        Status = NTE_BAD_PROVIDER;
        goto cleanup;
    }

    if (0 != wcstombs_s(&num_chars_converted, algorithm, pszAlgId, sizeof(algorithm) / sizeof(char)))
    {
        Status = NTE_BAD_ALGID;
        goto cleanup;
    }
    
    if (_strnicmp(algorithm, "RSA", strlen("RSA")) == 0)
    {
        size_t alglen = strlen(algorithm);

        // set as the default RSA key len
        bits = DKEYRSAKeyLen();

        // allow key size to be set
        if (alglen > strlen("RSA_"))
        {
            char *size = &algorithm[strlen("RSA_")];
            bits = atoi(size);
            if (bits < 1024 || bits > 4096)
            {
                Status = NTE_BAD_LEN;
                goto cleanup;
            }
        }
    }
    else if (_strnicmp(algorithm, "ECDSA", strlen("ECDSA")) == 0)
    {
        size_t alglen = strlen(algorithm);
        if (alglen == strlen("ECDSA"))
        {
            bits = 256; // default size
        }
        else if (alglen = strlen("ECDSA_P256"))
        {
            if (strcmp(algorithm, "ECDSA_P256") == 0) bits = 256;
            else if (strcmp(algorithm, "ECDSA_P384") == 0) bits = 384;
            else if (strcmp(algorithm, "ECDSA_P521") == 0) bits = 521;
            else bits = 0;
        }
    }

    if (0 != wcstombs_s(&num_chars_converted, label, pszKeyName, sizeof(label) / sizeof(char)))
    {
        Status = NTE_BAD_ALGID;
        goto cleanup;
    }

    // Use PKCS11 to generate the key
    result = DoKeyGen(hSession, algorithm, bits, (CK_CHAR *)label, expsize, &hPublicKey, &hPrivateKey);
    if (result != CKR_OK)
    {
        Status = NTE_INTERNAL_ERROR;
        goto cleanup;
    }

    // open and return the key that we just generated
    return OpenKey(hProvider, phKey, pszKeyName, dwLegacyKeySpec, dwFlags);

cleanup:
    return Status;
}

// Retrieves the value of a named property for a key storage provider. It is implemented by your
// key storage provider (KSP) and called by the NCryptGetProperty function.
// Parameters
// hProvider [in] - The handle of the key storage provider.
//
// pszProperty [in] - A pointer to a null-terminated Unicode string that contains the name of the property to
//                    retrieve. This can be one of the predefined Key Storage Property Identifiers or a custom property identifier.
//
// pbOutput [out] - A pointer to a buffer that receives the property value. The cbOutput parameter contains the size of this buffer.
//                  To calculate the size required for the buffer, set this parameter to NULL. The size, in bytes, required is
//                  returned in the location pointed to by the pcbResult parameter.
//
// cbOutput [in] - The size, in bytes, of the pbOutput buffer.
//
// pcbResult [out] - A pointer to a DWORD variable that receives the number of bytes that were copied to the pbOutput buffer.
//                   If the pbOutput parameter is NULL, the size, in bytes, required for the buffer is placed in the location
//                   pointed to by this parameter.
//
// dwFlags [in] - A set of flags that modify the behavior of this function. No flags are defined for this function.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds.
// Return NTE_UI_REQUIRED if a user interface must be displayed. Otherwise, return an error code. All status codes are logged
// then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_UI_REQUIRED  Indicates that a user interface must be displayed in the client application process. For more information, see Remarks.
//                  Note: If the calling application sets the dwFlags parameter to NCRYPT_SILENT_FLAG but your KSP requires
//                        that a user interface be displayed, the router fails and returns NTE_SILENT_CONTEXT to the caller.
//
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI GetProviderProperty(
	_In_    NCRYPT_PROV_HANDLE hProvider,
	_In_    LPCWSTR pszProperty,
	_Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
	_In_    DWORD   cbOutput,
	_Out_   DWORD * pcbResult,
	_In_    DWORD   dwFlags)
{
	return NTE_NOT_SUPPORTED;
}

// Retrieves the value of a named property for a key. It is implemented by your key storage provider (KSP) and called by the NCryptGetProperty function.
// Parameters
// hProvider [in] - The handle of the key storage provider that contains the key.
//
// hKey [in] - The handle of the key.
//
// pszProperty [in] - A pointer to a null-terminated Unicode string that contains the name of the property to retrieve. This can be one of the
//                    predefined Key Storage Property Identifiers or a custom property identifier.
//
// pbOutput [out] - The address of a buffer that receives the property value. The cbOutput parameter contains the size of this buffer.
//                  To calculate the size required for the buffer, set this parameter to NULL. The size, in bytes, required is returned
//                  in the location pointed to by the pcbResult parameter.
//
// cbOutput [in] - The size, in bytes, of the pbOutput buffer.
//
// pcbResult [out] - A pointer to a DWORD variable that receives the number of bytes that were copied to the pbOutput buffer.
//                   If the pbOutput parameter is NULL, the size, in bytes, required for the buffer is placed in the location
//                   pointed to by this parameter.
//
// dwFlags [in] - A set of flags that modify the behavior of this function. No flags are defined for this function.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds.
// Return NTE_UI_REQUIRED if a user interface must be displayed. Otherwise, return an error code. All status codes are logged
// then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_UI_REQUIRED  Indicates that a user interface must be displayed in the client application process. For more information, see Remarks.
//                  Note  If the calling application sets the dwFlags parameter to NCRYPT_SILENT_FLAG but your KSP requires that a user
//                  interface be displayed, the router fails and returns NTE_SILENT_CONTEXT to the caller.
//
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI GetKeyProperty(
	_In_    NCRYPT_PROV_HANDLE hProvider,
	_In_    NCRYPT_KEY_HANDLE hKey,
	_In_    LPCWSTR pszProperty,
	_Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
	_In_    DWORD   cbOutput,
	_Out_   DWORD * pcbResult,
	_In_    DWORD   dwFlags)
{
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    DKEY_KSP_PROVIDER *pProvider = NULL;
    DKEY_KSP_KEY *pKey = NULL;

    // maximum output temp buffer
    BYTE bOutBuffer[1024];
    DWORD cbResult = 0;
    char uuid_buffer[40];

    //
    // Validate input parameters.
    //
    pProvider = DKEYKspValidateProvHandle(hProvider);

    if (pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    pKey = DKEYKspValidateKeyHandle(hKey);

    if (pKey == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if ((pszProperty == NULL) ||
        (wcslen(pszProperty) > NCRYPT_MAX_PROPERTY_NAME) ||
        (pcbResult == NULL))
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    //NCRYPT_SILENT_FLAG is ignored in KSP.
    dwFlags &= ~NCRYPT_SILENT_FLAG;

    //If this is to get the security descriptor, the flags
    //must be one of the OWNER_SECURITY_INFORMATION |GROUP_SECURITY_INFORMATION |
    //DACL_SECURITY_INFORMATION|LABEL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION.
    if (wcscmp(pszProperty, NCRYPT_SECURITY_DESCR_PROPERTY) == 0)
    {

        if ((dwFlags == 0) || ((dwFlags & ~(OWNER_SECURITY_INFORMATION |
            GROUP_SECURITY_INFORMATION |
            DACL_SECURITY_INFORMATION |
            LABEL_SECURITY_INFORMATION |
            SACL_SECURITY_INFORMATION)) != 0))
        {
            Status = NTE_BAD_FLAGS;
            goto cleanup;
        }
    }
    else
    {
        //Otherwise,Only NCRYPT_PERSIST_ONLY_FLAG is a valid flag.
        if (dwFlags & ~NCRYPT_PERSIST_ONLY_FLAG)
        {
            Status = NTE_BAD_FLAGS;
            goto cleanup;
        }
    }

    // Get the property and add it to temporary buffer with the size
    // all properties are stored in the key structure
    if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0)
    {
        cbResult = (wcslen(pKey->pszKeyName) + 1) * sizeof(WCHAR);
        if (cbResult < sizeof(bOutBuffer))
            CopyMemory(&bOutBuffer[0], pKey->pszKeyName, cbResult);
        else
        {
            // error
            Status = NTE_BAD_LEN;
            goto cleanup;
        }
    }
    else if (wcscmp(pszProperty, NCRYPT_UNIQUE_NAME_PROPERTY) == 0)
    {
        LPWSTR uuid_wchar = (LPWSTR)&bOutBuffer[0];
        size_t uuid_wchar_max = sizeof(bOutBuffer) / sizeof(WCHAR);
        size_t num_converted;
        uuid_to_string(pKey->public_uuid, uuid_buffer, sizeof(uuid_buffer));

        mbstowcs_s(&num_converted, uuid_wchar, uuid_wchar_max, uuid_buffer, uuid_wchar_max);
        cbResult = (wcslen(uuid_wchar)+1) * sizeof(WCHAR);
    }
    else if (wcscmp(pszProperty, NCRYPT_ALGORITHM_PROPERTY) == 0)
    {
        cbResult = (wcslen(pKey->pszAlgID) + 1) * sizeof(WCHAR);
        CopyMemory(&bOutBuffer[0], pKey->pszAlgID, cbResult);
    }
    else if (wcscmp(pszProperty, NCRYPT_ALGORITHM_GROUP_PROPERTY) == 0)
    {
        if (wcsncmp(pKey->pszAlgID, NCRYPT_ECDSA_ALGORITHM_GROUP, wcslen(NCRYPT_ECDSA_ALGORITHM_GROUP)) == 0)
        {
            cbResult = sizeof(NCRYPT_ECDSA_ALGORITHM_GROUP);
            CopyMemory(&bOutBuffer[0], NCRYPT_ECDSA_ALGORITHM_GROUP, cbResult);
        }
        else if (wcsncmp(pKey->pszAlgID, NCRYPT_RSA_ALGORITHM_GROUP, wcslen(NCRYPT_RSA_ALGORITHM_GROUP)) == 0)
        {
            cbResult = sizeof(NCRYPT_RSA_ALGORITHM_GROUP);
            CopyMemory(&bOutBuffer[0], NCRYPT_RSA_ALGORITHM_GROUP, cbResult);
        }
        else
        {
            // error
            Status = NTE_BAD_TYPE;
            goto cleanup;
        }
    }
    else if (wcscmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0)
    {
        if (pKey->dwLength > 0)
        {
            cbResult = sizeof(DWORD);
            CopyMemory(&bOutBuffer[0], &(pKey->dwLength), cbResult);
        }
        else
        {
            // error
            Status = NTE_NOT_SUPPORTED;
            goto cleanup;
        }
    }
    else if (wcscmp(pszProperty, NCRYPT_EXPORT_POLICY_PROPERTY) == 0)
    {
        // exporting not allowed
        DWORD export_policy = 0;
        cbResult = sizeof(DWORD);
        CopyMemory(&bOutBuffer[0], &export_policy, cbResult);
    }
    else if (wcscmp(pszProperty, NCRYPT_IMPL_TYPE_PROPERTY) == 0)
    {
        // this is a hardware HSM
        DWORD impl_type_policy = NCRYPT_IMPL_HARDWARE_FLAG;
        cbResult = sizeof(DWORD);
        CopyMemory(&bOutBuffer[0], &impl_type_policy, cbResult);
    }
    else if (wcscmp(pszProperty, NCRYPT_KEY_USAGE_PROPERTY) == 0)
    {
        // only signing is allowed
        DWORD key_usage_policy = NCRYPT_ALLOW_SIGNING_FLAG;
        cbResult = sizeof(DWORD);
        CopyMemory(&bOutBuffer[0], &key_usage_policy, cbResult);
    }
    else if (wcscmp(pszProperty, NCRYPT_KEY_TYPE_PROPERTY) == 0)
    {
        // keys are availble to all users
        DWORD key_type_policy = NCRYPT_MACHINE_KEY_FLAG;
        cbResult = sizeof(DWORD);
        CopyMemory(&bOutBuffer[0], &key_type_policy, cbResult);
    }
    else if (wcscmp(pszProperty, NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY) == 0)
    {
        // HSM doesn't support security descriptor on keys
        DWORD sec_support_policy = 0;
        cbResult = sizeof(DWORD);
        CopyMemory(&bOutBuffer[0], &sec_support_policy, cbResult);
    }
    else
    {
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }


    //
    // Validate the size of the output buffer.
    //
    *pcbResult = cbResult;

    if (pbOutput == NULL)
    {
        Status = ERROR_SUCCESS;
        goto cleanup;
    }

    if (cbOutput < *pcbResult)
    {
        Status = NTE_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    //
    // Retrieve the requested property data.
    //
    CopyMemory(pbOutput, &bOutBuffer[0], cbResult);

    Status = ERROR_SUCCESS;

cleanup:
    return Status;
}

// Sets a property value for the provider. It is implemented by your key storage provider (KSP)
// and called by the NCryptSetProperty function.
//
// Parameters
// hProvider [in] - The handle of the key storage provider.
//
// pszProperty [in] - A pointer to a null-terminated Unicode string that contains the name of the property to set.
//                    This can be one of the predefined Key Storage Property Identifiers that applies to a provider
//                    or a custom property identifier.
//
// pbInput [in] - The address of a buffer that contains the new property value. The cbInput parameter contains the size of this buffer.
//
// cbInput [in] -The size, in bytes, of the pbInput buffer.
//
// dwFlags [in] - A set of flags that modify the behavior of this function. This can be zero or a combination of one or more of
//                the following values.
//                Value                     Meaning
//                NCRYPT_PERSIST_ONLY_FLAG  The property should be stored for retrieval at a later time.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds.
// Return NTE_UI_REQUIRED if a user interface must be displayed. Otherwise, return an error code. All status codes are logged
// then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
//
// NTE_UI_REQUIRED  Indicates that a user interface must be displayed in the client application process. For more information, see Remarks.
//                  Note  If the calling application sets the dwFlags parameter to NCRYPT_SILENT_FLAG but your KSP requires that a user interface be displayed, the router fails and returns NTE_SILENT_CONTEXT to the caller.
//
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI SetProviderProperty(
	_In_    NCRYPT_PROV_HANDLE hProvider,
	_In_    LPCWSTR pszProperty,
	_In_reads_bytes_(cbInput) PBYTE pbInput,
	_In_    DWORD   cbInput,
	_In_    DWORD   dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

// Sets a property value for a CNG key storage key. It is implemented by your key storage provider (KSP) and called by
// the NCryptSetProperty function.
// Parameters
// hProvider [in] - The handle of the key storage provider.
//
// hKey [in] - The handle of the key.
//
// pszProperty [in] - A pointer to a null-terminated Unicode string that contains the name of the property to set.
//                    This can be one of the predefined Key Storage Property Identifiers that applies to a key or
//                    a custom property identifier.
//
// pbInput [in] - The address of a buffer that contains the new property value. The cbInput parameter contains the
//                size of this buffer.
//
// cbInput [in] - The size, in bytes, of the pbInput buffer.
//
// dwFlags [in] - A set of flags that modify the behavior of this function. This can be zero or a combination of one
//                or more of the following values.
//                Value                Meaning
//                NCRYPT_PERSIST_FLAG  The property should be stored in key storage along with the key material.
//                NCRYPT_PERSIST_ONLY_FLAG  The property should be stored for retrieval at a later time. The property may or may not be stored in key storage.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function
// succeeds. Return NTE_UI_REQUIRED if a user interface must be displayed. Otherwise, return an error code. All status
// codes are logged then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_UI_REQUIRED  Indicates that a user interface must be displayed in the client application process. For more information, see Remarks.
//                  Note: If the calling application sets the dwFlags parameter to NCRYPT_SILENT_FLAG but your KSP requires that a
//                        user interface be displayed, the router fails and returns NTE_SILENT_CONTEXT to the caller.
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI SetKeyProperty(
	_In_    NCRYPT_PROV_HANDLE hProvider,
	_In_    NCRYPT_KEY_HANDLE hKey,
	_In_    LPCWSTR pszProperty,
	_In_reads_bytes_(cbInput) PBYTE pbInput,
	_In_    DWORD   cbInput,
	_In_    DWORD   dwFlags)
{
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    DKEY_KSP_PROVIDER *pProvider = NULL;
    DKEY_KSP_KEY *pKey = NULL;

    //
    // Validate input parameters.
    //
    pProvider = DKEYKspValidateProvHandle(hProvider);

    if (pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    pKey = DKEYKspValidateKeyHandle(hKey);

    if (pKey == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if ((pszProperty == NULL) ||
        (wcslen(pszProperty) > NCRYPT_MAX_PROPERTY_NAME))
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    // Get the property and add it to temporary buffer with the size
    // all properties are stored in the key structure
    if ((wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0) ||
        (wcscmp(pszProperty, NCRYPT_UNIQUE_NAME_PROPERTY) == 0) ||
        (wcscmp(pszProperty, NCRYPT_ALGORITHM_PROPERTY) == 0) ||
        (wcscmp(pszProperty, NCRYPT_ALGORITHM_GROUP_PROPERTY) == 0) ||
        (wcscmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0) ||
        (wcscmp(pszProperty, NCRYPT_EXPORT_POLICY_PROPERTY) == 0) ||
        (wcscmp(pszProperty, NCRYPT_IMPL_TYPE_PROPERTY) == 0) ||
        (wcscmp(pszProperty, NCRYPT_KEY_USAGE_PROPERTY) == 0) ||
        (wcscmp(pszProperty, NCRYPT_KEY_TYPE_PROPERTY) == 0) ||
        (wcscmp(pszProperty, NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY) == 0))
    {
        Status = NTE_FIXEDPARAMETER;
    }
    else
    {
        Status = NTE_NOT_SUPPORTED;
    }

cleanup:
    return Status;
}

// Completes a CNG key storage key. It is implemented by your key storage provider (KSP) and called by the NCryptFinalizeKey function.
// Parameters
// hProvider [in] - The handle of the key storage provider.
//
// hKey [in] - The handle of the key to complete. This handle is obtained by using the NCryptCreatePersistedKeyFn function.
//
// dwFlags [in] - A set of flags that modify the behavior of this function. This can be zero or a combination of one or more of the following values.
//               Value                                  Meaning
//               NCRYPT_NO_KEY_VALIDATION               Do not validate the public portion of the key pair. This flag only applies to public/private key pairs.
//               NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG  Also save the key in legacy storage. This allows the key to be used with the CryptoAPI. This flag only applies to RSA keys.
//               NCRYPT_SILENT_FLAG                     The application requests that the provider not display any user interface. If the provider must display the UI to operate, the call fails and the NTE_SILENT_CONTEXT error code is set as the last error.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds. Return NTE_UI_REQUIRED if a user interface must be displayed. Otherwise, return an error code. All status codes are logged then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_UI_REQUIRED  Indicates that a user interface must be displayed in the client application process. For more information, see Remarks.
//                  Note: If the calling application sets the dwFlags parameter to NCRYPT_SILENT_FLAG but your KSP requires that a user
//                        interface be displayed, the router fails and returns NTE_SILENT_CONTEXT to the caller.
//
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI FinalizeKey(
    _In_    NCRYPT_PROV_HANDLE hProvider,
    _In_    NCRYPT_KEY_HANDLE hKey,
    _In_    DWORD   dwFlags)
{
    SECURITY_STATUS Status = ERROR_SUCCESS;
    DKEY_KSP_PROVIDER *pProvider;
    DKEY_KSP_KEY *pKey = NULL;

    // Validate input parameters.
    pProvider = DKEYKspValidateProvHandle(hProvider);

    if (pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    pKey = DKEYKspValidateKeyHandle(hKey);

    if (pKey == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if (pKey->phProvider != pProvider)
    {
        Status = NTE_BAD_PROVIDER;
        goto cleanup;
    }

    if (((dwFlags & NCRYPT_NO_KEY_VALIDATION) != 0) ||
        ((dwFlags & NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG) != 0))
    {
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }

    // can't finalize twice
    if (pKey->bFinalized == TRUE)
    {
        Status = NTE_FIXEDPARAMETER;
        goto cleanup;
    }

    pKey->bFinalized = TRUE;

cleanup:

    return Status;
}

// Deletes a cyptographic key. It is implemented by your key storage provider (KSP) and called by the NCryptDeleteKey function.
//
// Parameters
// hProvider [in] - The handle of the key storage provider to create the key in. This handle is obtained by using the NCryptOpenStorageProvider function.
//
// hKey [in] - The handle of the key to delete. This handle is obtained with the NCryptOpenKeyFn function.
//
// dwFlags [in] - The following flag can be specified.
//                Value               Meaning
//                NCRYPT_SILENT_FLAG  The application requests that the provider not display any user interface.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds.
// Return NTE_UI_REQUIRED if a user interface must be displayed. Otherwise, return an error code. All status codes are logged
// then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_UI_REQUIRED  Indicates that a user interface must be displayed in the client application process. For more information, see Remarks.
//                  Note: If the calling application sets the dwFlags parameter to NCRYPT_SILENT_FLAG but your KSP requires that a user
//                        interface be displayed, the router fails and returns NTE_SILENT_CONTEXT to the caller.
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI DeleteKey(
	_In_    NCRYPT_PROV_HANDLE hProvider,
	_In_    NCRYPT_KEY_HANDLE hKey,
	_In_    DWORD   dwFlags)
{
    SECURITY_STATUS Status = ERROR_SUCCESS;
    DKEY_KSP_PROVIDER *pProvider;
    DKEY_KSP_KEY *pKey = NULL;

    // Validate input parameters.
    pProvider = DKEYKspValidateProvHandle(hProvider);

    if (pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    pKey = DKEYKspValidateKeyHandle(hKey);

    if (pKey == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if (pKey->phProvider != pProvider)
    {
        Status = NTE_BAD_PROVIDER;
        goto cleanup;
    }

    // delete the key
    hal_rpc_pkey_delete(pKey->hPrivateKey);
    hal_rpc_pkey_delete(pKey->hPublicKey);

    HeapFree(GetProcessHeap(), 0, pKey);

cleanup:

    return Status;
}

// Frees a provider handle created by the provider. It is implemented by your key storage provider (KSP) and called by
// the NCryptFreeObject function.
// Parameters
// hProvider [in] - The handle of the provider to free.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds.
// Otherwise, return an error code. All status codes are logged then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI FreeProvider(
	_In_    NCRYPT_PROV_HANDLE hProvider)
{
	SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
	DKEY_KSP_PROVIDER *pProvider = NULL;

	// Validate input parameters.
	pProvider = DKEYKspValidateProvHandle(hProvider);

	if (pProvider == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

    C_CloseSession((CK_SESSION_HANDLE)pProvider->session.handle);

    // reduce the number of providers
    --g_dwNumOpenProviders;

    if (g_bConnectionOpen == TRUE &&
        g_dwNumOpenProviders == 0)
    {
        // we had an error there shouldn't be any open providers
        CloseConnectionToHSM();

        g_bConnectionOpen = FALSE;
    }

	// Free context.
	if (pProvider->pszContext)
	{
		HeapFree(GetProcessHeap(), 0, pProvider->pszContext);
		pProvider->pszContext = NULL;
	}

	ZeroMemory(pProvider, pProvider->cbLength);
	HeapFree(GetProcessHeap(), 0, pProvider);

	Status = ERROR_SUCCESS;
cleanup:

	return Status;
}

// Frees an object handle created by the provider. It is implemented by your key storage provider (KSP) and called by the NCryptFreeObject function.
// Parameters
// hProvider [in] - The handle of the provider.
//
// hKey [in] - The handle of the key to free.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds.
// Otherwise, return an error code. All status codes are logged then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI FreeKey(
	_In_    NCRYPT_PROV_HANDLE hProvider,
	_In_    NCRYPT_KEY_HANDLE hKey)
{
    SECURITY_STATUS Status = ERROR_SUCCESS;
    DKEY_KSP_PROVIDER *pProvider;
    DKEY_KSP_KEY *pKey = NULL;

    // Validate input parameters.
    pProvider = DKEYKspValidateProvHandle(hProvider);

    if (pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    pKey = DKEYKspValidateKeyHandle(hKey);

    if (pKey == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if (pKey->phProvider != pProvider)
    {
        Status = NTE_BAD_PROVIDER;
        goto cleanup;
    }

    //
    // Free key object.
    //
    if (pKey)
    {
        if (pKey->hPrivateKey.handle != 0) hal_rpc_pkey_close(pKey->hPrivateKey);
        if (pKey->hPublicKey.handle != 0) hal_rpc_pkey_close(pKey->hPublicKey);

        HeapFree(GetProcessHeap(), 0, pKey);
    }

cleanup:

    return Status;
}

// Releases a block of memory allocated by the provider. It is implemented by your key storage provider (KSP) and called by
// the NCryptFreeBuffer function.
// Parameters
// pvInput [in] - The address of the memory to be released.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds.
// Otherwise, return an error code. All status codes are logged then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI FreeBuffer(
	_Pre_notnull_ PVOID   pvInput)
{
    if (NULL == pvInput)
    {
        return NTE_INVALID_PARAMETER;
    }
    //
    // Free the buffer from the heap.
    //

    HeapFree(GetProcessHeap(), 0, pvInput);

cleanup:

    return ERROR_SUCCESS;
}

// Encrypts a block of data. It is implemented by your key storage provider (KSP) and called by the NCryptEncrypt function.
// Parameters
// hProvider [in] - The handle of the key storage provider.
//
// hKey [in] - The handle of the key to use to encrypt the data.
//
// pbInput [in] - The address of a buffer that contains the data to be encrypted. The cbInput parameter contains the size of the
//                data to encrypt. For more information, see Remarks.
//
// cbInput [in] - The number of bytes in the pbInput buffer to encrypt.
//
// pPaddingInfo [in, optional] - A pointer to a structure that contains padding information. The actual type of structure this
//                               parameter points to depends on the value of the dwFlags parameter. This parameter is only used
//                               with asymmetric keys and must be NULL otherwise.
//
// pbOutput [out] - The address of a buffer to receive the encrypted data produced by this function. The cbOutput parameter
//                  contains the size of this buffer. For more information, see Remarks.
//                  If this parameter is NULL, this function must calculate the size needed for the encrypted data and return
//                  the size in the location pointed to by the pcbResult parameter.
//
// cbOutput [in] -  The size, in bytes, of the pbOutput buffer. This parameter is ignored if the pbOutput parameter is NULL.
//
// pcbResult [out] - A pointer to a DWORD variable that receives the number of bytes copied to the pbOutput buffer.
//                   If pbOutput is NULL, this receives the size, in bytes, required for the ciphertext.
//
// dwFlags [in] - A set of flags that modify the behavior of this function. The allowed set of flags depends on the type
//                of key specified by the hKey parameter.
//                If the key is an asymmetric key, this can be one of the following values.
//                Value                   Meaning
//                NCRYPT_NO_PADDING_FLAG  Do not use any padding. The pPaddingInfo parameter is not used. The size of the plaintext
//                                        specified in the cbInput parameter must be a multiple of the block size of the algorithm.
//                NCRYPT_PAD_OAEP_FLAG    Use the Optimal Asymmetric Encryption Padding (OAEP) scheme. The pPaddingInfo parameter
//                                        is a pointer to a BCRYPT_OAEP_PADDING_INFO structure.
//                NCRYPT_PAD_PKCS1_FLAG   The data will be padded with a random number to round out the block size. The pPaddingInfo
//                                        parameter is not used.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds.
// Return NTE_UI_REQUIRED if a user interface must be displayed. Otherwise, return an error code. All status codes are logged
// then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_UI_REQUIRED Indicates that a user interface must be displayed in the client application process. For more information, see Remarks.
//                 Note: If the calling application sets the dwFlags parameter to NCRYPT_SILENT_FLAG but your KSP requires that a user interface be displayed, the router fails and returns NTE_SILENT_CONTEXT to the caller.
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI Encrypt(
	_In_    NCRYPT_PROV_HANDLE hProvider,
	_In_    NCRYPT_KEY_HANDLE hKey,
	_In_reads_bytes_opt_(cbInput) PBYTE pbInput,
	_In_    DWORD   cbInput,
	_In_opt_    VOID *pPaddingInfo,
	_Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
	_In_    DWORD   cbOutput,
	_Out_   DWORD * pcbResult,
	_In_    DWORD   dwFlags)
{
	return NTE_NOT_SUPPORTED;
}

// Decrypts a block of encrypted data. It is implemented by your key storage provider (KSP) and called by the NCryptDecrypt function.
// Parameters
// hProvider [in] - The handle of the key storage provider.
//
// hKey [in] - The handle of the key to use to decrypt the data.
//
// pbInput [in] - The address of a buffer that contains the data to be decrypted. The cbInput parameter contains the size of the data to decrypt. For more information, see Remarks.
//
// cbInput [in] - The number of bytes in the pbInput buffer to decrypt.
//
// pPaddingInfo [in, optional] - A pointer to a structure that contains padding information. The actual type of structure this parameter points to depends on the
//                               value of the dwFlags parameter. This parameter is only used with asymmetric keys and must be NULL otherwise.
//
// pbOutput [out] - The address of a buffer that will receive the decrypted data produced by this function. The cbOutput parameter contains
//                  the size of this buffer.
//                  If this parameter is NULL, this function will calculate the size needed for the decrypted data and return the size in the
//                  location pointed to by the pcbResult parameter.
//
// cbOutput [in] - The size, in bytes, of the pbOutput buffer. This parameter is ignored if the pbOutput parameter is NULL.
//
// pcbResult [out] - A pointer to a DWORD variable that receives the number of bytes copied to the pbOutput buffer. If pbOutput is NULL, this receives the size, in bytes, required for the decrypted data.
//
// dwFlags [in] - A set of flags that modify the behavior of this function. The allowed set of flags depends on the type of key specified by the hKey parameter.
//                If the key is an asymmetric key, this can be one of the following values.
//                Value                   Meaning
//                NCRYPT_NO_PADDING_FLAG  No padding was used when the data was encrypted. The pPaddingInfo parameter is not used.
//                NCRYPT_PAD_OAEP_FLAG    The Optimal Asymmetric Encryption Padding (OAEP) scheme was used when the data was encrypted. The pPaddingInfo parameter is a pointer to a BCRYPT_OAEP_PADDING_INFO structure.
//                NCRYPT_PAD_PKCS1_FLAG   The data was padded with a random number to round out the block size when the data was encrypted. The pPaddingInfo parameter is not used.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds. Return NTE_UI_REQUIRED if a user interface must be displayed. Otherwise, return an error code. All status codes are logged then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_UI_REQUIRED  Indicates that a user interface must be displayed in the client application process. For more information, see Remarks.
//                  Note: If the calling application sets the dwFlags parameter to NCRYPT_SILENT_FLAG but your KSP requires that a
//                        user interface be displayed, the router fails and returns NTE_SILENT_CONTEXT to the caller.
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI Decrypt(
	_In_    NCRYPT_PROV_HANDLE hProvider,
	_In_    NCRYPT_KEY_HANDLE hKey,
	_In_reads_bytes_opt_(cbInput) PBYTE pbInput,
	_In_    DWORD   cbInput,
	_In_opt_    VOID *pPaddingInfo,
	_Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
	_In_    DWORD   cbOutput,
	_Out_   DWORD * pcbResult,
	_In_    DWORD   dwFlags)
{
	return NTE_NOT_SUPPORTED;
}

// Determines whether the provider supports a specific cryptographic algorithm. It is implemented by your key storage provider (KSP) and called by the NCryptIsAlgSupported function.
// Parameters
// hProvider [in] - The handle of the key storage provider.
//
// pszAlgId [in] - A pointer to a null-terminated Unicode string that identifies the cryptographic algorithm in question. This can be one of the standard CNG Algorithm Identifiers or the identifier for another registered algorithm.
//
// dwFlags [in] - Flags that modify the behavior of the function. These flags are passed directly from the NCryptIsAlgSupported function.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds. Return NTE_UI_REQUIRED if a user interface must be displayed. Otherwise, return an error code. All status codes are logged then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_UI_REQUIRED  Indicates that a user interface must be displayed in the client application process. For more information, see Remarks.
//                  Note  If the calling application sets the dwFlags parameter to NCRYPT_SILENT_FLAG but your KSP requires that a user interface be displayed, the router fails and returns NTE_SILENT_CONTEXT to the caller.
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI IsAlgSupported(
	_In_    NCRYPT_PROV_HANDLE hProvider,
	_In_    LPCWSTR pszAlgId,
	_In_    DWORD   dwFlags)
{
    DKEY_KSP_PROVIDER *pProvider = NULL;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;

    // Validate input parameters.
    pProvider = DKEYKspValidateProvHandle(hProvider);

    if (pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if (pszAlgId == NULL)
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    if ((dwFlags & ~NCRYPT_SILENT_FLAG) != 0)
    {
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }

    if ((wcscmp(pszAlgId, NCRYPT_RSA_ALGORITHM) == 0) ||
        (wcscmp(pszAlgId, NCRYPT_SHA1_ALGORITHM) == 0) ||
        (wcscmp(pszAlgId, NCRYPT_SHA256_ALGORITHM) == 0) ||
        (wcscmp(pszAlgId, NCRYPT_SHA384_ALGORITHM) == 0) ||
        (wcscmp(pszAlgId, NCRYPT_SHA512_ALGORITHM) == 0) ||
        (wcscmp(pszAlgId, NCRYPT_ECDSA_P256_ALGORITHM) == 0) ||
        (wcscmp(pszAlgId, NCRYPT_ECDSA_P384_ALGORITHM) == 0) ||
        (wcscmp(pszAlgId, NCRYPT_ECDSA_P521_ALGORITHM) == 0))
    {
        Status = ERROR_SUCCESS;
    }
    else
    {
        Status = NTE_NOT_SUPPORTED;
    }

cleanup:
    return Status;
}

void addalgtoEnum(NCryptAlgorithmName *&pCurrentAlg, PBYTE &pbCurrent, DWORD dwclass, DWORD dwAlgOperations, const wchar_t *name, size_t name_size)
{
    pCurrentAlg->dwFlags = 0;
    pCurrentAlg->dwClass = dwclass;
    pCurrentAlg->dwAlgOperations = dwAlgOperations;

    pCurrentAlg->pszName = (LPWSTR)pbCurrent;
    CopyMemory(pbCurrent,
        name,
        name_size);
    pbCurrent += name_size;
    ++pCurrentAlg;
}

// Enumerates the names of the algorithms supported by the provider. It is implemented by your key storage provider (KSP) and called by the NCryptEnumAlgorithms function.
// Parameters
// hProvider [in] - The handle of the key storage provider to enumerate the algorithms for.
//
// dwAlgClass [in] - A set of values that determine which algorithm classes to enumerate. This can be a combination of one or more of the following values.
//                   Value Meaning
//                   NCRYPT_CIPHER_OPERATION                 0x00000001  Enumerate the cipher (symmetric encryption) algorithms.
//                   NCRYPT_HASH_OPERATION                   0x00000002  Enumerate the hashing algorithms.
//                   NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION  0x00000004  Enumerate the asymmetric encryption algorithms.
//                   NCRYPT_SECRET_AGREEMENT_OPERATION       0x00000008  Enumerate the secret agreement algorithms.
//                   NCRYPT_SIGNATURE_OPERATION              0x00000010  Enumerate the digital signature algorithms.
//                   NCRYPT_RNG_OPERATION                    0x00000020  Enumerate the random number generator algorithms.
//
// pdwAlgCount [out] - The address of a DWORD that receives the number of elements in the ppAlgList array.
//
// ppAlgList [out] - The address of an NCryptAlgorithmName structure pointer that receives an array of the registered algorithm names. The variable pointed to by the pdwAlgCount parameter receives the number of elements in this array.
//                   When this memory is no longer needed, it will be freed by passing this pointer to the NCryptFreeBufferFn function.
//
// dwFlags [in] - A set of flags that modify the behavior of this function. This can be zero or the following value.
//                Value               Meaning
//                NCRYPT_SILENT_FLAG  Do not display any user interface. This flag may not be suitable for all key types.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds. Return NTE_UI_REQUIRED if a user interface must be displayed. Otherwise, return an error code. All status codes are logged then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_UI_REQUIRED  Indicates that a user interface must be displayed in the client application process. For more information, see Remarks.
//                  Note: If the calling application sets the dwFlags parameter to NCRYPT_SILENT_FLAG but your KSP requires that a user interface be displayed, the router fails and returns NTE_SILENT_CONTEXT to the caller.
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI EnumAlgorithms(
    _In_    NCRYPT_PROV_HANDLE hProvider,
    _In_    DWORD   dwAlgClass,
    _Out_   DWORD * pdwAlgCount,
    _Outptr_result_buffer_(*pdwAlgCount) NCryptAlgorithmName **ppAlgList,
    _In_    DWORD   dwFlags)
{
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    DKEY_KSP_PROVIDER *pProvider = NULL;
    NCryptAlgorithmName *pCurrentAlg = NULL;
    PBYTE pbCurrent = NULL;
    PBYTE pbOutput = NULL;
    DWORD cbOutput = 0;
    DWORD count = 0;

    // Validate input parameters.
    pProvider = DKEYKspValidateProvHandle(hProvider);

    if (pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if (pdwAlgCount == NULL || ppAlgList == NULL)
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    if ((dwFlags & ~NCRYPT_SILENT_FLAG) != 0)
    {
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }

    // Get the size of the data that we need to create
    // NCRYPT_HASH_OPERATION
    if (dwAlgClass == 0 ||
        ((dwAlgClass & NCRYPT_HASH_OPERATION) != 0))
    {
        cbOutput += sizeof(NCryptAlgorithmName) + sizeof(BCRYPT_SHA1_ALGORITHM);
        cbOutput += sizeof(NCryptAlgorithmName) + sizeof(BCRYPT_SHA256_ALGORITHM);
        cbOutput += sizeof(NCryptAlgorithmName) + sizeof(BCRYPT_SHA384_ALGORITHM);
        cbOutput += sizeof(NCryptAlgorithmName) + sizeof(BCRYPT_SHA512_ALGORITHM);
        count += 4;
    }

    // NCRYPT_SIGNATURE_OPERATION
    // NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION
    if (dwAlgClass == 0 ||
        ((dwAlgClass & NCRYPT_SIGNATURE_OPERATION) != 0))
    {
        cbOutput += sizeof(NCryptAlgorithmName) + sizeof(BCRYPT_RSA_ALGORITHM);
        cbOutput += sizeof(NCryptAlgorithmName) + sizeof(BCRYPT_ECDSA_P256_ALGORITHM);
        cbOutput += sizeof(NCryptAlgorithmName) + sizeof(BCRYPT_ECDSA_P384_ALGORITHM);
        cbOutput += sizeof(NCryptAlgorithmName) + sizeof(BCRYPT_ECDSA_P521_ALGORITHM);

        count += 4;
    }

    if (cbOutput == 0)
    {
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }

    //Allocate the output buffer.
    pbOutput = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbOutput);
    if (pbOutput == NULL)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }

    pCurrentAlg = (NCryptAlgorithmName *)pbOutput;
    pbCurrent = pbOutput + (sizeof(NCryptAlgorithmName) * count);

    if (dwAlgClass == 0 ||
        ((dwAlgClass & NCRYPT_HASH_OPERATION) != 0))
    {
        addalgtoEnum(pCurrentAlg, pbCurrent, NCRYPT_HASH_INTERFACE, NCRYPT_HASH_OPERATION, BCRYPT_SHA1_ALGORITHM, sizeof(BCRYPT_SHA1_ALGORITHM));
        addalgtoEnum(pCurrentAlg, pbCurrent, NCRYPT_HASH_INTERFACE, NCRYPT_HASH_OPERATION, BCRYPT_SHA256_ALGORITHM, sizeof(BCRYPT_SHA256_ALGORITHM));
        addalgtoEnum(pCurrentAlg, pbCurrent, NCRYPT_HASH_INTERFACE, NCRYPT_HASH_OPERATION, BCRYPT_SHA384_ALGORITHM, sizeof(BCRYPT_SHA384_ALGORITHM));
        addalgtoEnum(pCurrentAlg, pbCurrent, NCRYPT_HASH_INTERFACE, NCRYPT_HASH_OPERATION, BCRYPT_SHA512_ALGORITHM, sizeof(BCRYPT_SHA512_ALGORITHM));
    }

    // NCRYPT_SIGNATURE_OPERATION
    // NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION
    if (dwAlgClass == 0 ||
        ((dwAlgClass & NCRYPT_SIGNATURE_OPERATION) != 0))
    {
        addalgtoEnum(pCurrentAlg, pbCurrent, NCRYPT_SIGNATURE_INTERFACE, NCRYPT_SIGNATURE_OPERATION,
                     BCRYPT_RSA_ALGORITHM, sizeof(BCRYPT_RSA_ALGORITHM));
        addalgtoEnum(pCurrentAlg, pbCurrent, NCRYPT_SIGNATURE_INTERFACE, NCRYPT_SIGNATURE_OPERATION,
                     BCRYPT_ECDSA_P256_ALGORITHM, sizeof(BCRYPT_ECDSA_P256_ALGORITHM));
        addalgtoEnum(pCurrentAlg, pbCurrent, NCRYPT_SIGNATURE_INTERFACE, NCRYPT_SIGNATURE_OPERATION,
                     BCRYPT_ECDSA_P384_ALGORITHM, sizeof(BCRYPT_ECDSA_P384_ALGORITHM));
        addalgtoEnum(pCurrentAlg, pbCurrent, NCRYPT_SIGNATURE_INTERFACE, NCRYPT_SIGNATURE_OPERATION,
                     BCRYPT_ECDSA_P521_ALGORITHM, sizeof(BCRYPT_ECDSA_P521_ALGORITHM));
    }

    *pdwAlgCount = count;
    *ppAlgList = (NCryptAlgorithmName *)pbOutput;

    Status = ERROR_SUCCESS;

cleanup:

    return Status;
}

#define check_hal_enum_keys(a) if ((a) != HAL_OK) { \
                                   Status = NTE_INTERNAL_ERROR; \
                                   *ppEnumState = pEnumState; \
                                   pEnumState = NULL; \
                                   goto cleanup; \
                               }

// Enumerates the names of the keys supported by the provider. It is implemented by your key storage provider (KSP) and called by the NCryptEnumKeys function.
// Parameters
// hProvider [in] - The handle of the KSP for which the keys are to be enumerated.
//
// pszScope [in, optional] - This parameter is not currently used.
//
// ppKeyName [out] - The address of a pointer to an NCryptKeyName structure that receives the name of the retrieved key. The caller is responsible for freeing this memory by using the NCryptFreeBufferFn function.
//
// ppEnumState [in, out] - The address of a VOID pointer that receives enumeration state information that is used in subsequent calls to this function. This information only has meaning to the key storage provider and is opaque to the caller. The key storage provider can use this information to determine which item is next in the enumeration. If the variable pointed to by this parameter contains NULL, the enumeration is started from the beginning.
//                         When this memory is no longer needed, it will be freed by passing this pointer to the NCryptFreeBufferFn function.
//
// dwFlags [in] - A set of flags that modify the behavior of this function. This can be zero or a combination of one or more of the following values.
//                Value                    Meaning
//                NCRYPT_MACHINE_KEY_FLAG  Enumerate the keys for the local computer. If this flag is not present, the current user keys are enumerated.
//                NCRYPT_SILENT_FLAG       Do not display any user interface. This flag may not be suitable for all key types.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds. Return NTE_UI_REQUIRED if a user interface must be displayed. Otherwise, return an error code. All status codes are logged then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_UI_REQUIRED  Indicates that a user interface must be displayed in the client application process. For more information, see Remarks.
//                  Note: If the calling application sets the dwFlags parameter to NCRYPT_SILENT_FLAG but your KSP requires that a user interface be displayed, the router fails and returns NTE_SILENT_CONTEXT to the caller.
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI EnumKeys(
	_In_    NCRYPT_PROV_HANDLE hProvider,
	_In_opt_ LPCWSTR pszScope,
	_Outptr_ NCryptKeyName **ppKeyName,
	_Inout_ PVOID * ppEnumState,
	_In_    DWORD   dwFlags)
{
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    DKEY_KSP_PROVIDER *pProvider = NULL;
    KeyMatchData *pEnumState = NULL;
    BOOL first_time = FALSE;
    BOOL close_handle = FALSE;
    NCryptKeyName *pKeyName = NULL;
    PBYTE pbCurrent;

    hal_uuid_t found_uuid;
    hal_pkey_handle_t found_handle;
    hal_key_type_t found_type;
    hal_key_flags_t found_flags;
    hal_curve_name_t found_curve;
    WCHAR found_name[1024];
    WCHAR found_alg[256];
    char temp_buf[256];

    uint8_t buffer[1024]; // lazy waste of memory
    DWORD cbOutput;

    // Validate input parameters.
    pProvider = DKEYKspValidateProvHandle(hProvider);

    if (NULL == pProvider)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if(NULL == ppKeyName || NULL == ppEnumState)
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    pEnumState = (KeyMatchData *)*ppEnumState;

    // we're starting a new search
    if (pEnumState == NULL)
    {
        pEnumState = (KeyMatchData*)HeapAlloc(GetProcessHeap(), 0, sizeof(KeyMatchData));
        if (NULL == pEnumState)
        {
            Status = NTE_NO_MEMORY;
            goto cleanup;
        }
        // this is the first time
        first_time = TRUE;

        // make sure the data has been all zeroed out
        ZeroMemory(pEnumState, sizeof(KeyMatchData));
    }

    while (TRUE)
    {
        // we need to search
        if (pEnumState->current_key == pEnumState->num_keys_found)
        {
            hal_uuid_t previous_uuid;

            // find the last key
            if (pEnumState->current_key > 0)
            {
                memcpy(&previous_uuid, &(pEnumState->uuid_list[pEnumState->current_key - 1]), sizeof(hal_uuid_t));
            }
            else
            {
                // there is no first key
                ZeroMemory(&previous_uuid, sizeof(hal_uuid_t));
            }

            // we search key pairs so only search on private keys because a key/pair is one key
            // grab upto 64 keys at a time instead of one at a time
            check_hal_enum_keys(hal_rpc_pkey_match(pProvider->client, pProvider->session,
                HAL_KEY_TYPE_NONE, HAL_CURVE_NONE,
                0,
                0,
                NULL, 0, &(pEnumState->state), pEnumState->uuid_list, &(pEnumState->num_keys_found),
                MAX_CRYPTECH_UUIDS_IN_KEYMATCH, &previous_uuid));

            // we didn't find anything
            if (0 == pEnumState->num_keys_found)
            {
                Status = NTE_NO_MORE_ITEMS;
                *ppEnumState = pEnumState;
                pEnumState = NULL;

                goto cleanup;
            }
            else
            {
                pEnumState->current_key = 0;
            }
        }

        // at this point we have data to return

        // get the uuid that we will return
        memcpy(&found_uuid, &(pEnumState->uuid_list[pEnumState->current_key]), sizeof(hal_uuid_t));

        // save the first uuid to prevent looping
        if (first_time)
        {
            memcpy(&(pEnumState->first_uuid), &found_uuid, sizeof(hal_uuid_t));
        }
        else if (memcmp(&(pEnumState->first_uuid), &found_uuid, sizeof(hal_uuid_t)) == 0)
        {
            // we've looped around. This sometimes happens
            Status = NTE_NO_MORE_ITEMS;
            *ppEnumState = pEnumState;
            pEnumState = NULL;

            goto cleanup;
        }

        // open the key
        check_hal_enum_keys(hal_rpc_pkey_open(pProvider->client,
            pProvider->session,
            &found_handle,
            &found_uuid));

        close_handle = TRUE;

        check_hal_enum_keys(hal_rpc_pkey_get_key_type(found_handle, &found_type));

        if (found_type != HAL_KEY_TYPE_EC_PRIVATE && found_type != HAL_KEY_TYPE_RSA_PRIVATE)
        {
            // only search private keys
            pEnumState->current_key++;

            hal_rpc_pkey_close(found_handle);
            close_handle = FALSE;

            // try again
            continue;
        }
        else if (found_type == HAL_KEY_TYPE_EC_PRIVATE)
        {
            check_hal_enum_keys(hal_rpc_pkey_get_key_curve(found_handle, &found_curve));
        }

        check_hal_enum_keys(hal_rpc_pkey_get_key_flags(found_handle, &found_flags));

        hal_pkey_attribute_t attr_get_name;
        attr_get_name.type = CKA_LABEL;
        check_hal_enum_keys(hal_rpc_pkey_get_attributes(found_handle, &attr_get_name, 1, buffer, sizeof(buffer)));

        if (attr_get_name.length == 0)
        {
            // no name so not compatible with CNG
            pEnumState->current_key++;

            hal_rpc_pkey_close(found_handle);
            close_handle = FALSE;

            // try again
            continue;
        }
        else
        {
            strncpy_s(temp_buf, (char *)attr_get_name.value, attr_get_name.length);
            size_t num_converted;
            mbstowcs_s(&num_converted, found_name, temp_buf, sizeof(found_name) / sizeof(WCHAR));
        }

        hal_rpc_pkey_close(found_handle);
        close_handle = FALSE;

        break;
    }

    if (found_type == HAL_KEY_TYPE_EC_PRIVATE)
    {
        if (found_curve == HAL_CURVE_P256) wcscpy_s(found_alg, NCRYPT_ECDSA_P256_ALGORITHM);
        else if (found_curve == HAL_CURVE_P384) wcscpy_s(found_alg, NCRYPT_ECDSA_P384_ALGORITHM);
        else if (found_curve == HAL_CURVE_P521) wcscpy_s(found_alg, NCRYPT_ECDSA_P521_ALGORITHM);
    }
    else
    {
        wcscpy_s(found_alg, NCRYPT_RSA_ALGORITHM);
    }

    cbOutput = sizeof(NCryptKeyName);
    cbOutput += (wcslen(found_name)+1) * sizeof(WCHAR);
    cbOutput += (wcslen(found_alg)+1) * sizeof(WCHAR);

    pKeyName = (NCryptKeyName *)HeapAlloc(GetProcessHeap(), 0, cbOutput);
    pKeyName->dwFlags = found_flags;
    pKeyName->dwLegacyKeySpec = 0;

    pbCurrent = (PBYTE)(pKeyName + 1);
    CopyMemory(pbCurrent, found_name, (wcslen(found_name)+1) * sizeof(WCHAR));
    pKeyName->pszName = (LPWSTR)pbCurrent;
    pbCurrent += (wcslen(found_name)+1) * sizeof(WCHAR);
    CopyMemory(pbCurrent, found_alg, (wcslen(found_alg)+1) * sizeof(WCHAR));
    pKeyName->pszAlgid = (LPWSTR)pbCurrent;

    // prepare for the next key on subsequent calls
    pEnumState->current_key++;

    Status = ERROR_SUCCESS;
    *ppEnumState = pEnumState;
    pEnumState = NULL;
    *ppKeyName = pKeyName;
    pKeyName = NULL;

cleanup:
    if (pEnumState)
    {
        HeapFree(GetProcessHeap(), 0, pEnumState);
    }
    if (pKeyName)
    {
        HeapFree(GetProcessHeap(), 0, pKeyName);
    }
    if (NULL != pProvider && TRUE == close_handle)
    {
        hal_rpc_pkey_close(found_handle);
    }

	return Status;
}

// Imports a CNG key from a memory BLOB. It is implemented by your key storage provider (KSP) and called by the NCryptImportKey function.
// Parameters
// hProvider [in] - The handle of the key storage provider.
//
// hImportKey [in, optional] - The handle of the cryptographic key that was used to encrypt the key data within the imported key BLOB. This must be a handle to the same key that was passed in the hExportKey parameter of the NCryptExportKeyFn function. If this parameter is NULL, the key BLOB is assumed to not be encrypted.
//
// pszBlobType [in] - A null-terminated Unicode string that contains an identifier that specifies the format of the key BLOB. This can be one of the following values.
//                    BCRYPT_DH_PRIVATE_BLOB  - The BLOB is a Diffie-Hellman public/private key pair. The pbInput buffer contains a BCRYPT_DH_KEY_BLOB structure immediately followed by the key data.
//                    BCRYPT_DH_PUBLIC_BLOB   - The BLOB is a Diffie-Hellman public key. The pbInput buffer contains a BCRYPT_DH_KEY_BLOB structure immediately followed by the key data.
//                    BCRYPT_DSA_PRIVATE_BLOB - The BLOB is a Digital Signature Algorithm (DSA) public/private key pair. The pbInput buffer contains a BCRYPT_DSA_KEY_BLOB structure immediately followed by the key data.
//                    BCRYPT_DSA_PUBLIC_BLOB  - The BLOB is a DSA public key. The pbInput buffer contains a BCRYPT_DSA_KEY_BLOB structure immediately followed by the key data.
//                    BCRYPT_ECCPRIVATE_BLOB  - The BLOB is an elliptic curve cryptography (ECC) private key. The pbInput buffer contains a BCRYPT_ECCKEY_BLOB structure immediately followed by the key data.
//                    BCRYPT_ECCPUBLIC_BLOB - The BLOB is an ECC public key. The pbInput buffer contains a BCRYPT_ECCKEY_BLOB structure immediately followed by the key data.
//                    BCRYPT_OPAQUE_KEY_BLOB - The BLOB is a symmetric key in a format that is specific to a single cryptographic service provider (CSP). Opaque BLOBs are not transferable and must be imported by using the same CSP that generated the BLOB.
//                    BCRYPT_PUBLIC_KEY_BLOB - The BLOB is a generic public key of any type. The type of key in this BLOB is determined by the Magic member of the BCRYPT_KEY_BLOB structure.
//                    BCRYPT_PRIVATE_KEY_BLOB - The BLOB is a generic private key of any type. The private key does not necessarily contain the public key. The type of key in this BLOB is determined by the Magic member of the BCRYPT_KEY_BLOB structure.
//                    BCRYPT_RSAPRIVATE_BLOB - The BLOB is an RSA public/private key pair. The pbInput buffer contains a BCRYPT_RSAKEY_BLOB structure immediately followed by the key data.
//                    BCRYPT_RSAPUBLIC_BLOB - The BLOB is an RSA public key. The pbInput buffer contains a BCRYPT_RSAKEY_BLOB structure immediately followed by the key data.
//                    LEGACY_DH_PRIVATE_BLOB - The BLOB is a legacy Diffie-Hellman Version 3 Private Key BLOB that contains a Diffie-Hellman public/private key pair that was exported by using CryptoAPI.
//                    LEGACY_DH_PUBLIC_BLOB - The BLOB is a legacy Diffie-Hellman Version 3 Private Key BLOB that contains a Diffie-Hellman public key that was exported by using CryptoAPI.
//                    LEGACY_DSA_PRIVATE_BLOB -The BLOB is a DSA public/private key pair in a form that can be imported by using CryptoAPI.
//                    LEGACY_DSA_PUBLIC_BLOB - The BLOB is a DSA public key in a form that can be imported by using CryptoAPI.
//                    LEGACY_DSA_V2_PRIVATE_BLOB - The BLOB is a DSA version 2 public/private key pair in a form that can be imported by using CryptoAPI.
//                    LEGACY_DSA_V2_PUBLIC_BLOB - The BLOB is a DSA version 2 public key in a form that can be imported by using CryptoAPI.
//                                                Windows Server 2008 and Windows Vista:  This value is not available.
//                    LEGACY_RSAPRIVATE_BLOB - The BLOB is an RSA public/private key pair in a form that can be imported by using CryptoAPI.
//                    LEGACY_RSAPUBLIC_BLOB - The BLOB is an RSA public key in a form that can be imported by using CryptoAPI.
//                    NCRYPT_OPAQUETRANSPORT_BLOB - The BLOB is a key in a format that is specific to a single CSP and is suitable for transport. Opaque BLOBs are not transferable and must be imported by using the same CSP that generated the BLOB.
//                    NCRYPT_PKCS7_ENVELOPE_BLOB - The BLOB is a PKCS7 envelope BLOB. The parameters identified by the pParameterList parameter either can or must contain the following parameters, as indicated by the Required or optional column.
//                                                 Parameter                   Required or optional
//                                                 NCRYPTBUFFER_CERT_BLOB      Required
//                                                 NCRYPTBUFFER_PKCS_KEY_NAME  Optional
//
//                    NCRYPT_PKCS8_PRIVATE_KEY_BLOB - The BLOB is a PKCS8 private key BLOB. The parameters identified by the pParameterList parameter either can or must contain the following parameters, as indicated by the Required or optional column.
//                                                    Parameter                    Required or optional
//                                                    NCRYPTBUFFER_PKCS_KEY_NAME   Optional
//                                                    NCRYPTBUFFER_PKCS_SECRET     Optional
//
// pParameterList [in, optional] - The address of an NCryptBufferDesc structure that contains parameter information for the key. This parameter can be NULL if this information is not used.
//
// phKey [out] - The address of an NCRYPT_KEY_HANDLE variable that receives the handle of the key. This handle will be passed to the NCryptDeleteKeyFn function when it is no longer needed.
//
// pbData [in] - The address of a buffer that contains the key BLOB to be imported. The cbOutput parameter contains the size of this buffer.
//
// cbData [in] - The size, in bytes, of the key BLOB in the pbData buffer.
//
// dwFlags [in] - A set of flags that modify the behavior of this function. This can be zero or a combination of one or more of the following values.
//                Value                        Meaning
//                NCRYPT_NO_KEY_VALIDATION     Do not validate the public portion of the key pair. This flag only applies to public/private key pairs.
//                NCRYPT_DO_NOT_FINALIZE_FLAG  Do not finalize the key. If this flag is not specified, you should finalize the key. You must finalize the key before it can be used by passing the key handle to the NCryptFinalizeKey function. This flag is supported for the private keys PKCS #7 and PKCS #8 but not public keys.
//                NCRYPT_MACHINE_KEY_FLAG      The key applies to the local computer. If this flag is not present, the key applies to the current user.
//                NCRYPT_OVERWRITE_KEY_FLAG    If a key already exists in the container with the specified name, the existing key will be overwritten. If this flag is not specified and a key with the specified name already exists, this function will return NTE_EXISTS.
//                NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG  Also save the key in legacy storage. This allows the key to be used with the CryptoAPI. This flag only applies to RSA keys.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds. Return NTE_UI_REQUIRED if a user interface must be displayed. Otherwise, return an error code. All status codes are logged then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_UI_REQUIRED  Indicates that a user interface must be displayed in the client application process. For more information, see Remarks.
//                  Note: If the calling application sets the dwFlags parameter to NCRYPT_SILENT_FLAG but your KSP requires that a user
//                        interface be displayed, the router fails and returns NTE_SILENT_CONTEXT to the caller.
//
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI ImportKey(
	_In_    NCRYPT_PROV_HANDLE hProvider,
	_In_opt_ NCRYPT_KEY_HANDLE hImportKey,
	_In_    LPCWSTR pszBlobType,
	_In_opt_ NCryptBufferDesc *pParameterList,
	_Out_   NCRYPT_KEY_HANDLE *phKey,
	_In_reads_bytes_(cbData) PBYTE pbData,
	_In_    DWORD   cbData,
	_In_    DWORD   dwFlags)
{
	return NTE_NOT_SUPPORTED;
}

// Exports a key to a memory BLOB. It is implemented by your key storage provider (KSP) and called by the NCryptExportKey function.
// Parameters
// hProvider [in] - A handle of the key storage provider.
//
// hKey [in] - A handle of the key to export.
//
// hExportKey [in, optional] - A handle to a cryptographic key of the destination user. The key data within the exported key BLOB is encrypted by using this key. This ensures that only the destination user is able to make use of the key BLOB.
//
// pszBlobType [in] - A null-terminated Unicode string that contains an identifier that specifies the type of BLOB to export. This can be one of the following values.
//                    BCRYPT_DH_PRIVATE_BLOB - Export a Diffie-Hellman public/private key pair. The pbOutput buffer receives a BCRYPT_DH_KEY_BLOB structure immediately followed by the key data.
//                    BCRYPT_DH_PUBLIC_BLOB - Export a Diffie-Hellman public key. The pbOutput buffer receives a BCRYPT_DH_KEY_BLOB structure immediately followed by the key data.
//                    BCRYPT_DSA_PRIVATE_BLOB - Export a DSA public/private key pair. The pbOutput buffer receives a BCRYPT_DSA_KEY_BLOB structure immediately followed by the key data.
//                    BCRYPT_DSA_PUBLIC_BLOB - Export a DSA public key. The pbOutput buffer receives a BCRYPT_DSA_KEY_BLOB structure immediately followed by the key data.
//                    BCRYPT_ECCPRIVATE_BLOB - Export an elliptic curve cryptography (ECC) private key. The pbOutput buffer receives a BCRYPT_ECCKEY_BLOB structure immediately followed by the key data.
//                    BCRYPT_ECCPUBLIC_BLOB - Export an ECC public key. The pbOutput buffer receives a BCRYPT_ECCKEY_BLOB structure immediately followed by the key data.
//                    BCRYPT_OPAQUE_KEY_BLOB - Export a symmetric key in a format that is specific to a single cryptographic service provider (CSP). Opaque BLOBs are not transferable and must be imported by using the same CSP that generated the BLOB.
//                    BCRYPT_PUBLIC_KEY_BLOB - Export a generic public key of any type. The type of key in this BLOB is determined by the Magic member of the BCRYPT_KEY_BLOB structure.
//                    BCRYPT_PRIVATE_KEY_BLOB - Export a generic private key of any type. The private key does not necessarily contain the public key. The type of key in this BLOB is determined by the Magic member of the BCRYPT_KEY_BLOB structure.
//                    BCRYPT_RSAFULLPRIVATE_BLOB - Export a full RSA public/private key pair. The pbOutput buffer receives a BCRYPT_RSAKEY_BLOB structure immediately followed by the key data. This BLOB will include additional key material compared to the BCRYPT_RSAPRIVATE_BLOB type.
//                    BCRYPT_RSAPRIVATE_BLOB - Export an RSA public/private key pair. The pbOutput buffer receives a BCRYPT_RSAKEY_BLOB structure immediately followed by the key data.
//                    BCRYPT_RSAPUBLIC_BLOB - Export an RSA public key. The pbOutput buffer receives a BCRYPT_RSAKEY_BLOB structure immediately followed by the key data.
//                    LEGACY_DH_PRIVATE_BLOB - Export a Diffie-Hellman public/private key pair in a form that can be imported by using CryptoAPI.
//                    LEGACY_DH_PUBLIC_BLOB - Export a Diffie-Hellman public key in a form that can be imported by using CryptoAPI.
//                    LEGACY_DSA_PRIVATE_BLOB - Export a DSA public/private key pair in a form that can be imported by using CryptoAPI.
//                    LEGACY_DSA_PUBLIC_BLOB - Export a DSA public key in a form that can be imported by using CryptoAPI.
//                    LEGACY_RSAPRIVATE_BLOB - Export an RSA public/private key pair in a form that can be imported by using CryptoAPI.
//                    LEGACY_RSAPUBLIC_BLOB - Export an RSA public key in a form that can be imported by using CryptoAPI.
//                    NCRYPT_OPAQUETRANSPORT_BLOB - Export a key in a format that is specific to a single CSP and is suitable for transport. Opaque BLOBs are not transferable and must be imported by using the same CSP that generated the BLOB.
//                    NCRYPT_PKCS7_ENVELOPE_BLOB - Export a PKCS7 envelope BLOB. The parameters identified by the pParameterList parameter either can or must contain the following parameters, as indicated by the Required or optional column.
//                                                 Parameter                   Required or optional
//                                                 NCRYPTBUFFER_CERT_BLOB      Required
//                                                 NCRYPTBUFFER_PKCS_ALG_OID   Required
//                                                 NCRYPTBUFFER_PKCS_ALG_PARAM Optional
//
//                    NCRYPT_PKCS8_PRIVATE_KEY_BLOB - Export a PKCS8 private key BLOB. The parameters identified by the pParameterList parameter either can or must contain the following parameters, as indicated by the Required or optional column.
//                                                    Parameter                   Required or optional
//                                                    NCRYPTBUFFER_PKCS_ALG_OID   Optional
//                                                    NCRYPTBUFFER_PKCS_ALG_PARAM Optional
//                                                    NCRYPTBUFFER_PKCS_SECRET    Optional
//
// pParameterList [in, optional] - The address of an NCryptBufferDesc structure that receives parameter information for the key. This parameter can be NULL if this information is not needed.
//
// pbOutput [out, optional] - The address of a buffer that receives the key BLOB. The cbOutput parameter contains the size of this buffer. If this parameter is NULL, this function will place the required size, in bytes, in the DWORD pointed to by the pcbResult parameter.
//
// cbOutput [in] - The size, in bytes, of the pbOutput buffer.
//
// pcbResult [out] - The address of a DWORD variable that receives the number of bytes copied to the pbOutput buffer. If the pbOutput parameter is NULL, this function will place the required size, in bytes, in the DWORD pointed to by this parameter.
//
// dwFlags [in] - A set of flags that modify the behavior of this function. No flags are defined for this function.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds. Return NTE_UI_REQUIRED if a user interface must be displayed. Otherwise, return an error code. All status codes are logged then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_UI_REQUIRED  Indicates that a user interface must be displayed in the client application process. For more information, see Remarks.
//                  Note  If the calling application sets the dwFlags parameter to NCRYPT_SILENT_FLAG but your KSP requires that a user interface be displayed, the router fails and returns NTE_SILENT_CONTEXT to the caller.
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI ExportKey(
	_In_    NCRYPT_PROV_HANDLE hProvider,
	_In_    NCRYPT_KEY_HANDLE hKey,
	_In_opt_ NCRYPT_KEY_HANDLE hExportKey,
	_In_    LPCWSTR pszBlobType,
	_In_opt_ NCryptBufferDesc *pParameterList,
	_Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
	_In_    DWORD   cbOutput,
	_Out_   DWORD * pcbResult,
	_In_    DWORD   dwFlags)
{
	return NTE_NOT_SUPPORTED;
}

// Signs a hash value. It is implemented by your key storage provider (KSP) and called by the NCryptSignHash function.
// Parameters
// hProvider [in] - The handle of the key storage provider to sign the hash value.
//
// hKey [in] - The handle of the key to use to sign the hash.
//
// pPaddingInfo [in, optional] - A pointer to a structure that contains padding information. The actual type of structure this parameter points to depends on the value of the dwFlags parameter. This parameter is only used with asymmetric keys and must be NULL otherwise.
//
// pbHashValue [in] - A pointer to a buffer that contains the hash value to sign. The cbInput parameter contains the size of this buffer.
//
// cbHashValue [in] - The number of bytes in the pbHashValue buffer to sign.
//
// pbSignature [out] - The address of a buffer to receive the signature produced by this function. The cbSignature parameter contains the size of this buffer.
//                     If this parameter is NULL, this function will calculate the size required for the signature and return the size in the location pointed to by the pcbResult parameter.
//
// cbSignature [in] - The size, in bytes, of the pbSignature buffer. This parameter is ignored if the pbSignature parameter is NULL.
//
// pcbResult [out] - A pointer to a DWORD variable that receives the number of bytes copied to the pbSignature buffer.
//                   If pbSignature is NULL, this receives the size, in bytes, required for the signature.
//
// dwFlags [in] - A set of flags that modify the behavior of this function. The allowed set of flags depends on the type of key specified by the hKey parameter.
//                If the key is a symmetric key, this parameter is not used and should be set to zero.
//                If the key is an asymmetric key, this can be one of the following values.
//                Value              Meaning
//                BCRYPT_PAD_PKCS1   Use the PKCS1 padding scheme. The pPaddingInfo parameter is a pointer to a BCRYPT_PKCS1_PADDING_INFO structure.
//                BCRYPT_PAD_PSS     Use the Probabilistic Signature Scheme (PSS) padding scheme. The pPaddingInfo parameter is a pointer to a BCRYPT_PSS_PADDING_INFO structure.
// 
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds. Return NTE_UI_REQUIRED if a user interface must be displayed. Otherwise, return an error code. All status codes are logged then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_UI_REQUIRED  Indicates that a user interface must be displayed in the client application process. For more information, see Remarks.
//                  Note  If the calling application sets the dwFlags parameter to NCRYPT_SILENT_FLAG but your KSP requires that a user interface be displayed, the router fails and returns NTE_SILENT_CONTEXT to the caller.
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI SignHash(
	_In_    NCRYPT_PROV_HANDLE hProvider,
	_In_    NCRYPT_KEY_HANDLE hKey,
	_In_opt_    VOID *pPaddingInfo,
	_In_reads_bytes_(cbHashValue) PBYTE pbHashValue,
	_In_    DWORD   cbHashValue,
	_Out_writes_bytes_to_opt_(cbSignature, *pcbResult) PBYTE pbSignature,
	_In_    DWORD   cbSignature,
	_Out_   DWORD * pcbResult,
	_In_    DWORD   dwFlags)
{
    SECURITY_STATUS     Status = NTE_INTERNAL_ERROR;
    DKEY_KSP_PROVIDER *pProvider;
    DKEY_KSP_KEY *pKey = NULL;
    hal_error_t rpc_result;

    // Validate input parameters.
    pProvider = DKEYKspValidateProvHandle(hProvider);

    if (pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    pKey = DKEYKspValidateKeyHandle(hKey);

    if (pKey == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if (pKey->phProvider != pProvider)
    {
        Status = NTE_BAD_PROVIDER;
        goto cleanup;
    }

    if (NULL == pbHashValue || 0 == cbHashValue)
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    size_t signature_len;
    if (!get_signature_len(pKey->hPublicKey, &signature_len))
    {
        Status = NTE_BAD_KEYSET;
        goto cleanup;
    }
    *pcbResult = signature_len;
    if (NULL == pbSignature)
    {
        return ERROR_SUCCESS;
    }

    if (cbSignature < signature_len)
    {
        Status = NTE_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    rpc_result = hal_rpc_pkey_sign(pKey->hPrivateKey, hal_hash_handle_none, pbHashValue, cbHashValue, pbSignature, &signature_len, cbSignature);
    if (rpc_result != HAL_OK)
    {
        Status = NTE_INTERNAL_ERROR;
    }
    else
    {
        Status = ERROR_SUCCESS;
    }

cleanup:
    return Status;
}

// Verifies a signature. It is implemented by your key storage provider (KSP) and called by the NCryptVerifySignature function.
// Parameters
// hProvider [in] - The handle of the key storage provider.
//
// hKey [in] - The handle of the key to use to decrypt the signature. This must be an identical key or the public key portion of the key pair used to sign the data with the NCryptSignHashFn function.
//
// pPaddingInfo [in, optional] - A pointer to a structure that contains padding information. The actual type of structure this parameter points to depends on the value of the dwFlags parameter. This parameter is only used with asymmetric keys and must be NULL otherwise.
//
// pbHashValue [in] - The address of a buffer that contains the hash of the data. The cbHash parameter contains the size of this buffer.
//
// cbHashValue [in] - The size, in bytes, of the pbHash buffer.
//
// pbSignature [in] - The address of a buffer that contains the signed hash of the data. The NCryptSignHashFn function is used to create the signature. The cbSignature parameter contains the size of this buffer.
//
// cbSignature [in] - The size, in bytes, of the pbSignature buffer. The NCryptSignHashFn function is used to create the signature.
//
// dwFlags [in] - A set of flags that modify the behavior of this function. The allowed set of flags depends on the type of key specified by the hKey parameter.
//                If the key is a symmetric key, this parameter is not used and should be zero.
//                If the key is an asymmetric key, this can be one of the following values.
//                Value                   Meaning
//                NCRYPT_PAD_PKCS1_FLAG   The PKCS1 padding scheme was used when the signature was created. The pPaddingInfo parameter is a pointer to a BCRYPT_PKCS1_PADDING_INFO structure.
//                NCRYPT_PAD_PSS_FLAG     The Probabilistic Signature Scheme (PSS) padding scheme was used when the signature was created. The pPaddingInfo parameter is a pointer to a BCRYPT_PSS_PADDING_INFO structure.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds. Return NTE_UI_REQUIRED if a user interface must be displayed. Otherwise, return an error code. All status codes are logged then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_UI_REQUIRED  Indicates that a user interface must be displayed in the client application process. For more information, see Remarks.
//                  Note  If the calling application sets the dwFlags parameter to NCRYPT_SILENT_FLAG but your KSP requires that a user interface be displayed, the router fails and returns NTE_SILENT_CONTEXT to the caller.
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
SECURITY_STATUS WINAPI VerifySignature(
	_In_    NCRYPT_PROV_HANDLE hProvider,
	_In_    NCRYPT_KEY_HANDLE hKey,
	_In_opt_    VOID *pPaddingInfo,
	_In_reads_bytes_(cbHashValue) PBYTE pbHashValue,
	_In_    DWORD   cbHashValue,
	_In_reads_bytes_(cbSignature) PBYTE pbSignature,
	_In_    DWORD   cbSignature,
	_In_    DWORD   dwFlags)
{
    SECURITY_STATUS     Status = NTE_INTERNAL_ERROR;
    DKEY_KSP_PROVIDER *pProvider;
    DKEY_KSP_KEY *pKey = NULL;
    hal_error_t rpc_result;

    // Validate input parameters.
    pProvider = DKEYKspValidateProvHandle(hProvider);

    if (pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    pKey = DKEYKspValidateKeyHandle(hKey);

    if (pKey == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if (pKey->phProvider != pProvider)
    {
        Status = NTE_BAD_PROVIDER;
        goto cleanup;
    }

    if (NULL == pbHashValue || 0 == cbHashValue)
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    rpc_result = hal_rpc_pkey_verify(pKey->hPublicKey, hal_hash_handle_none, pbHashValue, cbHashValue, pbSignature, cbSignature);
    if (rpc_result != HAL_OK)
    {
        Status = NTE_BAD_SIGNATURE;
    }
    else
    {
        Status = ERROR_SUCCESS;
    }

cleanup:
    return Status;
}

// Displays a user interface and prompts the user for information. It is implemented by your key storage provider (KSP) and called by the key storage router when you return NTE_UI_REQUIRED from an implemented (NCryptxxxFn) function.
// Parameters
// hProvider [in] - The handle of the key storage provider.
//
// hKey [in] - The handle of the object in question. The exact data type will depend on the operation identified by the pszOperation parameter. This parameter may be NULL if it is not used.
//
// pszOperation [in] - A pointer to a null-terminated Unicode string that identifies the operation that caused this function to be called. In most cases, this will be the name of the CNG function that this function is being called from, such as "NCryptOpenKey" or "NCryptGetProperty". This parameter cannot be NULL.
//
// dwFlags [in] - A set of flags that modify the behavior of this function. No flags are defined for this function.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds. Otherwise, return an error code. All status codes are logged then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
//
// Remarks
// If your KSP does not implement this function, return NTE_NOT_SUPPORTED and set the PromptUser member of the NCRYPT_KEY_STORAGE_FUNCTION_TABLE structure to NULL.
//
// The implementation should present the user interface in the target user's session. For example, you can use either the WTSSendMessage or the CreateProcessAsUser function.
SECURITY_STATUS WINAPI PromptUser(
	_In_    NCRYPT_PROV_HANDLE hProvider,
	_In_opt_ NCRYPT_KEY_HANDLE hKey,
	_In_    LPCWSTR pszOperation,
	_In_    DWORD   dwFlags)
{
	return NTE_NOT_SUPPORTED;
}

// Creates or removes an event notification that signals whether a key has changed. It is implemented by your key storage provider (KSP) and called by the NCryptNotifyChangeKey function.
// Parameters
// hProvider [in] - The handle of the key storage provider.
//
// phEvent [in, out] - Pointer to a HANDLE variable that either receives or contains the key change notification event handle. This is the same handle that is returned by the FindFirstChangeNotification function. For more information, see the dwFlags parameter description.
//
// dwFlags [in] - A set of flags that modify the behavior of this function. This parameter contains a combination of one or more of the following values.
//                Value                                       Meaning
//                NCRYPT_REGISTER_NOTIFY_FLAG   0x00000001    Create a new change notification. The phEvent parameter will receive the key change notification handle.
//                NCRYPT_UNREGISTER_NOTIFY_FLAG 0x00000002    Remove an existing change notification. The phEvent parameter must contain a valid key change notification handle. This handle is no longer valid after this function is called with this flag and the INVALID_HANDLE_VALUE value is placed in this handle.
//                NCRYPT_MACHINE_KEY_FLAG       0x00000020    Receive change notifications for local system keys. If this flag is not specified, the change notification events will only occur for shared computer keys. This flag is only valid when combined with the NCRYPT_REGISTER_NOTIFY_FLAG flag and when this function is called in the context of the Local System account.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds. Otherwise, return an error code. All status codes are logged then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
//
// Remarks
// If your KSP does not implement this function, return NTE_NOT_SUPPORTED.
// This function is called by NCryptNotifyChangeKey through the key storage router. That is, NCryptNotifyChangeKey calls the router and the router calls your NCryptNotifyChangeKeyFn implementation. You must place a pointer to your implementation in the NotifyChangeKey member of the NCRYPT_KEY_STORAGE_FUNCTION_TABLE structure so that the function can be found by the router.
SECURITY_STATUS WINAPI NotifyChangeKey(
	_In_    NCRYPT_PROV_HANDLE hProvider,
	_Inout_ HANDLE *phEvent,
	_In_    DWORD   dwFlags)
{
	return NTE_NOT_SUPPORTED;
}

// Creates a secret agreement value from a private and a public key. It is implemented by your key storage provider (KSP) and called by the NCryptSecretAgreement function.
// Parameters
// hProvider [in] - The handle of the key storage provider.
//
// hPrivKey [in] - The handle of the private key to use to create the secret agreement value.
//
// hPubKey [in] - The handle of the public key to use to create the secret agreement value.
//
// phSecret [out] - A pointer to an NCRYPT_SECRET_HANDLE variable that receives a handle that represents the secret agreement value. When this handle is no longer needed, release it by passing it to the NCryptFreeObject function.
//
// dwFlags [in] - A set of flags that modify the behavior of this function. No flags are defined for this function.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds. Return NTE_UI_REQUIRED if a user interface must be displayed. Otherwise, return an error code. All status codes are logged then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_UI_REQUIRED  Indicates that a user interface must be displayed in the client application process. For more information, see Remarks.
//                  Note: If the calling application sets the dwFlags parameter to NCRYPT_SILENT_FLAG but your KSP requires that a user interface be displayed, the router fails and returns NTE_SILENT_CONTEXT to the caller.
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
//
// Remarks
// If your KSP does not implement this function, return NTE_NOT_SUPPORTED.
// This function is called by NCryptSecretAgreement through the key storage router. That is, NCryptSecretAgreement calls the router and the router calls your NCryptSecretAgreementFn implementation. You must place a pointer to your implementation in the SecretAgreement member of the NCRYPT_KEY_STORAGE_FUNCTION_TABLE structure so that the function can be found by the router.
// If your KSP must display a user interface, you must return an HRESULT value of NTE_UI_REQUIRED to the router. The router then calls your NCryptPromptUserFn implementation. If that function returns ERROR_SUCCESS, the router again calls NCryptSecretAgreementFn.
SECURITY_STATUS WINAPI SecretAgreement(
	_In_    NCRYPT_PROV_HANDLE hProvider,
	_In_    NCRYPT_KEY_HANDLE hPrivKey,
	_In_    NCRYPT_KEY_HANDLE hPubKey,
	_Out_   NCRYPT_SECRET_HANDLE *phAgreedSecret,
	_In_    DWORD   dwFlags)
{
	return NTE_NOT_SUPPORTED;
}

// Derives a key. It is implemented by your key storage provider (KSP) and called by the NCryptDeriveKey function.
SECURITY_STATUS WINAPI DeriveKey(
	_In_        NCRYPT_PROV_HANDLE   hProvider,
	_In_        NCRYPT_SECRET_HANDLE hSharedSecret,
	_In_        LPCWSTR              pwszKDF,
	_In_opt_    NCryptBufferDesc     *pParameterList,
	_Out_writes_bytes_to_opt_(cbDerivedKey, *pcbResult) PBYTE pbDerivedKey,
	_In_        DWORD                cbDerivedKey,
	_Out_       DWORD                *pcbResult,
	_In_        ULONG                dwFlags)
{
	return NTE_NOT_SUPPORTED;
}

// Frees a shared secret handle that was created by the provider's shared secret algorithm. It is implemented by your key storage provider (KSP) and called by the NCryptFreeObject function.
// Parameters
// hProvider [in] - The handle of the provider.
//
// hSharedSecret [in] - The handle of the shared secret.
//
// Return value
// Your implementation of this function in a CNG key storage provider (KSP) must return ERROR_SUCCESS if the function succeeds. Otherwise, return an error code. All status codes are logged then returned to the caller.
//
// Return code Description
// ERROR_SUCCESS  The function was successful.
// NTE_NOT_SUPPORTED  Specifies that the function is not implemented.
//
// Remarks
// If your KSP does not implement this function, return NTE_NOT_SUPPORTED.
// This function is called by NCryptFreeObject through the key storage router. That is, NCryptFreeObject calls the router and the router calls your NCryptFreeSecretFn implementation. You must place a pointer to your implementation in the FreeSecret member of the NCRYPT_KEY_STORAGE_FUNCTION_TABLE structure so that the function can be found by the router.
SECURITY_STATUS WINAPI FreeSecret(
	_In_    NCRYPT_PROV_HANDLE hProvider,
	_In_    NCRYPT_SECRET_HANDLE hSharedSecret)
{
	return NTE_NOT_SUPPORTED;
}
