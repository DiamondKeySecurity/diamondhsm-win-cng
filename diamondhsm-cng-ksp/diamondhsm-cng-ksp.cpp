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
	DWORD cbLength = 0;
	size_t cbProviderName = 0;
    void *conn_context = NULL;
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
    pProvider->client = hal_client_handle_t{ 0 };

    // connect to the HSM
    hal_error_t err;
    if ((err = hal_rpc_client_transport_init_ip(DKEYKspGetHostAddr(), "dks-hsm", &conn_context)) != HAL_OK)
    {
        status = NTE_DEVICE_NOT_FOUND;
        goto cleanup;
    }

    // save the context
    pProvider->conn_context = conn_context;

    if ((err = hal_rpc_login(pProvider->conn_context, pProvider->client, HAL_USER_NORMAL, DKEYKspGetUserPin(), strlen(DKEYKspGetUserPin()))) != HAL_OK)
    {
        status = NTE_VALIDATION_FAILED;
        goto cleanup;
    }

	//Assign the output value.
	*phProvider = (NCRYPT_PROV_HANDLE)pProvider;
	pProvider = NULL;
	status = ERROR_SUCCESS;
cleanup:
	if (pProvider)
	{
		HeapFree(GetProcessHeap(), 0, pProvider);
	}
    if (status != ERROR_SUCCESS && NULL != conn_context)
    {
        hal_rpc_client_transport_close(conn_context);
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
	return NTE_NOT_SUPPORTED;
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
	return NTE_NOT_SUPPORTED;
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
	return NTE_NOT_SUPPORTED;
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
	return NTE_NOT_SUPPORTED;
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
	return NTE_NOT_SUPPORTED;
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
	return NTE_NOT_SUPPORTED;
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

    // log out and disconnect
    hal_rpc_logout(pProvider->conn_context, pProvider->client);

    hal_rpc_client_transport_close(pProvider->conn_context);

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
	return NTE_NOT_SUPPORTED;
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
	return NTE_NOT_SUPPORTED;
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
	return NTE_NOT_SUPPORTED;
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
	return NTE_NOT_SUPPORTED;
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
	return NTE_NOT_SUPPORTED;
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
	return NTE_NOT_SUPPORTED;
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
	return NTE_NOT_SUPPORTED;
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
