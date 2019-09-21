// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.

/*++

Abstract:
Helper functions for sample CNG RSA key storage provider

Implementation Note:
In several places this sample returns a single, generic SECURITY_STATUS error when a called function
returns any Win32 error.  This is only done for the sake of brevity in the sample.

As a best practice, production code should provide a function to convert Win32 errors
to appropriate SECURITY_STATUS errors, and use it to set SECURITY_STATUS error
variables accurately.  This would allow relevant troubleshooting error information
to propagate out of the KSP.
--*/

#include "stdafx.h"
#include "diamondhsm-ksp.h"
#include "diamondhsm-cng-ksp.h"

///////////////////////////////////////////////////////////////////////////////
/******************************************************************************
*
* DESCRIPTION :     Convert NTSTATUS error code to SECURITY_STATUS error code
*
* INPUTS :
*            NTSTATUS NtStatus          Error code of NTSTATUS format
* RETURN :
*            SECURITY_STATUS            Converted error code
*/
SECURITY_STATUS
NormalizeNteStatus(
	__in NTSTATUS NtStatus)
{
	SECURITY_STATUS SecStatus;

	switch (NtStatus)
	{
	case STATUS_SUCCESS:
		SecStatus = ERROR_SUCCESS;
		break;

	case STATUS_NO_MEMORY:
	case STATUS_INSUFFICIENT_RESOURCES:
		SecStatus = NTE_NO_MEMORY;
		break;

	case STATUS_INVALID_PARAMETER:
		SecStatus = NTE_INVALID_PARAMETER;
		break;

	case STATUS_INVALID_HANDLE:
		SecStatus = NTE_INVALID_HANDLE;
		break;

	case STATUS_BUFFER_TOO_SMALL:
		SecStatus = NTE_BUFFER_TOO_SMALL;
		break;

	case STATUS_NOT_SUPPORTED:
		SecStatus = NTE_NOT_SUPPORTED;
		break;

	case STATUS_INTERNAL_ERROR:
	case ERROR_INTERNAL_ERROR:
		SecStatus = NTE_INTERNAL_ERROR;
		break;

	case STATUS_INVALID_SIGNATURE:
		SecStatus = NTE_BAD_SIGNATURE;
		break;

	default:
		SecStatus = NTE_INTERNAL_ERROR;
		break;
	}

	return SecStatus;
}

///////////////////////////////////////////////////////////////////////////////
/*****************************************************************************
* DESCRIPTION :    Validate sample KSP provider handle
*
* INPUTS :
*           NCRYPT_PROV_HANDLE hProvider                A NCRYPT_PROV_HANDLE handle
*
* RETURN :
*           A pointer to a SAMPLEKSP_PROVIDER struct    The function was successful.
*           NULL                                        The handle is invalid.
*/
DKEY_KSP_PROVIDER *DKEYKspValidateProvHandle(
	__in    NCRYPT_PROV_HANDLE hProvider)
{
	DKEY_KSP_PROVIDER *pProvider = NULL;

	if (hProvider == 0)
	{
		return NULL;
	}

	pProvider = (DKEY_KSP_PROVIDER *)hProvider;

	if (pProvider->cbLength < sizeof(DKEY_KSP_PROVIDER) ||
		pProvider->dwMagic != DKEY_KSP_PROVIDER_MAGIC)
	{
		return NULL;
	}

	return pProvider;
}

/*****************************************************************************
* DESCRIPTION :    Validate sample KSP key handle
*
* INPUTS :
*           NCRYPT_KEY_HANDLE hKey                 An NCRYPT_KEY_HANDLE handle
*
* RETURN :
*           A pointer to a SAMPLEKSP_KEY struct    The function was successful.
*           NULL                                   The handle is invalid.
*/
DKEY_KSP_KEY *DKEYKspValidateKeyHandle(
	__in    NCRYPT_KEY_HANDLE hKey)
{
	DKEY_KSP_KEY *pKey = NULL;

	if (hKey == 0)
	{
		return NULL;
	}

	pKey = (DKEY_KSP_KEY *)hKey;

	if (pKey->cbLength < sizeof(DKEY_KSP_KEY) ||
		pKey->dwMagic != DKEY_KSP_KEY_MAGIC)
	{
		return NULL;
	}

	return pKey;
}