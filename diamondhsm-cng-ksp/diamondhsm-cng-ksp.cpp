// diamondhsm-cng-ksp.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

NTSTATUS WINAPI GetKeyStorageInterface(
	_In_   LPCWSTR pszProviderName,
	_Out_  NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
	_In_   DWORD dwFlags
)
{
	//return ERROR_SUCCESS;
	return ERROR_NOT_READY;
}

