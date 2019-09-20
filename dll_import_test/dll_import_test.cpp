// dll_import_test.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>

void TestFunctionsExist(NCRYPT_KEY_STORAGE_FUNCTION_TABLE *pFunctionTable)
{
	SECURITY_STATUS status;

	status = pFunctionTable->OpenProvider(NULL, NULL, 0U);
	std::cout << "OpenProvider returned " << status << std::endl;

	status = pFunctionTable->OpenKey(NULL, NULL, NULL, 0U, 0U);
	std::cout << "OpenKey returned " << status << std::endl;

	status = pFunctionTable->CreatePersistedKey(NULL, NULL, NULL, NULL, 0U, 0U);
	std::cout << "CreatePersistedKey returned " << status << std::endl;

	status = pFunctionTable->GetProviderProperty(NULL, NULL, NULL, 0U, NULL, 0U);
	std::cout << "GetProviderProperty returned " << status << std::endl;

	status = pFunctionTable->GetKeyProperty(NULL, NULL, NULL, NULL, 0U, NULL, 0U);
	std::cout << "GetKeyProperty returned " << status << std::endl;

	status = pFunctionTable->SetProviderProperty(NULL, NULL, NULL, 0U, 0U);
	std::cout << "SetProviderProperty returned " << status << std::endl;

	status = pFunctionTable->SetKeyProperty(NULL, NULL, NULL, NULL, 0U, 0U);
	std::cout << "SetKeyProperty returned " << status << std::endl;

	status = pFunctionTable->FinalizeKey(NULL, NULL, 0U);
	std::cout << "FinalizeKey returned " << status << std::endl;

	status = pFunctionTable->DeleteKey(NULL, NULL, 0U);
	std::cout << "DeleteKey returned " << status << std::endl;

	status = pFunctionTable->FreeProvider(NULL);
	std::cout << "FreeProvider returned " << status << std::endl;

	status = pFunctionTable->FreeKey(NULL, NULL);
	std::cout << "FreeKey returned " << status << std::endl;

	status = pFunctionTable->FreeBuffer(NULL);
	std::cout << "FreeBuffer returned " << status << std::endl;

	status = pFunctionTable->Encrypt(NULL, NULL, NULL, 0U, NULL, NULL, 0U, NULL, 0U);
	std::cout << "Encrypt returned " << status << std::endl;

	status = pFunctionTable->Decrypt(NULL, NULL, NULL, 0U, NULL, NULL, 0U, NULL, 0U);
	std::cout << "Decrypt returned " << status << std::endl;

	status = pFunctionTable->IsAlgSupported(NULL, NULL, 0U);
	std::cout << "IsAlgSupported returned " << status << std::endl;

	status = pFunctionTable->EnumAlgorithms(NULL, 0U, NULL, NULL, 0U);
	std::cout << "EnumAlgorithms returned " << status << std::endl;

	status = pFunctionTable->EnumKeys(NULL, NULL, NULL, NULL, 0U);
	std::cout << "EnumKeys returned " << status << std::endl;

	status = pFunctionTable->ImportKey(NULL, NULL, NULL, NULL, NULL, NULL, 0U, 0U);
	std::cout << "ImportKey returned " << status << std::endl;

	status = pFunctionTable->ExportKey(NULL, NULL, NULL, NULL, NULL, NULL, 0U, NULL, 0U);
	std::cout << "ExportKey returned " << status << std::endl;

	status = pFunctionTable->SignHash(NULL, NULL, NULL, NULL, 0U, NULL, 0U, NULL, 0U);
	std::cout << "SignHash returned " << status << std::endl;

	status = pFunctionTable->VerifySignature(NULL, NULL, NULL, NULL, 0U, NULL, 0U, 0U);
	std::cout << "VerifySignature returned " << status << std::endl;

	status = pFunctionTable->PromptUser(NULL, NULL, NULL, 0U);
	std::cout << "PromptUser returned " << status << std::endl;

	status = pFunctionTable->NotifyChangeKey(NULL, NULL, 0U);
	std::cout << "NotifyChangeKey returned " << status << std::endl;

	status = pFunctionTable->SecretAgreement(NULL, NULL, NULL, NULL, 0U);
	std::cout << "SecretAgreement returned " << status << std::endl;

	status = pFunctionTable->DeriveKey(NULL, NULL, NULL, NULL, NULL, 0U, NULL, 0U);
	std::cout << "DeriveKey returned " << status << std::endl;

	status = pFunctionTable->FreeSecret(NULL, NULL);
	std::cout << "FreeSecret returned " << status << std::endl;
}

void TestFunctions(NCRYPT_KEY_STORAGE_FUNCTION_TABLE *pFunctionTable)
{
	TestFunctionsExist(pFunctionTable);
}

int main()
{
	HINSTANCE hinstLib;
	GetKeyStorageInterfaceFn ProcGetKeyStorageInterface;
	BOOL fFreeResult, fRunTimeLinkSuccess = FALSE;

	// Get a handle to the DLL module.

	hinstLib = LoadLibrary(TEXT("diamondhsm-cng-ksp.dll"));

	// If the handle is valid, try to get the function address.

	if (hinstLib != NULL)
	{
		ProcGetKeyStorageInterface = (GetKeyStorageInterfaceFn)GetProcAddress(hinstLib, "GetKeyStorageInterface");

		// If the function address is valid, call the function.

		if (NULL != ProcGetKeyStorageInterface)
		{
			NCRYPT_KEY_STORAGE_FUNCTION_TABLE *pFunctionTable;

			int result = (ProcGetKeyStorageInterface)(TEXT(""), &pFunctionTable, 0L);
			std::cout << "result == " << result << std::endl;

			TestFunctions(pFunctionTable);
			std::cin.ignore();
		}
		else
		{
			std::cout << "Function not found" << std::endl;
			std::cin.ignore();
		}
		// Free the DLL module.

		fFreeResult = FreeLibrary(hinstLib);
	}
	else
	{
		std::cout << "DLL not found" << std::endl;
		std::cin.ignore();
	}

	return 0;
}

