// dll_import_test.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>

#include "../diamondhsm-cng-ksp/diamondhsm-ksp.h"

void TestFunctionsExist(NCRYPT_KEY_STORAGE_FUNCTION_TABLE *pFunctionTable)
{
	SECURITY_STATUS status;
	NCRYPT_PROV_HANDLE phProvider;

	status = pFunctionTable->OpenProvider(&phProvider, DKEY_KSP_PROVIDER_NAME, 0U);
	std::cout << "OpenProvider returned " << status << std::endl;

	status = pFunctionTable->OpenKey(phProvider, NULL, NULL, 0U, 0U);
	std::cout << "OpenKey returned " << status << std::endl;

	status = pFunctionTable->CreatePersistedKey(phProvider, NULL, NULL, NULL, 0U, 0U);
	std::cout << "CreatePersistedKey returned " << status << std::endl;

	status = pFunctionTable->GetProviderProperty(phProvider, NULL, NULL, 0U, NULL, 0U);
	std::cout << "GetProviderProperty returned " << status << std::endl;

	status = pFunctionTable->GetKeyProperty(phProvider, NULL, NULL, NULL, 0U, NULL, 0U);
	std::cout << "GetKeyProperty returned " << status << std::endl;

	status = pFunctionTable->SetProviderProperty(phProvider, NULL, NULL, 0U, 0U);
	std::cout << "SetProviderProperty returned " << status << std::endl;

	status = pFunctionTable->SetKeyProperty(phProvider, NULL, NULL, NULL, 0U, 0U);
	std::cout << "SetKeyProperty returned " << status << std::endl;

	status = pFunctionTable->FinalizeKey(phProvider, NULL, 0U);
	std::cout << "FinalizeKey returned " << status << std::endl;

	status = pFunctionTable->DeleteKey(phProvider, NULL, 0U);
	std::cout << "DeleteKey returned " << status << std::endl;

	status = pFunctionTable->FreeKey(phProvider, NULL);
	std::cout << "FreeKey returned " << status << std::endl;

	status = pFunctionTable->FreeBuffer(NULL);
	std::cout << "FreeBuffer returned " << status << std::endl;

	status = pFunctionTable->Encrypt(phProvider, NULL, NULL, 0U, NULL, NULL, 0U, NULL, 0U);
	std::cout << "Encrypt returned " << status << std::endl;

	status = pFunctionTable->Decrypt(phProvider, NULL, NULL, 0U, NULL, NULL, 0U, NULL, 0U);
	std::cout << "Decrypt returned " << status << std::endl;

	status = pFunctionTable->IsAlgSupported(phProvider, NULL, 0U);
	std::cout << "IsAlgSupported returned " << status << std::endl;

	status = pFunctionTable->EnumAlgorithms(phProvider, 0U, NULL, NULL, 0U);
	std::cout << "EnumAlgorithms returned " << status << std::endl;

	status = pFunctionTable->EnumKeys(phProvider, NULL, NULL, NULL, 0U);
	std::cout << "EnumKeys returned " << status << std::endl;

	status = pFunctionTable->ImportKey(phProvider, NULL, NULL, NULL, NULL, NULL, 0U, 0U);
	std::cout << "ImportKey returned " << status << std::endl;

	status = pFunctionTable->ExportKey(phProvider, NULL, NULL, NULL, NULL, NULL, 0U, NULL, 0U);
	std::cout << "ExportKey returned " << status << std::endl;

	status = pFunctionTable->SignHash(phProvider, NULL, NULL, NULL, 0U, NULL, 0U, NULL, 0U);
	std::cout << "SignHash returned " << status << std::endl;

	status = pFunctionTable->VerifySignature(phProvider, NULL, NULL, NULL, 0U, NULL, 0U, 0U);
	std::cout << "VerifySignature returned " << status << std::endl;

	status = pFunctionTable->PromptUser(phProvider, NULL, NULL, 0U);
	std::cout << "PromptUser returned " << status << std::endl;

	status = pFunctionTable->NotifyChangeKey(phProvider, NULL, 0U);
	std::cout << "NotifyChangeKey returned " << status << std::endl;

	status = pFunctionTable->SecretAgreement(phProvider, NULL, NULL, NULL, 0U);
	std::cout << "SecretAgreement returned " << status << std::endl;

	status = pFunctionTable->DeriveKey(phProvider, NULL, NULL, NULL, NULL, 0U, NULL, 0U);
	std::cout << "DeriveKey returned " << status << std::endl;

	status = pFunctionTable->FreeSecret(phProvider, NULL);
	std::cout << "FreeSecret returned " << status << std::endl;

	status = pFunctionTable->FreeProvider(phProvider);
	std::cout << "FreeProvider returned " << status << std::endl;
}

void TestEnum(NCRYPT_KEY_STORAGE_FUNCTION_TABLE *pFunctionTable)
{
    SECURITY_STATUS status;
    NCRYPT_PROV_HANDLE phProvider;

    status = pFunctionTable->OpenProvider(&phProvider, DKEY_KSP_PROVIDER_NAME, 0U);
    std::cout << "OpenProvider returned " << status << std::endl;

    NCryptAlgorithmName *pAlgList;
    DWORD dwAlgCount;
    status = pFunctionTable->EnumAlgorithms(phProvider, 0U, &dwAlgCount, &pAlgList, 0U);
    std::cout << "EnumAlgorithms returned " << status << std::endl;
    if (status == 0)
    {
        for (int i = 0; i < dwAlgCount; ++i)
        {
            char buffer[256];
            size_t converted;
            wcstombs_s(&converted, buffer, pAlgList[i].pszName, 256);
            std::cout << "Algorithm: " << buffer << "; class == " << pAlgList[i].dwClass << "; op == " << pAlgList[i].dwAlgOperations << std::endl;
        }
    }

    status = pFunctionTable->FreeProvider(phProvider);
    std::cout << "FreeProvider returned " << status << std::endl;
}

void TestFunctions(NCRYPT_KEY_STORAGE_FUNCTION_TABLE *pFunctionTable)
{
    std::cout << "Testing Function Existence" << std::endl;
	TestFunctionsExist(pFunctionTable);

    std::cout << "Testing Enum Functions" << std::endl;
    TestEnum(pFunctionTable);
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

