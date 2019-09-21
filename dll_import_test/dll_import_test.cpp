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

    status = 0;
    void *pEnumState = NULL;
    while (status == 0)
    {
        NCryptKeyName *pKeyName = NULL;
        status = pFunctionTable->EnumKeys(phProvider, NULL, &pKeyName, &pEnumState, 0);

        if (0 == status)
        {
            char name_buffer[256];
            char alg_buffer[256];
            size_t converted;

            wcstombs_s(&converted, name_buffer, pKeyName->pszName, 256);
            wcstombs_s(&converted, alg_buffer, pKeyName->pszAlgid, 256);
            std::cout << "Found: " << name_buffer << " ; alg == " << alg_buffer << std::endl;
        }

        pFunctionTable->FreeBuffer(pKeyName);
    }
    pFunctionTable->FreeBuffer(pEnumState);

    status = pFunctionTable->FreeProvider(phProvider);
    std::cout << "FreeProvider returned " << status << std::endl;
}

void TestAlgorithms(NCRYPT_KEY_STORAGE_FUNCTION_TABLE *pFunctionTable)
{
    SECURITY_STATUS status;
    NCRYPT_PROV_HANDLE phProvider;
    char str_buffer[256];
    size_t num_converted;

    status = pFunctionTable->OpenProvider(&phProvider, DKEY_KSP_PROVIDER_NAME, 0U);
    std::cout << "OpenProvider returned " << status << std::endl;

    status = pFunctionTable->IsAlgSupported(phProvider, NCRYPT_RSA_ALGORITHM, 0);
    wcstombs_s(&num_converted, str_buffer, NCRYPT_RSA_ALGORITHM, 256);
    std::cout << str_buffer << " returned " << status << std::endl;

    status = pFunctionTable->IsAlgSupported(phProvider, NCRYPT_RSA_SIGN_ALGORITHM, 0);
    wcstombs_s(&num_converted, str_buffer, NCRYPT_RSA_SIGN_ALGORITHM, 256);
    std::cout << str_buffer << " returned " << status << std::endl;

    status = pFunctionTable->IsAlgSupported(phProvider, NCRYPT_DH_ALGORITHM, 0);
    wcstombs_s(&num_converted, str_buffer, NCRYPT_DH_ALGORITHM, 256);
    std::cout << str_buffer << " returned " << status << std::endl;

    status = pFunctionTable->IsAlgSupported(phProvider, NCRYPT_DSA_ALGORITHM, 0);
    wcstombs_s(&num_converted, str_buffer, NCRYPT_DSA_ALGORITHM, 256);
    std::cout << str_buffer << " returned " << status << std::endl;

    status = pFunctionTable->IsAlgSupported(phProvider, NCRYPT_MD2_ALGORITHM, 0);
    wcstombs_s(&num_converted, str_buffer, NCRYPT_MD2_ALGORITHM, 256);
    std::cout << str_buffer << " returned " << status << std::endl;

    status = pFunctionTable->IsAlgSupported(phProvider, NCRYPT_MD4_ALGORITHM, 0);
    wcstombs_s(&num_converted, str_buffer, NCRYPT_MD4_ALGORITHM, 256);
    std::cout << str_buffer << " returned " << status << std::endl;

    status = pFunctionTable->IsAlgSupported(phProvider, NCRYPT_MD5_ALGORITHM, 0);
    wcstombs_s(&num_converted, str_buffer, NCRYPT_MD5_ALGORITHM, 256);
    std::cout << str_buffer << " returned " << status << std::endl;

    status = pFunctionTable->IsAlgSupported(phProvider, NCRYPT_SHA1_ALGORITHM, 0);
    wcstombs_s(&num_converted, str_buffer, NCRYPT_SHA1_ALGORITHM, 256);
    std::cout << str_buffer << " returned " << status << std::endl;

    status = pFunctionTable->IsAlgSupported(phProvider, NCRYPT_SHA256_ALGORITHM, 0);
    wcstombs_s(&num_converted, str_buffer, NCRYPT_SHA256_ALGORITHM, 256);
    std::cout << str_buffer << " returned " << status << std::endl;

    status = pFunctionTable->IsAlgSupported(phProvider, NCRYPT_SHA384_ALGORITHM, 0);
    wcstombs_s(&num_converted, str_buffer, NCRYPT_SHA384_ALGORITHM, 256);
    std::cout << str_buffer << " returned " << status << std::endl;

    status = pFunctionTable->IsAlgSupported(phProvider, NCRYPT_SHA512_ALGORITHM, 0);
    wcstombs_s(&num_converted, str_buffer, NCRYPT_SHA512_ALGORITHM, 256);
    std::cout << str_buffer << " returned " << status << std::endl;

    status = pFunctionTable->IsAlgSupported(phProvider, NCRYPT_ECDSA_P256_ALGORITHM, 0);
    wcstombs_s(&num_converted, str_buffer, NCRYPT_ECDSA_P256_ALGORITHM, 256);
    std::cout << str_buffer << " returned " << status << std::endl;

    status = pFunctionTable->IsAlgSupported(phProvider, NCRYPT_ECDSA_P384_ALGORITHM, 0);
    wcstombs_s(&num_converted, str_buffer, NCRYPT_ECDSA_P384_ALGORITHM, 256);
    std::cout << str_buffer << " returned " << status << std::endl;

    status = pFunctionTable->IsAlgSupported(phProvider, NCRYPT_ECDSA_P521_ALGORITHM, 0);
    wcstombs_s(&num_converted, str_buffer, NCRYPT_ECDSA_P521_ALGORITHM, 256);
    std::cout << str_buffer << " returned " << status << std::endl;

    status = pFunctionTable->IsAlgSupported(phProvider, NCRYPT_ECDH_P256_ALGORITHM, 0);
    wcstombs_s(&num_converted, str_buffer, NCRYPT_ECDH_P256_ALGORITHM, 256);
    std::cout << str_buffer << " returned " << status << std::endl;

    status = pFunctionTable->IsAlgSupported(phProvider, NCRYPT_ECDH_P384_ALGORITHM, 0);
    wcstombs_s(&num_converted, str_buffer, NCRYPT_ECDH_P384_ALGORITHM, 256);
    std::cout << str_buffer << " returned " << status << std::endl;

    status = pFunctionTable->IsAlgSupported(phProvider, NCRYPT_ECDH_P521_ALGORITHM, 0);
    wcstombs_s(&num_converted, str_buffer, NCRYPT_ECDH_P521_ALGORITHM, 256);
    std::cout << str_buffer << " returned " << status << std::endl;

    status = pFunctionTable->FreeProvider(phProvider);
    std::cout << "FreeProvider returned " << status << std::endl;
}

void TestFunctions(NCRYPT_KEY_STORAGE_FUNCTION_TABLE *pFunctionTable)
{
    std::cout << "Testing Function Existence" << std::endl;
	TestFunctionsExist(pFunctionTable);

    std::cout << "Testing Enum Functions" << std::endl;
    TestEnum(pFunctionTable);

    std::cout << "Testing Algorithm Functions" << std::endl;
    TestAlgorithms(pFunctionTable);
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

