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

    std::cout << "-----------------------------------------" << std::endl;
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
    std::cout << "-----------------------------------------" << std::endl;
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

char *tombsstring(const wchar_t *incoming, char *buffer, size_t buf_len)
{
    size_t num_converted;
    wcstombs_s(&num_converted, buffer, buf_len, incoming, buf_len);

    return buffer;
}

void TestPKEY(NCRYPT_KEY_STORAGE_FUNCTION_TABLE *pFunctionTable, const wchar_t *key_name)
{
    SECURITY_STATUS status;
    NCRYPT_PROV_HANDLE phProvider;
    NCRYPT_KEY_HANDLE hKey;
    WCHAR wstr_propertybuffer[512];
    DWORD dwProperty;
    DWORD cbResult;
    char str_buffer1[512];
    char str_buffer2[512];

    status = pFunctionTable->OpenProvider(&phProvider, DKEY_KSP_PROVIDER_NAME, 0U);
    std::cout << "OpenProvider returned " << status << std::endl;

    status = pFunctionTable->OpenKey(phProvider, &hKey, key_name, 0, 0);
    std::cout << "OpenKey " << status << std::endl;

    // --------------------------------
    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_NAME_PROPERTY, (PBYTE)&wstr_propertybuffer[0], sizeof(wstr_propertybuffer), &cbResult, 0);
    std::cout << "GetKeyProperty: " << tombsstring(NCRYPT_NAME_PROPERTY, str_buffer1, sizeof(str_buffer1)) <<
                 " returned " << tombsstring(wstr_propertybuffer, str_buffer2, sizeof(str_buffer2)) << "; status == 0" << status << "; cbResult ==" << cbResult << std::endl;

    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_NAME_PROPERTY, NULL, 0, &cbResult, 0);
    std::cout << "GetKeyProperty (length only): " << tombsstring(NCRYPT_NAME_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << "; cbResult ==" << cbResult << std::endl;
    // --------------------------------
    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_UNIQUE_NAME_PROPERTY, (PBYTE)&wstr_propertybuffer[0], sizeof(wstr_propertybuffer), &cbResult, 0);
    std::cout << "GetKeyProperty: " << tombsstring(NCRYPT_UNIQUE_NAME_PROPERTY, str_buffer1, sizeof(str_buffer1)) <<
        " returned " << tombsstring(wstr_propertybuffer, str_buffer2, sizeof(str_buffer2)) << "; status == 0" << status << "; cbResult ==" << cbResult << std::endl;

    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_UNIQUE_NAME_PROPERTY, NULL, 0, &cbResult, 0);
    std::cout << "GetKeyProperty (length only): " << tombsstring(NCRYPT_UNIQUE_NAME_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << "; cbResult ==" << cbResult << std::endl;
    // --------------------------------
    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)&wstr_propertybuffer[0], sizeof(wstr_propertybuffer), &cbResult, 0);
    std::cout << "GetKeyProperty: " << tombsstring(NCRYPT_ALGORITHM_PROPERTY, str_buffer1, sizeof(str_buffer1)) <<
        " returned " << tombsstring(wstr_propertybuffer, str_buffer2, sizeof(str_buffer2)) << "; status == 0" << status << "; cbResult ==" << cbResult << std::endl;

    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_ALGORITHM_PROPERTY, NULL, 0, &cbResult, 0);
    std::cout << "GetKeyProperty (length only): " << tombsstring(NCRYPT_ALGORITHM_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << "; cbResult ==" << cbResult << std::endl;
    // --------------------------------
    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_ALGORITHM_GROUP_PROPERTY, (PBYTE)&wstr_propertybuffer[0], sizeof(wstr_propertybuffer), &cbResult, 0);
    std::cout << "GetKeyProperty: " << tombsstring(NCRYPT_ALGORITHM_GROUP_PROPERTY, str_buffer1, sizeof(str_buffer1)) <<
        " returned " << tombsstring(wstr_propertybuffer, str_buffer2, sizeof(str_buffer2)) << "; status == 0" << status << "; cbResult ==" << cbResult << std::endl;

    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_ALGORITHM_GROUP_PROPERTY, NULL, 0, &cbResult, 0);
    std::cout << "GetKeyProperty (length only): " << tombsstring(NCRYPT_ALGORITHM_GROUP_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << "; cbResult ==" << cbResult << std::endl;
    // --------------------------------
    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_LENGTH_PROPERTY, (PBYTE)&dwProperty, sizeof(DWORD), &cbResult, 0);
    std::cout << "GetKeyProperty: " << tombsstring(NCRYPT_LENGTH_PROPERTY, str_buffer1, sizeof(str_buffer1)) <<
        " returned " << dwProperty << "; status == " << status << "; cbResult ==" << cbResult << std::endl;

    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_LENGTH_PROPERTY, NULL, 0, &cbResult, 0);
    std::cout << "GetKeyProperty (length only): " << tombsstring(NCRYPT_LENGTH_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << "; cbResult ==" << cbResult << std::endl;
    // --------------------------------
    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&dwProperty, sizeof(DWORD), &cbResult, 0);
    std::cout << "GetKeyProperty: " << tombsstring(NCRYPT_EXPORT_POLICY_PROPERTY, str_buffer1, sizeof(str_buffer1)) <<
        " returned " << dwProperty << "; status == " << status << "; cbResult ==" << cbResult << std::endl;

    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_EXPORT_POLICY_PROPERTY, NULL, 0, &cbResult, 0);
    std::cout << "GetKeyProperty (length only): " << tombsstring(NCRYPT_EXPORT_POLICY_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << "; cbResult ==" << cbResult << std::endl;
    // --------------------------------
    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_IMPL_TYPE_PROPERTY, (PBYTE)&dwProperty, sizeof(DWORD), &cbResult, 0);
    std::cout << "GetKeyProperty: " << tombsstring(NCRYPT_IMPL_TYPE_PROPERTY, str_buffer1, sizeof(str_buffer1)) <<
        " returned " << dwProperty << "; status == " << status << "; cbResult ==" << cbResult << std::endl;

    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_IMPL_TYPE_PROPERTY, NULL, 0, &cbResult, 0);
    std::cout << "GetKeyProperty (length only): " << tombsstring(NCRYPT_IMPL_TYPE_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << "; cbResult ==" << cbResult << std::endl;
    // --------------------------------
    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&dwProperty, sizeof(DWORD), &cbResult, 0);
    std::cout << "GetKeyProperty: " << tombsstring(NCRYPT_KEY_USAGE_PROPERTY, str_buffer1, sizeof(str_buffer1)) <<
        " returned " << dwProperty << "; status == " << status << "; cbResult ==" << cbResult << std::endl;

    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_KEY_USAGE_PROPERTY, NULL, 0, &cbResult, 0);
    std::cout << "GetKeyProperty (length only): " << tombsstring(NCRYPT_KEY_USAGE_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << "; cbResult ==" << cbResult << std::endl;
    // --------------------------------
    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_KEY_TYPE_PROPERTY, (PBYTE)&dwProperty, sizeof(DWORD), &cbResult, 0);
    std::cout << "GetKeyProperty: " << tombsstring(NCRYPT_KEY_TYPE_PROPERTY, str_buffer1, sizeof(str_buffer1)) <<
        " returned " << dwProperty << "; status == " << status << "; cbResult ==" << cbResult << std::endl;

    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_KEY_TYPE_PROPERTY, NULL, 0, &cbResult, 0);
    std::cout << "GetKeyProperty (length only): " << tombsstring(NCRYPT_KEY_TYPE_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << "; cbResult ==" << cbResult << std::endl;
    // --------------------------------
    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY, (PBYTE)&dwProperty, sizeof(DWORD), &cbResult, 0);
    std::cout << "GetKeyProperty: " << tombsstring(NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY, str_buffer1, sizeof(str_buffer1)) <<
        " returned " << dwProperty << "; status == " << status << "; cbResult ==" << cbResult << std::endl;

    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY, NULL, 0, &cbResult, 0);
    std::cout << "GetKeyProperty (length only): " << tombsstring(NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << "; cbResult ==" << cbResult << std::endl;
    // --------------------------------   
    // --------------------------------
    status = pFunctionTable->SetKeyProperty(phProvider, hKey, NCRYPT_KEY_TYPE_PROPERTY, NULL, 0, 0);
    std::cout << "SetKeyProperty: " << tombsstring(NCRYPT_KEY_TYPE_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status  << std::endl;

    status = pFunctionTable->FreeKey(phProvider, hKey);
    std::cout << "FreeKey returned " << status << std::endl;

    status = pFunctionTable->OpenKey(phProvider, &hKey, TEXT("not in key storage"), 0, 0);
    std::cout << "OpenKey \"not in key storage\" returned " << status << std::endl;

    status = pFunctionTable->FreeKey(phProvider, hKey);
    std::cout << "FreeKey returned " << status << std::endl;

    status = pFunctionTable->FreeProvider(phProvider);
    std::cout << "FreeProvider returned " << status << std::endl;
}

void TestSign(NCRYPT_KEY_STORAGE_FUNCTION_TABLE *pFunctionTable)
{
    SECURITY_STATUS status;
    NCRYPT_PROV_HANDLE phProvider;
    NCRYPT_KEY_HANDLE hKey;
    WCHAR wstr_propertybuffer[512];
    DWORD dwProperty;
    DWORD cbResult;
    char str_buffer1[512];
    char str_buffer2[512];

    const uint8_t sha256_double_digest[] = { /* 32 bytes */
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93,
        0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
    };
    uint8_t signature[1024];

    for (int i = 0; i < 2; ++i)
    {
        if (i == 0)
        {
            std::cout << "Testing RSA signing ----------------------" << std::endl;
            const wchar_t *key_name = TEXT("signer-key-ZZZZZ-rsa");

            status = pFunctionTable->OpenProvider(&phProvider, DKEY_KSP_PROVIDER_NAME, 0U);
            std::cout << "OpenProvider returned " << status << std::endl;

            status = pFunctionTable->CreatePersistedKey(phProvider, &hKey, TEXT("RSA"), key_name, 0, 0);
            std::cout << "CreatePersistedKey returned " << status << std::endl;
        }
        else
        {
            std::cout << "Testing ECDSA signing ----------------------" << std::endl;
            const wchar_t *key_name = TEXT("signer-key-ZZZZZ-ecdsa");

            status = pFunctionTable->OpenProvider(&phProvider, DKEY_KSP_PROVIDER_NAME, 0U);
            std::cout << "OpenProvider returned " << status << std::endl;

            status = pFunctionTable->CreatePersistedKey(phProvider, &hKey, TEXT("ECDSA_P256"), key_name, 0, 0);
            std::cout << "CreatePersistedKey returned " << status << std::endl;
        }

        status = pFunctionTable->SignHash(phProvider, hKey, NULL, (PBYTE)sha256_double_digest, sizeof(sha256_double_digest), signature, sizeof(signature), &cbResult, 0);
        std::cout << "SignHash returned " << status << std::endl;

        status = pFunctionTable->VerifySignature(phProvider, hKey, NULL, (PBYTE)sha256_double_digest, sizeof(sha256_double_digest), signature, cbResult, 0);
        std::cout << "VerifySignature returned " << status << std::endl;

        // break sig and try again
        signature[0] = 0;
        signature[1] = 0;
        status = pFunctionTable->VerifySignature(phProvider, hKey, NULL, (PBYTE)sha256_double_digest, sizeof(sha256_double_digest), signature, cbResult, 0);
        std::cout << "(Break test)VerifySignature returned " << status << std::endl;

        status = pFunctionTable->DeleteKey(phProvider, hKey, 0);
        std::cout << "DeleteKey returned " << status << std::endl;
    }

    status = pFunctionTable->FreeProvider(phProvider);
    std::cout << "FreeProvider returned " << status << std::endl;
}

void TestPKEYGen(NCRYPT_KEY_STORAGE_FUNCTION_TABLE *pFunctionTable)
{
    SECURITY_STATUS status;
    NCRYPT_PROV_HANDLE phProvider;
    NCRYPT_KEY_HANDLE hKey;
    WCHAR wstr_propertybuffer[512];
    DWORD dwProperty;
    DWORD cbResult;
    char str_buffer1[512];
    char str_buffer2[512];
    const wchar_t *key_name = TEXT("aaaaaa-diamond-co-kr-ksk-ZZZZZ");

    status = pFunctionTable->OpenProvider(&phProvider, DKEY_KSP_PROVIDER_NAME, 0U);
    std::cout << "OpenProvider returned " << status << std::endl;

    status = pFunctionTable->CreatePersistedKey(phProvider, &hKey, TEXT("ECDSA_P256"), TEXT("aaa-ecdsa_test"), 0, 0);
    std::cout << "CreatePersistedKey returned " << status << std::endl;
    status = pFunctionTable->FreeKey(phProvider, hKey);
    std::cout << "FreeKey returned " << status << std::endl;

    status = pFunctionTable->CreatePersistedKey(phProvider, &hKey, TEXT("RSA"), key_name, 0, 0);
    std::cout << "CreatePersistedKey returned " << status << std::endl;

    //status = pFunctionTable->OpenKey(phProvider, &hKey, TEXT("diamond-dr-ksk"), 0, 0);
    //std::cout << "OpenKey \"diamond - dr - ksk\" returned " << status << std::endl;

    // --------------------------------
    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_NAME_PROPERTY, (PBYTE)&wstr_propertybuffer[0], sizeof(wstr_propertybuffer), &cbResult, 0);
    std::cout << "GetKeyProperty: " << tombsstring(NCRYPT_NAME_PROPERTY, str_buffer1, sizeof(str_buffer1)) <<
        " returned " << tombsstring(wstr_propertybuffer, str_buffer2, sizeof(str_buffer2)) << "; status == 0" << status << "; cbResult ==" << cbResult << std::endl;

    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_NAME_PROPERTY, NULL, 0, &cbResult, 0);
    std::cout << "GetKeyProperty (length only): " << tombsstring(NCRYPT_NAME_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << "; cbResult ==" << cbResult << std::endl;
    // --------------------------------
    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_UNIQUE_NAME_PROPERTY, (PBYTE)&wstr_propertybuffer[0], sizeof(wstr_propertybuffer), &cbResult, 0);
    std::cout << "GetKeyProperty: " << tombsstring(NCRYPT_UNIQUE_NAME_PROPERTY, str_buffer1, sizeof(str_buffer1)) <<
        " returned " << tombsstring(wstr_propertybuffer, str_buffer2, sizeof(str_buffer2)) << "; status == 0" << status << "; cbResult ==" << cbResult << std::endl;

    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_UNIQUE_NAME_PROPERTY, NULL, 0, &cbResult, 0);
    std::cout << "GetKeyProperty (length only): " << tombsstring(NCRYPT_UNIQUE_NAME_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << "; cbResult ==" << cbResult << std::endl;
    // --------------------------------
    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)&wstr_propertybuffer[0], sizeof(wstr_propertybuffer), &cbResult, 0);
    std::cout << "GetKeyProperty: " << tombsstring(NCRYPT_ALGORITHM_PROPERTY, str_buffer1, sizeof(str_buffer1)) <<
        " returned " << tombsstring(wstr_propertybuffer, str_buffer2, sizeof(str_buffer2)) << "; status == 0" << status << "; cbResult ==" << cbResult << std::endl;

    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_ALGORITHM_PROPERTY, NULL, 0, &cbResult, 0);
    std::cout << "GetKeyProperty (length only): " << tombsstring(NCRYPT_ALGORITHM_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << "; cbResult ==" << cbResult << std::endl;
    // --------------------------------
    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_ALGORITHM_GROUP_PROPERTY, (PBYTE)&wstr_propertybuffer[0], sizeof(wstr_propertybuffer), &cbResult, 0);
    std::cout << "GetKeyProperty: " << tombsstring(NCRYPT_ALGORITHM_GROUP_PROPERTY, str_buffer1, sizeof(str_buffer1)) <<
        " returned " << tombsstring(wstr_propertybuffer, str_buffer2, sizeof(str_buffer2)) << "; status == 0" << status << "; cbResult ==" << cbResult << std::endl;

    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_ALGORITHM_GROUP_PROPERTY, NULL, 0, &cbResult, 0);
    std::cout << "GetKeyProperty (length only): " << tombsstring(NCRYPT_ALGORITHM_GROUP_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << "; cbResult ==" << cbResult << std::endl;
    // --------------------------------
    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_LENGTH_PROPERTY, (PBYTE)&dwProperty, sizeof(DWORD), &cbResult, 0);
    std::cout << "GetKeyProperty: " << tombsstring(NCRYPT_LENGTH_PROPERTY, str_buffer1, sizeof(str_buffer1)) <<
        " returned " << dwProperty << "; status == " << status << "; cbResult ==" << cbResult << std::endl;

    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_LENGTH_PROPERTY, NULL, 0, &cbResult, 0);
    std::cout << "GetKeyProperty (length only): " << tombsstring(NCRYPT_LENGTH_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << "; cbResult ==" << cbResult << std::endl;
    // --------------------------------
    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&dwProperty, sizeof(DWORD), &cbResult, 0);
    std::cout << "GetKeyProperty: " << tombsstring(NCRYPT_EXPORT_POLICY_PROPERTY, str_buffer1, sizeof(str_buffer1)) <<
        " returned " << dwProperty << "; status == " << status << "; cbResult ==" << cbResult << std::endl;

    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_EXPORT_POLICY_PROPERTY, NULL, 0, &cbResult, 0);
    std::cout << "GetKeyProperty (length only): " << tombsstring(NCRYPT_EXPORT_POLICY_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << "; cbResult ==" << cbResult << std::endl;
    // --------------------------------
    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_IMPL_TYPE_PROPERTY, (PBYTE)&dwProperty, sizeof(DWORD), &cbResult, 0);
    std::cout << "GetKeyProperty: " << tombsstring(NCRYPT_IMPL_TYPE_PROPERTY, str_buffer1, sizeof(str_buffer1)) <<
        " returned " << dwProperty << "; status == " << status << "; cbResult ==" << cbResult << std::endl;

    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_IMPL_TYPE_PROPERTY, NULL, 0, &cbResult, 0);
    std::cout << "GetKeyProperty (length only): " << tombsstring(NCRYPT_IMPL_TYPE_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << "; cbResult ==" << cbResult << std::endl;
    // --------------------------------
    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&dwProperty, sizeof(DWORD), &cbResult, 0);
    std::cout << "GetKeyProperty: " << tombsstring(NCRYPT_KEY_USAGE_PROPERTY, str_buffer1, sizeof(str_buffer1)) <<
        " returned " << dwProperty << "; status == " << status << "; cbResult ==" << cbResult << std::endl;

    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_KEY_USAGE_PROPERTY, NULL, 0, &cbResult, 0);
    std::cout << "GetKeyProperty (length only): " << tombsstring(NCRYPT_KEY_USAGE_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << "; cbResult ==" << cbResult << std::endl;
    // --------------------------------
    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_KEY_TYPE_PROPERTY, (PBYTE)&dwProperty, sizeof(DWORD), &cbResult, 0);
    std::cout << "GetKeyProperty: " << tombsstring(NCRYPT_KEY_TYPE_PROPERTY, str_buffer1, sizeof(str_buffer1)) <<
        " returned " << dwProperty << "; status == " << status << "; cbResult ==" << cbResult << std::endl;

    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_KEY_TYPE_PROPERTY, NULL, 0, &cbResult, 0);
    std::cout << "GetKeyProperty (length only): " << tombsstring(NCRYPT_KEY_TYPE_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << "; cbResult ==" << cbResult << std::endl;
    // --------------------------------
    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY, (PBYTE)&dwProperty, sizeof(DWORD), &cbResult, 0);
    std::cout << "GetKeyProperty: " << tombsstring(NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY, str_buffer1, sizeof(str_buffer1)) <<
        " returned " << dwProperty << "; status == " << status << "; cbResult ==" << cbResult << std::endl;

    status = pFunctionTable->GetKeyProperty(phProvider, hKey, NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY, NULL, 0, &cbResult, 0);
    std::cout << "GetKeyProperty (length only): " << tombsstring(NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << "; cbResult ==" << cbResult << std::endl;
    // --------------------------------   
    // --------------------------------
    status = pFunctionTable->SetKeyProperty(phProvider, hKey, NCRYPT_KEY_TYPE_PROPERTY, NULL, 0, 0);
    std::cout << "SetKeyProperty: " << tombsstring(NCRYPT_KEY_TYPE_PROPERTY, str_buffer1, sizeof(str_buffer1)) << " status == " << status << std::endl;

    status = pFunctionTable->FreeKey(phProvider, hKey);
    std::cout << "FreeKey returned " << status << std::endl;

    std::cout << "Testing Enum Functions" << std::endl;
    TestEnum(pFunctionTable);

    std::cout << "--------------Testing PKEY Functions" << std::endl;
    TestPKEY(pFunctionTable, key_name);

    status = pFunctionTable->OpenKey(phProvider, &hKey, key_name, 0, 0);
    std::cout << "OpenKey returned " << status << std::endl;

    status = pFunctionTable->DeleteKey(phProvider, hKey, 0);
    std::cout << "DeleteKey returned " << status << std::endl;

    status = pFunctionTable->FreeProvider(phProvider);
    std::cout << "FreeProvider returned " << status << std::endl;
}

void TestFunctions(NCRYPT_KEY_STORAGE_FUNCTION_TABLE *pFunctionTable)
{
    std::cout << "**************************************************" << std::endl;
    std::cout << "Testing Function Existence" << std::endl;
	TestFunctionsExist(pFunctionTable);

    std::cout << "**************************************************" << std::endl;
    std::cout << "Testing Enum Functions" << std::endl;
    TestEnum(pFunctionTable);

    std::cout << "**************************************************" << std::endl;
    std::cout << "Testing Algorithm Functions" << std::endl;
    TestAlgorithms(pFunctionTable);

    std::cout << "**************************************************" << std::endl;
    std::cout << "Testing PKEYGen Functions" << std::endl;
    TestPKEYGen(pFunctionTable);

    std::cout << "**************************************************" << std::endl;
    std::cout << "Testing Signing Functions" << std::endl;
    TestSign(pFunctionTable);
}

int main()
{
	HINSTANCE hinstLib;
	GetKeyStorageInterfaceFn ProcGetKeyStorageInterface;
	BOOL fFreeResult, fRunTimeLinkSuccess = FALSE;

	// Get a handle to the DLL module.
#ifdef _WIN64
    hinstLib = LoadLibrary(TEXT("diamondhsm-cng-ksp_x64.dll"));
#else
    hinstLib = LoadLibrary(TEXT("diamondhsm-cng-ksp_Win32.dll"));
#endif

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

