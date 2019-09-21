#pragma once

#include <ncrypt_provider.h>
#include <bcrypt_provider.h>

#define DKEY_KSP_INTERFACE_VERSION NCRYPT_KEY_STORAGE_INTERFACE_VERSION //version of the DKEY KSP interface
#define DKEY_KSP_VERSION 0x00010000                         //version of the DKEY KSP
#define DKEY_KSP_SUPPORT_SECURITY_DESCRIPTOR   0x00000001             //This DKEY KSP supports security descriptor
#define DKEY_KSP_PROVIDER_NAME           L"Diamond Key Security Key Storage Provider" //name of the DKEY KSP provider
#define DKEY_KSP_PROVIDER_MAGIC          0x53504C50      // SPLP
#define DKEY_KSP_KEY_MAGIC               0x53504C4b      // SPLK
#define DKEY_KSP_RSA_ALGID               1               // Algorithm ID RSA
#define DKEY_KSP_DEFAULT_KEY_LENGTH      1024            // default key length
#define DKEY_KSP_RSA_MIN_LENGTH          512             // minimal key length
#define DKEY_KSP_RSA_MAX_LENGTH          4096            // maximal key length
#define DKEY_KSP_RSA_INCREMENT           64              // increment of key length

//property ID
#define DKEY_KSP_IMPL_TYPE_PROPERTY      1
#define DKEY_KSP_MAX_NAME_LEN_PROPERTY   2
#define DKEY_KSP_NAME_PROPERTY           3
#define DKEY_KSP_VERSION_PROPERTY        4
#define DKEY_KSP_SECURITY_DESCR_SUPPORT_PROPERTY     5
#define DKEY_KSP_ALGORITHM_PROPERTY      6
#define DKEY_KSP_BLOCK_LENGTH_PROPERTY   7
#define DKEY_KSP_EXPORT_POLICY_PROPERTY  8
#define DKEY_KSP_KEY_USAGE_PROPERTY      9
#define DKEY_KSP_KEY_TYPE_PROPERTY       10
#define DKEY_KSP_LENGTH_PROPERTY         11
#define DKEY_KSP_LENGTHS_PROPERTY        12
#define DKEY_KSP_SECURITY_DESCR_PROPERTY 13
#define DKEY_KSP_ALGORITHM_GROUP_PROPERTY 14
#define DKEY_KSP_USE_CONTEXT_PROPERTY    15
#define DKEY_KSP_UNIQUE_NAME_PROPERTY    16
#define DKEY_KSP_UI_POLICY_PROPERTY      17
#define DKEY_KSP_WINDOW_HANDLE_PROPERTY  18
//const
#define MAXUSHORT   0xffff
#define MAX_NUM_PROPERTIES  100


//error handling
#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (status >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_NOT_SUPPORTED            ((NTSTATUS)0xC00000BBL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_INTERNAL_ERROR           ((NTSTATUS)0xC00000E5L)
#define STATUS_INVALID_SIGNATURE        ((NTSTATUS)0xC000A000L)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)
#endif

//provider handle
typedef __struct_bcount(sizeof(DKEY_KSP_PROVIDER)) struct _DKEY_KSP_PROVIDER
{
	DWORD               cbLength;   //length of the whole data struct
	DWORD               dwMagic;    //type of the provider
	DWORD               dwFlags;    //reserved flags
	LPWSTR              pszContext; //context
	hal_user_t          hal_user;
}DKEY_KSP_PROVIDER;

//key handle
typedef __struct_bcount(sizeof(DKEY_KSP_KEY)) struct _DKEY_KSP_KEY
{
	DWORD               cbLength;           //length of the whole data blob
	DWORD               dwMagic;            //type of the key
	LPWSTR              pszKeyName;         //name of the key (key file)
	DWORD               dwAlgID;            //Algorithm ID
	DWORD               dwKeyBitLength;     //length of the key
	DWORD               dwExportPolicy;     //export policy
	DWORD               dwKeyUsagePolicy;   //key usage policy
	BOOL                fFinished;          //Whether the key is finalized

	// handle to cryptography providers needed to perform operations with
	// the key.
	BCRYPT_ALG_HANDLE   hProvider;

	// handle to key objects.
	BCRYPT_KEY_HANDLE   hPublicKey;
	BCRYPT_KEY_HANDLE   hPrivateKey;
} DKEY_KSP_KEY;

