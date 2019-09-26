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

// diamond-hsm_ksp_config.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "stdafx.h"

void RegisterProvider();
void UnRegisterProvider();
void EnumProviders();



///////////////////////////////////////////////
//
//   Forward declarations of local routines....
//
///////////////////////////////////////////////
static void
DisplayUsage(
    void
);

///////////////////////////////////////////////////////////////////////////////
//
// Main entry point...
//
///////////////////////////////////////////////////////////////////////////////
int __cdecl
wmain(
    __in int argc,
    __in_ecount(argc) PWSTR* argv)
{
    if (argc > 1)
    {
        if ((_wcsicmp(argv[1], L"-register") == 0))
        {
            // register by default
            RegisterProvider();
        }
        else if ((_wcsicmp(argv[1], L"-unregister") == 0))
        {
            UnRegisterProvider();
        }
        else if ((_wcsicmp(argv[1], L"-enum") == 0))
        {
            EnumProviders();
        }
        else
        {
            wprintf(L"Unrecognized command \"%s\"\n", argv[1]);
            DisplayUsage();
        }
    }
    else
    {
        DisplayUsage();
    }
    return 1;
}
///////////////////////////////////////////////////////////////////////////////

void
DisplayUsage()
{
    wprintf(L"Usage: diamond-hsm_ksp_config -enum | -register | -unregister\n");
    exit(1);
}
///////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////
//
// Headers...
//
/////////////////////////////////////////////////


// File name of sample key storage provider's binary. *NO* path.
//
#ifdef _WIN64
#define DKEY_KSP_BINARY       L"diamondhsm-cng-ksp_x64.dll"
#else
#define DKEY_KSP_BINARY       L"diamondhsm-cng-ksp_Win32.dll"
#endif

//
// An array of algorithm names, all belonging to the
// same algorithm class...
//
PWSTR AlgorithmNames[1] = {
    (wchar_t*)NCRYPT_KEY_STORAGE_ALGORITHM
};

//
// Definition of ONE class of algorithms supported
// by the provider...
//
CRYPT_INTERFACE_REG AlgorithmClass = {
    NCRYPT_KEY_STORAGE_INTERFACE,       // ncrypt key storage interface
    CRYPT_LOCAL,                        // Scope: local system only
    1,                                  // One algorithm in the class
    AlgorithmNames                      // The name(s) of the algorithm(s) in the class
};

//
// An array of ALL the algorithm classes supported
// by the provider...
//
PCRYPT_INTERFACE_REG AlgorithmClasses[1] = {
    &AlgorithmClass
};


//
// Definition of the provider's user-mode binary...
//
CRYPT_IMAGE_REG SampleKspImage = {
    (PWSTR)DKEY_KSP_BINARY,                   // File name of the sample KSP binary
    1,                                  // Number of algorithm classes the binary supports
    AlgorithmClasses                    // List of all algorithm classes available
};

//
// Definition of the overall provider...
//
CRYPT_PROVIDER_REG SampleKSPProvider = {
    0,
    NULL,
    &SampleKspImage,  // Image that provides user-mode support
    NULL              // Image that provides kernel-mode support (*MUST* be NULL)
};



void
EnumProviders()
{
    NTSTATUS ntStatus = STATUS_SUCCESS;

    DWORD cbBuffer = 0;
    PCRYPT_PROVIDERS pBuffer = NULL;
    DWORD i = 0;

    ntStatus = BCryptEnumRegisteredProviders(&cbBuffer, &pBuffer);

    if (NT_SUCCESS(ntStatus))
    {
        if (pBuffer == NULL)
        {
            wprintf(L"BCryptEnumRegisteredProviders returned a NULL ptr\n");
        }
        else
        {
            for (i = 0; i < pBuffer->cProviders; i++)
            {
                wprintf(L"%s\n", pBuffer->rgpszProviders[i]);
            }
        }
    }
    else
    {
        wprintf(L"BCryptEnumRegisteredProviders failed with error code 0x%08x\n", ntStatus);
    }

    if (pBuffer != NULL)
    {
        BCryptFreeBuffer(pBuffer);
    }
}
///////////////////////////////////////////////////////////////////////////////

void
RegisterProvider(
    void
)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;

    //
    // Make CNG aware that our provider
    // exists...
    //
    ntStatus = BCryptRegisterProvider(
        DKEY_KSP_PROVIDER_NAME,
        0,                          // Flags: fail if provider is already registered
        &SampleKSPProvider
    );
    if (!NT_SUCCESS(ntStatus))
    {
        wprintf(L"BCryptRegisterProvider failed with error code 0x%08x\n", ntStatus);
    }

    //
    // Add the algorithm name to the priority list of the
    // symmetric cipher algorithm class. (This makes it
    // visible to BCryptResolveProviders.)
    //
    ntStatus = BCryptAddContextFunction(
        _In_	CRYPT_LOCAL,                        // Scope: local machine only
        _In_	NULL,                               // Application context: default
        _In_	NCRYPT_KEY_STORAGE_INTERFACE,       // Algorithm class
        _In_	NCRYPT_KEY_STORAGE_ALGORITHM,       // Algorithm name
        _In_	CRYPT_PRIORITY_TOP               // Lowest priority
    );
    if (!NT_SUCCESS(ntStatus))
    {
        wprintf(L"BCryptAddContextFunction failed with error code 0x%08x\n", ntStatus);
    }

    //
    // Identify our new provider as someone who exposes
    // an implementation of the new algorithm.
    //
    ntStatus = BCryptAddContextFunctionProvider(
        CRYPT_LOCAL,                    // Scope: local machine only
        NULL,                           // Application context: default
        NCRYPT_KEY_STORAGE_INTERFACE,   // Algorithm class
        NCRYPT_KEY_STORAGE_ALGORITHM,   // Algorithm name
        DKEY_KSP_PROVIDER_NAME,        // Provider name
        CRYPT_PRIORITY_BOTTOM           // Lowest priority
    );
    if (!NT_SUCCESS(ntStatus))
    {
        wprintf(L"BCryptAddContextFunctionProvider failed with error code 0x%08x\n", ntStatus);
    }
}
///////////////////////////////////////////////////////////////////////////////

void
UnRegisterProvider()
{
    NTSTATUS ntStatus = STATUS_SUCCESS;

    //
    // Tell CNG that this provider no longer supports
    // this algorithm.
    //
    ntStatus = BCryptRemoveContextFunctionProvider(
        CRYPT_LOCAL,                    // Scope: local machine only
        NULL,                           // Application context: default
        NCRYPT_KEY_STORAGE_INTERFACE,   // Algorithm class
        NCRYPT_KEY_STORAGE_ALGORITHM,   // Algorithm name
        DKEY_KSP_PROVIDER_NAME         // Provider
    );
    if (!NT_SUCCESS(ntStatus))
    {
        wprintf(L"BCryptRemoveContextFunctionProvider failed with error code 0x%08x\n", ntStatus);
    }


    //
    // Tell CNG to forget about our provider component.
    //
    ntStatus = BCryptUnregisterProvider(DKEY_KSP_PROVIDER_NAME);
    if (!NT_SUCCESS(ntStatus))
    {
        wprintf(L"BCryptUnregisterProvider failed with error code 0x%08x\n", ntStatus);
    }
}
///////////////////////////////////////////////////////////////////////////////



