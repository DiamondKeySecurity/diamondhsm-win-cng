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
#include "stdafx.h"

#include "internal.h"
#include "pkcs11.h"

LPCSTR DKEYKspGetUserPin(char *buffer, const size_t buffer_len)
{
    WCHAR regbuffer[128];
    DWORD cbBuffer = sizeof(regbuffer), ret;
    size_t num_converted;
    ret = RegGetValue(HKEY_CURRENT_USER, DKEY_KSP_REGISTRY_KEY, DKEY_KSP_REGISTRY_PIN, RRF_RT_REG_SZ, NULL, regbuffer, &cbBuffer);
    if (ret != ERROR_SUCCESS) return NULL;

    wcstombs_s(&num_converted, buffer, buffer_len, regbuffer, buffer_len);

    return buffer;
}

LPCSTR DKEYKspGetHostAddr(char *buffer, const size_t buffer_len)
{
    WCHAR regbuffer[128];
    DWORD cbBuffer = sizeof(regbuffer), ret;
    size_t num_converted;
    ret = RegGetValue(HKEY_CURRENT_USER, DKEY_KSP_REGISTRY_KEY, DKEY_KSP_REGISTRY_IPADDR, RRF_RT_REG_SZ, NULL, regbuffer, &cbBuffer);
    if (ret != ERROR_SUCCESS) return NULL;

    wcstombs_s(&num_converted, buffer, buffer_len, regbuffer, buffer_len);

    return buffer;
}

DWORD DKEYRSAKeyLen()
{
    return 1024;
}

// buffer must be at least 40 characters
char *uuid_to_string(hal_uuid_t uuid, char *buffer, size_t buffer_count)
{
    // sorry for implementing this this way, but it was so easy.
    sprintf_s(buffer, buffer_count, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        (unsigned int)uuid.uuid[0],
        (unsigned int)uuid.uuid[1],
        (unsigned int)uuid.uuid[2],
        (unsigned int)uuid.uuid[3],
        (unsigned int)uuid.uuid[4],
        (unsigned int)uuid.uuid[5],
        (unsigned int)uuid.uuid[6],
        (unsigned int)uuid.uuid[7],
        (unsigned int)uuid.uuid[8],
        (unsigned int)uuid.uuid[9],
        (unsigned int)uuid.uuid[10],
        (unsigned int)uuid.uuid[11],
        (unsigned int)uuid.uuid[12],
        (unsigned int)uuid.uuid[13],
        (unsigned int)uuid.uuid[14],
        (unsigned int)uuid.uuid[15]
    );

    return buffer;
}

SECURITY_STATUS ConnectToHSM(hal_client_handle_t client)
{
    SECURITY_STATUS status = ERROR_SUCCESS;
    BOOL transport_open = FALSE;

    // USE PKCS #11 function to connect to HSM
    CK_C_INITIALIZE_ARGS pkcs11_init_args;
    ZeroMemory(&pkcs11_init_args, sizeof(CK_C_INITIALIZE_ARGS));
    pkcs11_init_args.flags = CKF_OS_LOCKING_OK;

    CK_RV result = C_Initialize(&pkcs11_init_args);
    if (result != CKR_OK)
    {
        status = NTE_DEVICE_NOT_FOUND;
        goto cleanup;
    }
    else
    {
        transport_open = TRUE;
    }

cleanup:
    if (status != ERROR_SUCCESS &&
        transport_open == TRUE)
    {
        CloseConnectionToHSM();
    }
    return status;
}

void CloseConnectionToHSM()
{
    // Disconnect PKCS #11
    C_Finalize(NULL);
}