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
#pragma once

#include "diamondhsm-cng-ksp.h"
#include "diamondhsm-ksp.h"
#include "../cryptech-libhal/hal.h"

struct KeyMatchData
{
    // list of all keys found on the last request to the HSM
    hal_uuid_t uuid_list[MAX_CRYPTECH_UUIDS_IN_KEYMATCH];

    // the actual number of keys found
    uint32_t   num_keys_found;

    // the current key
    uint32_t   current_key;

    // the very first key found
    hal_uuid_t first_uuid;

    // state variable used by key_match
    uint32_t state;
};

LPCSTR DKEYKspGetUserPin();
LPCSTR DKEYKspGetHostAddr();

SECURITY_STATUS NormalizeNteStatus(__in NTSTATUS NtStatus);

DKEY_KSP_PROVIDER *DKEYKspValidateProvHandle(
	__in    NCRYPT_PROV_HANDLE hProvider);

DKEY_KSP_KEY *DKEYKspValidateKeyHandle(
	__in    NCRYPT_KEY_HANDLE hKey);

// buffer must be at least 40 characters
char *uuid_to_string(hal_uuid_t uuid, char *buffer, size_t buffer_count);

SECURITY_STATUS ConnectToHSM(hal_client_handle_t client);
void CloseConnectionToHSM();
