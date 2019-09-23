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

LPCSTR DKEYKspGetUserPin()
{
	return "1234";
}

LPCSTR DKEYKspGetHostAddr()
{
	return "10.1.10.9";
}

DWORD DKEYRSAKeyLen()
{
    return 2048;
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