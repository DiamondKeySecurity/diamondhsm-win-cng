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

// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

/*
* Magic PKCS #11 macros that must be defined before including
* pkcs11.h.  For now these are only the Unix versions, add others
* later (which may require minor refactoring).
*/

#define CK_PTR                                          *
#define CK_DEFINE_FUNCTION(returnType, name)            returnType name
#define CK_DECLARE_FUNCTION(returnType, name)           returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name)   returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name)          returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR                                        NULL
#endif



#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>

#include <bcrypt.h>
#include <bcrypt_provider.h>
#include <cardmod.h>
//#include <cspdk.h>
#include <msclmd.h>
#include <ncrypt.h>
#include <ncrypt_provider.h>
#include <sslprovider.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <memory>

#include "pkcs11-types.h"

// cryptech-libhal
extern "C"
{
#include "tfm.h"

#include "../cryptech-libhal/hal.h"
#include "../cryptech-libhal/hal_internal.h"

#include "asn1_internal.h"
#include "pkcs11.h"
#include "pkcs11-attributes.h"
#include "constants.h"
#include "pkcs11-internal.h"
}
