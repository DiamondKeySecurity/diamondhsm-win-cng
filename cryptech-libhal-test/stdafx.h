// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>

extern "C"
{
#include "hal.h"
#include "hal_internal.h"
#include "slip_internal.h"
#include "xdr_internal.h"
#include "test-ecdsa.h"
#include "test-rsa.h"
}
#include "rpc_client_tcp.h"
