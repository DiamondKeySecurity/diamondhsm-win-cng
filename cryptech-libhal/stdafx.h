// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <winsock.h>
#include <stdint.h>
#include <string.h>             /* memcpy, memset */
#include <winsock.h>
#include <memory>

#include "libressl-3.0.0/tls.h"

extern "C"
{
#include "hal.h"
#include "hal_internal.h"
#include "slip_internal.h"
#include "xdr_internal.h"
}
#include "rpc_client_tcp.h"



// TODO: reference additional headers your program requires here
