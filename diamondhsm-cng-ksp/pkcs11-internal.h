#pragma once

/*
* PKCS #11 objects.  These are pretty simple, as they're really just
* mappings from PKCS #11's naming scheme to libhal UUIDs, with a little
* extra fun for PKCS #11 "session" objects.
*/

typedef struct p11_object {
    CK_OBJECT_HANDLE  handle;             /* Object handle */
    CK_SESSION_HANDLE session;            /* Associated session (if any) */
    hal_uuid_t        uuid;               /* libhal key UUID */
} p11_object_t;

p11_object_t *p11_object_by_handle(const CK_OBJECT_HANDLE object_handle);

/*
* Compute the length of a signature based on the key.
*/

int get_signature_len(const hal_pkey_handle_t pkey, size_t *signature_len);
