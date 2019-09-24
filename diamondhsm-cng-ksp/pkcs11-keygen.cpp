/*
* Copyright 2019, Diamond Key Security, NFP
* Excerpts from pkcs11-keygen.c from the BIND9 source by
* Internet Systems Consortium, Inc. ("ISC")
* Used to generate CNG Key Storage Provider keys that
* are compatible with BIND
*/
/*
* Copyright (C) 2009, 2012, 2015 Internet Systems Consortium, Inc. ("ISC")
*
* Permission to use, copy, modify, and/or distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND ISC AND NETWORK ASSOCIATES DISCLAIMS
* ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE
* FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
* ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
* IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

/*
* Portions copyright (c) 2008 Nominet UK.  All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* pkcs11-keygen - PKCS#11 key generator
*
* Create a key in the keystore of an HSM
*
* The calculation of key tag is left to the script
* that converts the key into a DNSKEY RR and inserts
* it into a zone file.
*
* usage:
* pkcs11-keygen [-P] [-m module] [-s slot] [-e] [-b keysize]
*               [-i id] [-p pin] -l label
*
*/

/*! \file */
#include "stdafx.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

/* Define static key template values */
static CK_BBOOL truevalue = TRUE;
static CK_BBOOL falsevalue = FALSE;

/* Key class: RSA, ECC, ECX, or unknown */
typedef enum {
    key_unknown,
    key_rsa,
    key_ecc,
    key_ecx
} key_class_t;

/*
* Private key template: usable for most key classes without
* modificaton; override CKA_SIGN with CKA_DERIVE for DH
*/
#define PRIVATE_LABEL 0
#define PRIVATE_SIGN 1
#define PRIVATE_DERIVE 1
#define PRIVATE_TOKEN 2
#define PRIVATE_PRIVATE 3
#define PRIVATE_SENSITIVE 4
#define PRIVATE_EXTRACTABLE 5
#define PRIVATE_ID 6
#define PRIVATE_ATTRS 7
static CK_ATTRIBUTE private_template[] = {
    { CKA_LABEL, NULL_PTR, 0 },
{ CKA_SIGN, &truevalue, sizeof(truevalue) },
{ CKA_TOKEN, &truevalue, sizeof(truevalue) },
{ CKA_PRIVATE, &truevalue, sizeof(truevalue) },
{ CKA_SENSITIVE, &truevalue, sizeof(truevalue) },
{ CKA_EXTRACTABLE, &falsevalue, sizeof(falsevalue) },
{ CKA_ID, NULL_PTR, 0 }
};

/*
* Public key template for RSA keys
*/
#define RSA_LABEL 0
#define RSA_VERIFY 1
#define RSA_TOKEN 2
#define RSA_PRIVATE 3
#define RSA_MODULUS_BITS 4
#define RSA_PUBLIC_EXPONENT 5
#define RSA_ID 6
#define RSA_ATTRS 7
static CK_ATTRIBUTE rsa_template[] = {
    { CKA_LABEL, NULL_PTR, 0 },
{ CKA_VERIFY, &truevalue, sizeof(truevalue) },
{ CKA_TOKEN, &truevalue, sizeof(truevalue) },
{ CKA_PRIVATE, &falsevalue, sizeof(falsevalue) },
{ CKA_MODULUS_BITS, NULL_PTR, 0 },
{ CKA_PUBLIC_EXPONENT, NULL_PTR, 0 },
{ CKA_ID, NULL_PTR, 0 }
};

/*
* Public key template for ECC/ECX keys
*/
#define ECC_LABEL 0
#define ECC_VERIFY 1
#define ECC_TOKEN 2
#define ECC_PRIVATE 3
#define ECC_PARAMS 4
#define ECC_ID 5
#define ECC_ATTRS 6
static CK_ATTRIBUTE ecc_template[] = {
    { CKA_LABEL, NULL_PTR, 0 },
{ CKA_VERIFY, &truevalue, sizeof(truevalue) },
{ CKA_TOKEN, &truevalue, sizeof(truevalue) },
{ CKA_PRIVATE, &falsevalue, sizeof(falsevalue) },
{ CKA_EC_PARAMS, NULL_PTR, 0 },
{ CKA_ID, NULL_PTR, 0 }
};

/*
* Convert from text to key class.  Accepts the names of DNSSEC
* signing algorithms, so e.g., ECDSAP256SHA256 maps to ECC and
* NSEC3RSASHA1 maps to RSA.
*/
static key_class_t
keyclass_fromtext(const char *name) {
    if (name == NULL)
        return (key_unknown);

    if (_strnicmp(name, "rsa", 3) == 0 ||
        _strnicmp(name, "nsec3rsa", 8) == 0)
        return (key_rsa);
    else if (_strnicmp(name, "ecc", 3) == 0 ||
        _strnicmp(name, "ecdsa", 5) == 0)
        return (key_ecc);
    else if (_strnicmp(name, "ecx", 3) == 0 ||
        _strnicmp(name, "ed", 2) == 0)
        return (key_ecx);
    else
        return (key_unknown);
}

/*
* DoKeyGen
* This class was formerly int main() inside of pkcs11-keygen.c from ISC. It has been
* changed to a callable function that can be used to generate keys.
*/
CK_RV DoKeyGen(CK_SESSION_HANDLE hSession,
    char *algorithm,
    CK_ULONG bits,
    CK_CHAR *label,
    CK_ULONG expsize,
    CK_OBJECT_HANDLE_PTR phPublicKey,
    CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    CK_RV rv;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE privatekey, publickey;
    CK_BYTE exponent[5];
    int error = 0;
    int hide = 1, quiet = 0;
    int idlen = 0, id_offset = 0;
    unsigned long id = 0;
    CK_BYTE idbuf[4];
    CK_ULONG ulObjectCount;
    CK_ATTRIBUTE search_template[] = {
        { CKA_LABEL, NULL_PTR, 0 }
    };
    CK_ATTRIBUTE *public_template = NULL;
    CK_ULONG public_attrcnt = 0, private_attrcnt = PRIVATE_ATTRS;
    key_class_t keyclass = keyclass_fromtext(algorithm);

    if (label == NULL)
        return CKR_ARGUMENTS_BAD;

    if (expsize != 0 && keyclass != key_rsa)
        // "The -e option is only compatible with RSA key generation"
        return CKR_ARGUMENTS_BAD;
        

    switch (keyclass)
    {
        case key_rsa:
            if (expsize == 0)
                expsize = 3;
            if (bits == 0)
                return CKR_KEY_SIZE_RANGE;

            mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
            mech.pParameter = NULL;
            mech.ulParameterLen = 0;

            public_template = rsa_template;
            public_attrcnt = RSA_ATTRS;
            id_offset = RSA_ID;

            /* Set public exponent to F4 or F5 */
            exponent[0] = 0x01;
            exponent[1] = 0x00;
            if (expsize == 3)
                exponent[2] = 0x01;
            else {
                exponent[2] = 0x00;
                exponent[3] = 0x00;
                exponent[4] = 0x01;
            }

            public_template[RSA_MODULUS_BITS].pValue = &bits;
            public_template[RSA_MODULUS_BITS].ulValueLen = sizeof(bits);
            public_template[RSA_PUBLIC_EXPONENT].pValue = &exponent;
            public_template[RSA_PUBLIC_EXPONENT].ulValueLen = expsize;
            break;
        case key_ecc:
            if (bits == 0)
                bits = 256;
            else if (bits != 256 && bits != 384)
            {
                // "ECC keys only support bit sizes of 256, 384, and 521"
                return CKR_KEY_SIZE_RANGE;
            }

            mech.mechanism = CKM_EC_KEY_PAIR_GEN;
            mech.pParameter = NULL;
            mech.ulParameterLen = 0;

            public_template = ecc_template;
            public_attrcnt = ECC_ATTRS;
            id_offset = ECC_ID;

            if (bits == 256) {
                public_template[4].pValue = pk11_ecc_prime256v1;
                public_template[4].ulValueLen =
                    sizeof(pk11_ecc_prime256v1);
            }
            else {
                public_template[4].pValue = pk11_ecc_secp384r1;
                public_template[4].ulValueLen =
                    sizeof(pk11_ecc_secp384r1);
            }

            break;
        case key_ecx:
            // CKM_EDDSA_KEY_PAIR_GEN is not defined
            return CKR_ARGUMENTS_BAD;
        case key_unknown:
            return CKR_ARGUMENTS_BAD;
    }

    search_template[0].pValue = label;
    search_template[0].ulValueLen = strlen((char *)label);
    public_template[0].pValue = label;
    public_template[0].ulValueLen = strlen((char *)label);
    private_template[0].pValue = label;
    private_template[0].ulValueLen = strlen((char *)label);

    if (idlen == 0) {
        public_attrcnt--;
        private_attrcnt--;
    }
    else {
        if (id <= 0xffff) {
            idlen = 2;
            idbuf[0] = (CK_BYTE)(id >> 8);
            idbuf[1] = (CK_BYTE)id;
        }
        else {
            idbuf[0] = (CK_BYTE)(id >> 24);
            idbuf[1] = (CK_BYTE)(id >> 16);
            idbuf[2] = (CK_BYTE)(id >> 8);
            idbuf[3] = (CK_BYTE)id;
        }

        public_template[id_offset].pValue = idbuf;
        public_template[id_offset].ulValueLen = idlen;
        private_template[PRIVATE_ID].pValue = idbuf;
        private_template[PRIVATE_ID].ulValueLen = idlen;
    }

    /* check if a key with the same id already exists */
    rv = C_FindObjectsInit(hSession, search_template, 1);
    if (rv != CKR_OK) {
        // "C_FindObjectsInit: Error = 0x%.8lX\n", rv
        goto exit_session;
    }
    rv = C_FindObjects(hSession, &privatekey, 1, &ulObjectCount);
    if (rv != CKR_OK) {
        // "C_FindObjects: Error = 0x%.8lX\n", rv
        rv = CKR_ARGUMENTS_BAD;
        goto exit_search;
    }
    if (ulObjectCount != 0) {
        // "Key already exists.\n"
        rv = CKR_ARGUMENTS_BAD;
        goto exit_search;
    }

    /* Set attributes if the key is not to be hidden */
    if (!hide) {
        private_template[4].pValue = &falsevalue;
        private_template[5].pValue = &truevalue;
    }

    /* Generate Key pair for signing/verifying */
    rv = C_GenerateKeyPair(hSession, &mech,
        public_template, public_attrcnt,
        private_template, private_attrcnt,
        &publickey, &privatekey);

exit_search:
    C_FindObjectsFinal(hSession);

exit_session:
    return rv;
}