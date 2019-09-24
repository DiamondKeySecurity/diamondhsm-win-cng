// Extracted from rsa.c
/*
* rsa.c
* -----
* Basic RSA functions based on Cryptech ModExp core.
*
* The mix of what we're doing in software vs what we're doing on the
* FPGA is a moving target.  Goal for now is to have the bits we need
* to do in C be straightforward to review and as simple as possible
* (but no simpler).
*
* Much of the code in this module is based, at least loosely, on Tom
* St Denis's libtomcrypt code.
*
* Authors: Rob Austein
* Copyright (c) 2015-2018, NORDUnet A/S
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
* - Redistributions of source code must retain the above copyright notice,
*   this list of conditions and the following disclaimer.
*
* - Redistributions in binary form must reproduce the above copyright
*   notice, this list of conditions and the following disclaimer in the
*   documentation and/or other materials provided with the distribution.
*
* - Neither the name of the NORDUnet nor the names of its contributors may
*   be used to endorse or promote products derived from this software
*   without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
* IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
* TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
* PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
* TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
* PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
* We use "Tom's Fast Math" library for our bignum implementation.
* This particular implementation has a couple of nice features:
*
* - The code is relatively readable, thus reviewable.
*
* - The bignum representation doesn't use dynamic memory, which
*   simplifies things for us.
*
* The price tag for not using dynamic memory is that libtfm has to be
* configured to know about the largest bignum one wants it to be able
* to support at compile time.  This should not be a serious problem.
*
* We use a lot of one-element arrays (fp_int[1] instead of plain
* fp_int) to avoid having to prefix every use of an fp_int with "&".
* Perhaps we should encapsulate this idiom in a typedef.
*
* Unfortunately, libtfm is bad about const-ification, but we want to
* hide that from our users, so our public API uses const as
* appropriate and we use inline functions to remove const constraints
* in a relatively type-safe manner before calling libtom.
*/
#include "stdafx.h"

#define MODEXPA7_OPERAND_BITS                   (4096)
#define MODEXPA7_OPERAND_BYTES                  (MODEXPA7_OPERAND_BITS /  8)
#define MODEXPA7_OPERAND_WORDS                  (MODEXPA7_OPERAND_BITS / 32)
#define MODEXPA7_ADDR_REGISTERS                 (0 * MODEXPA7_OPERAND_WORDS)

/*
* How big to make the buffers for the modulus coefficient and
* Montgomery factor.  This will almost certainly want tuning.
*/

#ifndef HAL_RSA_MAX_OPERAND_LENGTH
#define HAL_RSA_MAX_OPERAND_LENGTH MODEXPA7_OPERAND_BYTES
#endif

extern "C"
{
    /*
    * RSA key implementation.  This structure type is private to this
    * module, anything else that needs to touch one of these just gets a
    * typed opaque pointer.  We do, however, export the size, so that we
    * can make memory allocation the caller's problem.
    */

    struct hal_rsa_key {
        hal_key_type_t type;          /* What kind of key this is */
        fp_int n[1];                  /* The modulus */
        fp_int e[1];                  /* Public exponent */
        fp_int d[1];                  /* Private exponent */
        fp_int p[1];                  /* 1st prime factor */
        fp_int q[1];                  /* 2nd prime factor */
        fp_int u[1];                  /* 1/q mod p */
        fp_int dP[1];                 /* d mod (p - 1) */
        fp_int dQ[1];                 /* d mod (q - 1) */
        unsigned flags;               /* Internal key flags */
        uint8_t                       /* ModExpA7 speedup factors */
            nC[HAL_RSA_MAX_OPERAND_LENGTH], nF[HAL_RSA_MAX_OPERAND_LENGTH],
            pC[HAL_RSA_MAX_OPERAND_LENGTH / 2], pF[HAL_RSA_MAX_OPERAND_LENGTH / 2],
            qC[HAL_RSA_MAX_OPERAND_LENGTH / 2], qF[HAL_RSA_MAX_OPERAND_LENGTH / 2];
    };

    const size_t hal_rsa_key_t_size = sizeof(hal_rsa_key_t);
}

/*
* Extract public key components.
*/

static hal_error_t extract_component(const hal_rsa_key_t * const key,
    const size_t offset,
    uint8_t *res, size_t *res_len, const size_t res_max)
{
    if (key == NULL)
        return HAL_ERROR_BAD_ARGUMENTS;

    const fp_int * const bn = (const fp_int *)(((const uint8_t *)key) + offset);

    const size_t len = fp_unsigned_bin_size(unconst_fp_int(bn));

    if (res_len != NULL)
        *res_len = len;

    if (res == NULL)
        return HAL_OK;

    if (len > res_max)
        return HAL_ERROR_RESULT_TOO_LONG;

    memset(res, 0, res_max);
    fp_to_unsigned_bin(unconst_fp_int(bn), res);
    return HAL_OK;
}

hal_error_t hal_rsa_key_get_modulus(const hal_rsa_key_t * const key,
    uint8_t *res, size_t *res_len, const size_t res_max)
{
    return extract_component(key, offsetof(hal_rsa_key_t, n), res, res_len, res_max);
}

hal_error_t hal_rsa_key_get_public_exponent(const hal_rsa_key_t * const key,
    uint8_t *res, size_t *res_len, const size_t res_max)
{
    return extract_component(key, offsetof(hal_rsa_key_t, e), res, res_len, res_max);
}

hal_error_t hal_rsa_public_key_from_der(hal_rsa_key_t **key_,
    void *keybuf, const size_t keybuf_len,
    const uint8_t * const der, const size_t der_len)
{
    hal_rsa_key_t *key = (hal_rsa_key_t *)keybuf;

    if (key_ == NULL || key == NULL || keybuf_len < sizeof(*key) || der == NULL)
        return HAL_ERROR_BAD_ARGUMENTS;

    memset(keybuf, 0, keybuf_len);

    key->type = HAL_KEY_TYPE_RSA_PUBLIC;

    const uint8_t *alg_oid = NULL, *null = NULL, *pubkey = NULL;
    size_t         alg_oid_len, null_len, pubkey_len;
    hal_error_t err;

    if ((err = hal_asn1_decode_spki(&alg_oid, &alg_oid_len, &null, &null_len, &pubkey, &pubkey_len, der, der_len)) != HAL_OK)
        return err;

    if (null != NULL || null_len != 0 || alg_oid == NULL ||
        alg_oid_len != hal_asn1_oid_rsaEncryption_len || memcmp(alg_oid, hal_asn1_oid_rsaEncryption, alg_oid_len) != 0)
        return HAL_ERROR_ASN1_PARSE_FAILED;

    size_t len, hlen, vlen;

    if ((err = hal_asn1_decode_header(ASN1_SEQUENCE, pubkey, pubkey_len, &hlen, &vlen)) != HAL_OK)
        return err;

    const uint8_t * const pubkey_end = pubkey + hlen + vlen;
    const uint8_t *d = pubkey + hlen;

    if ((err = hal_asn1_decode_integer(key->n, d, &len, pubkey_end - d)) != HAL_OK)
        return err;
    d += len;

    if ((err = hal_asn1_decode_integer(key->e, d, &len, pubkey_end - d)) != HAL_OK)
        return err;
    d += len;

    if (d != pubkey_end)
        return HAL_ERROR_ASN1_PARSE_FAILED;

    *key_ = key;

    return HAL_OK;
}
