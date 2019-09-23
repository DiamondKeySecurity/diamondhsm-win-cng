#pragma once
/*
* This file was generated automatically from attributes.yaml by build-attributes.  Do not edit this file directly.
*/

typedef struct {
    CK_ATTRIBUTE_TYPE type;
    CK_ULONG size;                        /* Size in bytes if this is a fixed-length attribute */
    CK_ULONG length;                      /* Length in bytes of the object to which value points */
    const void *value;                    /* Default or constant depending on P11_DESCRIPTOR_DEFAULT_VALUE */
    unsigned long flags;                  /* (NULL value with P11_DESCRIPTOR_DEFAULT_VALUE means zero length default */
} p11_attribute_descriptor_t;

typedef struct {
    const p11_attribute_descriptor_t *attributes;
    CK_ULONG n_attributes;
} p11_descriptor_t;

typedef struct {
    CK_OBJECT_CLASS object_class;
    CK_KEY_TYPE key_type;
    const p11_descriptor_t *descriptor;
} p11_descriptor_keyclass_map_t;

#define P11_DESCRIPTOR_DEFAULT_VALUE                0x00000001  /* Value field contains default */
#define P11_DESCRIPTOR_REQUIRED_BY_CREATEOBJECT     0x00000002  /* Section 10.2 table 15 footnote # 1 */
#define P11_DESCRIPTOR_FORBIDDEN_BY_CREATEOBJECT    0x00000004  /* Section 10.2 table 15 footnote # 2 */
#define P11_DESCRIPTOR_REQUIRED_BY_GENERATE         0x00000008  /* Section 10.2 table 15 footnote # 3 */
#define P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE        0x00000010  /* Section 10.2 table 15 footnote # 4 */
#define P11_DESCRIPTOR_REQUIRED_BY_UNWRAP           0x00000020  /* Section 10.2 table 15 footnote # 5 */
#define P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP          0x00000040  /* Section 10.2 table 15 footnote # 6 */
#define P11_DESCRIPTOR_SENSITIVE                    0x00000080  /* Section 10.2 table 15 footnote # 7 */
#define P11_DESCRIPTOR_PERHAPS_MODIFIABLE           0x00000100  /* Section 10.2 table 15 footnote # 8 */
#define P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC    0x00000200  /* Section 10.2 table 15 footnote # 9 */
#define P11_DESCRIPTOR_ONLY_SO_USER_CAN_SET         0x00000400  /* Section 10.2 table 15 footnote #10 */
#define P11_DESCRIPTOR_LATCHES_WHEN_TRUE            0x00000800  /* Section 10.2 table 15 footnote #11 */
#define P11_DESCRIPTOR_LATCHES_WHEN_FALSE           0x00001000  /* Section 10.2 table 15 footnote #12 */

static const CK_BBOOL const_CK_FALSE = CK_FALSE;
static const CK_BBOOL const_CK_TRUE = CK_TRUE;
static const CK_BYTE const_0x010001[] = { 0x01, 0x00, 0x01 };
static const CK_KEY_TYPE const_CKK_EC = CKK_EC;
static const CK_KEY_TYPE const_CKK_RSA = CKK_RSA;
static const CK_MECHANISM_TYPE const_CK_UNAVAILABLE_INFORMATION = CK_UNAVAILABLE_INFORMATION;
static const CK_OBJECT_CLASS const_CKO_PRIVATE_KEY = CKO_PRIVATE_KEY;
static const CK_OBJECT_CLASS const_CKO_PUBLIC_KEY = CKO_PUBLIC_KEY;

static const p11_attribute_descriptor_t p11_attribute_descriptor_rsa_public_key[] = {
    { CKA_CLASS, sizeof(CK_OBJECT_CLASS), sizeof(CK_OBJECT_CLASS), &const_CKO_PUBLIC_KEY, P11_DESCRIPTOR_REQUIRED_BY_CREATEOBJECT },
{ CKA_TOKEN, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_PRIVATE, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_TRUE, P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_LABEL, 0, 0, NULL_PTR, P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_TRUSTED, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_ONLY_SO_USER_CAN_SET | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_KEY_TYPE, sizeof(CK_KEY_TYPE), sizeof(CK_KEY_TYPE), &const_CKK_RSA, P11_DESCRIPTOR_REQUIRED_BY_CREATEOBJECT | P11_DESCRIPTOR_REQUIRED_BY_UNWRAP },
{ CKA_SUBJECT, 0, 0, NULL_PTR, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_ID, 0, 0, NULL_PTR, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_ENCRYPT, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_WRAP, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_VERIFY, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_VERIFY_RECOVER, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_DERIVE, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_START_DATE, sizeof(CK_DATE), 0, NULL_PTR, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_END_DATE, sizeof(CK_DATE), 0, NULL_PTR, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_MODULUS, 0, 0, NULL_PTR, P11_DESCRIPTOR_REQUIRED_BY_CREATEOBJECT | P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE },
{ CKA_MODULUS_BITS, sizeof(CK_ULONG), 0, NULL_PTR, P11_DESCRIPTOR_FORBIDDEN_BY_CREATEOBJECT | P11_DESCRIPTOR_REQUIRED_BY_GENERATE },
{ CKA_PUBLIC_EXPONENT, 0, sizeof(const_0x010001), const_0x010001, P11_DESCRIPTOR_REQUIRED_BY_CREATEOBJECT },
{ CKA_LOCAL, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_FORBIDDEN_BY_CREATEOBJECT | P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_KEY_GEN_MECHANISM, sizeof(CK_MECHANISM_TYPE), sizeof(CK_MECHANISM_TYPE), &const_CK_UNAVAILABLE_INFORMATION, P11_DESCRIPTOR_FORBIDDEN_BY_CREATEOBJECT | P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_MODIFIABLE, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_TRUE, P11_DESCRIPTOR_DEFAULT_VALUE },
};

static const p11_descriptor_t p11_descriptor_rsa_public_key = {
    p11_attribute_descriptor_rsa_public_key,
    sizeof(p11_attribute_descriptor_rsa_public_key) / sizeof(p11_attribute_descriptor_t)
};

static const p11_attribute_descriptor_t p11_attribute_descriptor_rsa_private_key[] = {
    { CKA_CLASS, sizeof(CK_OBJECT_CLASS), sizeof(CK_OBJECT_CLASS), &const_CKO_PRIVATE_KEY, P11_DESCRIPTOR_REQUIRED_BY_CREATEOBJECT },
{ CKA_TOKEN, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_PRIVATE, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_TRUE, P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_LABEL, 0, 0, NULL_PTR, P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_KEY_TYPE, sizeof(CK_KEY_TYPE), sizeof(CK_KEY_TYPE), &const_CKK_RSA, P11_DESCRIPTOR_REQUIRED_BY_CREATEOBJECT | P11_DESCRIPTOR_REQUIRED_BY_UNWRAP },
{ CKA_SUBJECT, 0, 0, NULL_PTR, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_ID, 0, 0, NULL_PTR, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_SENSITIVE, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_TRUE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC | P11_DESCRIPTOR_LATCHES_WHEN_TRUE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_DECRYPT, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_UNWRAP, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_SIGN, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_SIGN_RECOVER, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_DERIVE, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_START_DATE, sizeof(CK_DATE), 0, NULL_PTR, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_END_DATE, sizeof(CK_DATE), 0, NULL_PTR, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_MODULUS, 0, 0, NULL_PTR, P11_DESCRIPTOR_REQUIRED_BY_CREATEOBJECT | P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP },
{ CKA_PUBLIC_EXPONENT, 0, sizeof(const_0x010001), const_0x010001, P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP },
{ CKA_PRIVATE_EXPONENT, 0, 0, NULL_PTR, P11_DESCRIPTOR_REQUIRED_BY_CREATEOBJECT | P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP | P11_DESCRIPTOR_SENSITIVE },
{ CKA_PRIME_1, 0, 0, NULL_PTR, P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP | P11_DESCRIPTOR_SENSITIVE },
{ CKA_PRIME_2, 0, 0, NULL_PTR, P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP | P11_DESCRIPTOR_SENSITIVE },
{ CKA_EXPONENT_1, 0, 0, NULL_PTR, P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP | P11_DESCRIPTOR_SENSITIVE },
{ CKA_EXPONENT_2, 0, 0, NULL_PTR, P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP | P11_DESCRIPTOR_SENSITIVE },
{ CKA_COEFFICIENT, 0, 0, NULL_PTR, P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP | P11_DESCRIPTOR_SENSITIVE },
{ CKA_EXTRACTABLE, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC | P11_DESCRIPTOR_LATCHES_WHEN_FALSE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_LOCAL, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_FORBIDDEN_BY_CREATEOBJECT | P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_NEVER_EXTRACTABLE, sizeof(CK_BBOOL), 0, NULL_PTR, P11_DESCRIPTOR_FORBIDDEN_BY_CREATEOBJECT | P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP },
{ CKA_ALWAYS_SENSITIVE, sizeof(CK_BBOOL), 0, NULL_PTR, P11_DESCRIPTOR_FORBIDDEN_BY_CREATEOBJECT | P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP },
{ CKA_KEY_GEN_MECHANISM, sizeof(CK_MECHANISM_TYPE), sizeof(CK_MECHANISM_TYPE), &const_CK_UNAVAILABLE_INFORMATION, P11_DESCRIPTOR_FORBIDDEN_BY_CREATEOBJECT | P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_MODIFIABLE, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_TRUE, P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_WRAP_WITH_TRUSTED, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_LATCHES_WHEN_TRUE | P11_DESCRIPTOR_DEFAULT_VALUE },
};

static const p11_descriptor_t p11_descriptor_rsa_private_key = {
    p11_attribute_descriptor_rsa_private_key,
    sizeof(p11_attribute_descriptor_rsa_private_key) / sizeof(p11_attribute_descriptor_t)
};

static const p11_attribute_descriptor_t p11_attribute_descriptor_ec_public_key[] = {
    { CKA_CLASS, sizeof(CK_OBJECT_CLASS), sizeof(CK_OBJECT_CLASS), &const_CKO_PUBLIC_KEY, P11_DESCRIPTOR_REQUIRED_BY_CREATEOBJECT },
{ CKA_TOKEN, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_PRIVATE, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_TRUE, P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_LABEL, 0, 0, NULL_PTR, P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_TRUSTED, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_ONLY_SO_USER_CAN_SET | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_KEY_TYPE, sizeof(CK_KEY_TYPE), sizeof(CK_KEY_TYPE), &const_CKK_EC, P11_DESCRIPTOR_REQUIRED_BY_CREATEOBJECT | P11_DESCRIPTOR_REQUIRED_BY_UNWRAP },
{ CKA_SUBJECT, 0, 0, NULL_PTR, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_ID, 0, 0, NULL_PTR, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_ENCRYPT, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_WRAP, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_VERIFY, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_VERIFY_RECOVER, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_DERIVE, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_START_DATE, sizeof(CK_DATE), 0, NULL_PTR, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_END_DATE, sizeof(CK_DATE), 0, NULL_PTR, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_LOCAL, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_FORBIDDEN_BY_CREATEOBJECT | P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_KEY_GEN_MECHANISM, sizeof(CK_MECHANISM_TYPE), sizeof(CK_MECHANISM_TYPE), &const_CK_UNAVAILABLE_INFORMATION, P11_DESCRIPTOR_FORBIDDEN_BY_CREATEOBJECT | P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_MODIFIABLE, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_TRUE, P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_EC_PARAMS, 0, 0, NULL_PTR, P11_DESCRIPTOR_REQUIRED_BY_CREATEOBJECT | P11_DESCRIPTOR_REQUIRED_BY_GENERATE },
{ CKA_EC_POINT, 0, 0, NULL_PTR, P11_DESCRIPTOR_REQUIRED_BY_CREATEOBJECT | P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE },
};

static const p11_descriptor_t p11_descriptor_ec_public_key = {
    p11_attribute_descriptor_ec_public_key,
    sizeof(p11_attribute_descriptor_ec_public_key) / sizeof(p11_attribute_descriptor_t)
};

static const p11_attribute_descriptor_t p11_attribute_descriptor_ec_private_key[] = {
    { CKA_CLASS, sizeof(CK_OBJECT_CLASS), sizeof(CK_OBJECT_CLASS), &const_CKO_PRIVATE_KEY, P11_DESCRIPTOR_REQUIRED_BY_CREATEOBJECT },
{ CKA_TOKEN, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_PRIVATE, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_TRUE, P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_LABEL, 0, 0, NULL_PTR, P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_VALUE, 0, 0, NULL_PTR, P11_DESCRIPTOR_REQUIRED_BY_CREATEOBJECT | P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP | P11_DESCRIPTOR_SENSITIVE },
{ CKA_KEY_TYPE, sizeof(CK_KEY_TYPE), sizeof(CK_KEY_TYPE), &const_CKK_EC, P11_DESCRIPTOR_REQUIRED_BY_CREATEOBJECT | P11_DESCRIPTOR_REQUIRED_BY_UNWRAP },
{ CKA_SUBJECT, 0, 0, NULL_PTR, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_ID, 0, 0, NULL_PTR, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_SENSITIVE, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_TRUE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC | P11_DESCRIPTOR_LATCHES_WHEN_TRUE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_DECRYPT, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_UNWRAP, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_SIGN, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_SIGN_RECOVER, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_DERIVE, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_START_DATE, sizeof(CK_DATE), 0, NULL_PTR, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_END_DATE, sizeof(CK_DATE), 0, NULL_PTR, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_EXTRACTABLE, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_PERHAPS_MODIFIABLE | P11_DESCRIPTOR_DEFAULT_IS_TOKEN_SPECIFIC | P11_DESCRIPTOR_LATCHES_WHEN_FALSE | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_LOCAL, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_FORBIDDEN_BY_CREATEOBJECT | P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_NEVER_EXTRACTABLE, sizeof(CK_BBOOL), 0, NULL_PTR, P11_DESCRIPTOR_FORBIDDEN_BY_CREATEOBJECT | P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP },
{ CKA_ALWAYS_SENSITIVE, sizeof(CK_BBOOL), 0, NULL_PTR, P11_DESCRIPTOR_FORBIDDEN_BY_CREATEOBJECT | P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP },
{ CKA_KEY_GEN_MECHANISM, sizeof(CK_MECHANISM_TYPE), sizeof(CK_MECHANISM_TYPE), &const_CK_UNAVAILABLE_INFORMATION, P11_DESCRIPTOR_FORBIDDEN_BY_CREATEOBJECT | P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP | P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_MODIFIABLE, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_TRUE, P11_DESCRIPTOR_DEFAULT_VALUE },
{ CKA_EC_PARAMS, 0, 0, NULL_PTR, P11_DESCRIPTOR_REQUIRED_BY_CREATEOBJECT | P11_DESCRIPTOR_FORBIDDEN_BY_GENERATE | P11_DESCRIPTOR_FORBIDDEN_BY_UNWRAP },
{ CKA_WRAP_WITH_TRUSTED, sizeof(CK_BBOOL), sizeof(CK_BBOOL), &const_CK_FALSE, P11_DESCRIPTOR_LATCHES_WHEN_TRUE | P11_DESCRIPTOR_DEFAULT_VALUE },
};

static const p11_descriptor_t p11_descriptor_ec_private_key = {
    p11_attribute_descriptor_ec_private_key,
    sizeof(p11_attribute_descriptor_ec_private_key) / sizeof(p11_attribute_descriptor_t)
};

static const p11_descriptor_keyclass_map_t p11_descriptor_keyclass_map[] = {
    { CKO_PUBLIC_KEY, CKK_RSA, &p11_descriptor_rsa_public_key },
{ CKO_PRIVATE_KEY, CKK_RSA, &p11_descriptor_rsa_private_key },
{ CKO_PUBLIC_KEY, CKK_EC, &p11_descriptor_ec_public_key },
{ CKO_PRIVATE_KEY, CKK_EC, &p11_descriptor_ec_private_key },
};

