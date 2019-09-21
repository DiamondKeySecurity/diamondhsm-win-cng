// Copyright 2019 Diamond Key Security, NFP

/* pkcs11t.h include file for PKCS #11 V 2.30 - draft 1 */

/* License to copy and use this software is granted provided that it is
* identified as "RSA Security Inc. PKCS #11 Cryptographic Token Interface
* (Cryptoki)" in all material mentioning or referencing this software.

* License is also granted to make and use derivative works provided that
* such works are identified as "derived from the RSA Security Inc. PKCS #11
* Cryptographic Token Interface (Cryptoki)" in all material mentioning or
* referencing the derived work.

* RSA Security Inc. makes no representations concerning either the
* merchantability of this software or the suitability of this software for
* any particular purpose. It is provided "as is" without express or implied
* warranty of any kind.
*/

/* See top of pkcs11.h for information about the macros that
* must be defined and the structure-packing conventions that
* must be set before including this file. */
#pragma once

/* The following attribute types are defined: */
#define CKA_CLASS              0x00000000
#define CKA_TOKEN              0x00000001
#define CKA_PRIVATE            0x00000002
#define CKA_LABEL              0x00000003
#define CKA_APPLICATION        0x00000010
#define CKA_VALUE              0x00000011
#define CKA_OBJECT_ID          0x00000012
#define CKA_CERTIFICATE_TYPE   0x00000080
#define CKA_ISSUER             0x00000081
#define CKA_SERIAL_NUMBER      0x00000082
#define CKA_AC_ISSUER          0x00000083
#define CKA_OWNER              0x00000084
#define CKA_ATTR_TYPES         0x00000085
#define CKA_TRUSTED            0x00000086
#define CKA_CERTIFICATE_CATEGORY        0x00000087
#define CKA_JAVA_MIDP_SECURITY_DOMAIN   0x00000088
#define CKA_URL                         0x00000089
#define CKA_HASH_OF_SUBJECT_PUBLIC_KEY  0x0000008A
#define CKA_HASH_OF_ISSUER_PUBLIC_KEY   0x0000008B
#define CKA_CHECK_VALUE                 0x00000090

#define CKA_KEY_TYPE           0x00000100
#define CKA_SUBJECT            0x00000101
#define CKA_ID                 0x00000102
#define CKA_SENSITIVE          0x00000103
#define CKA_ENCRYPT            0x00000104
#define CKA_DECRYPT            0x00000105
#define CKA_WRAP               0x00000106
#define CKA_UNWRAP             0x00000107
#define CKA_SIGN               0x00000108
#define CKA_SIGN_RECOVER       0x00000109
#define CKA_VERIFY             0x0000010A
#define CKA_VERIFY_RECOVER     0x0000010B
#define CKA_DERIVE             0x0000010C
#define CKA_START_DATE         0x00000110
#define CKA_END_DATE           0x00000111
#define CKA_MODULUS            0x00000120
#define CKA_MODULUS_BITS       0x00000121
#define CKA_PUBLIC_EXPONENT    0x00000122
#define CKA_PRIVATE_EXPONENT   0x00000123
#define CKA_PRIME_1            0x00000124
#define CKA_PRIME_2            0x00000125
#define CKA_EXPONENT_1         0x00000126
#define CKA_EXPONENT_2         0x00000127
#define CKA_COEFFICIENT        0x00000128
#define CKA_PRIME              0x00000130
#define CKA_SUBPRIME           0x00000131
#define CKA_BASE               0x00000132

#define CKA_PRIME_BITS         0x00000133
#define CKA_SUBPRIME_BITS      0x00000134
/* (To retain backwards-compatibility) */
#define CKA_SUB_PRIME_BITS     CKA_SUBPRIME_BITS

#define CKA_VALUE_BITS         0x00000160
#define CKA_VALUE_LEN          0x00000161
#define CKA_EXTRACTABLE        0x00000162
#define CKA_LOCAL              0x00000163
#define CKA_NEVER_EXTRACTABLE  0x00000164
#define CKA_ALWAYS_SENSITIVE   0x00000165
#define CKA_KEY_GEN_MECHANISM  0x00000166

#define CKA_MODIFIABLE         0x00000170

/* CKA_ECDSA_PARAMS is deprecated in v2.11,
* CKA_EC_PARAMS is preferred. */
#define CKA_ECDSA_PARAMS       0x00000180
#define CKA_EC_PARAMS          0x00000180

#define CKA_EC_POINT           0x00000181

/* CKA_SECONDARY_AUTH, CKA_AUTH_PIN_FLAGS,
* are new for v2.10. Deprecated in v2.11 and onwards. */
#define CKA_SECONDARY_AUTH     0x00000200
#define CKA_AUTH_PIN_FLAGS     0x00000201

#define CKA_ALWAYS_AUTHENTICATE  0x00000202

#define CKA_WRAP_WITH_TRUSTED    0x00000210
#define CKA_WRAP_TEMPLATE        (CKF_ARRAY_ATTRIBUTE|0x00000211)
#define CKA_UNWRAP_TEMPLATE      (CKF_ARRAY_ATTRIBUTE|0x00000212)
#define CKA_DERIVE_TEMPLATE      (CKF_ARRAY_ATTRIBUTE|0x00000213)

#define CKA_OTP_FORMAT                0x00000220
#define CKA_OTP_LENGTH                0x00000221
#define CKA_OTP_TIME_INTERVAL         0x00000222
#define CKA_OTP_USER_FRIENDLY_MODE    0x00000223
#define CKA_OTP_CHALLENGE_REQUIREMENT 0x00000224
#define CKA_OTP_TIME_REQUIREMENT      0x00000225
#define CKA_OTP_COUNTER_REQUIREMENT   0x00000226
#define CKA_OTP_PIN_REQUIREMENT       0x00000227
#define CKA_OTP_COUNTER               0x0000022E
#define CKA_OTP_TIME                  0x0000022F
#define CKA_OTP_USER_IDENTIFIER       0x0000022A
#define CKA_OTP_SERVICE_IDENTIFIER    0x0000022B
#define CKA_OTP_SERVICE_LOGO          0x0000022C
#define CKA_OTP_SERVICE_LOGO_TYPE     0x0000022D

#define CKA_GOSTR3410_PARAMS           0x00000250
#define CKA_GOSTR3411_PARAMS           0x00000251
#define CKA_GOST28147_PARAMS           0x00000252

#define CKA_HW_FEATURE_TYPE    0x00000300
#define CKA_RESET_ON_INIT      0x00000301
#define CKA_HAS_RESET          0x00000302

#define CKA_PIXEL_X                     0x00000400
#define CKA_PIXEL_Y                     0x00000401
#define CKA_RESOLUTION                  0x00000402
#define CKA_CHAR_ROWS                   0x00000403
#define CKA_CHAR_COLUMNS                0x00000404
#define CKA_COLOR                       0x00000405
#define CKA_BITS_PER_PIXEL              0x00000406
#define CKA_CHAR_SETS                   0x00000480
#define CKA_ENCODING_METHODS            0x00000481
#define CKA_MIME_TYPES                  0x00000482
#define CKA_MECHANISM_TYPE              0x00000500
#define CKA_REQUIRED_CMS_ATTRIBUTES     0x00000501
#define CKA_DEFAULT_CMS_ATTRIBUTES      0x00000502
#define CKA_SUPPORTED_CMS_ATTRIBUTES    0x00000503
#define CKA_ALLOWED_MECHANISMS          (CKF_ARRAY_ATTRIBUTE|0x00000600)

#define CKA_VENDOR_DEFINED     0x80000000
