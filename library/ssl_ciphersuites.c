/**
* \file ssl_ciphersuites.c
*
* \brief SSL ciphersuites for mbed TLS
*
*  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
*  SPDX-License-Identifier: Apache-2.0
*
*  Licensed under the Apache License, Version 2.0 (the "License"); you may
*  not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*  http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
*  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*
*  This file is part of mbed TLS (https://tls.mbed.org)
*/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SSL_TLS_C)

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_time_t    time_t
#endif

#include "mbedtls/ssl_ciphersuites.h"
#include "mbedtls/ssl.h"

#include <string.h>

/*
* Ordered from most preferred to least preferred in terms of security.
*
* Current rule (except rc4, weak and null which come last):
* 1. By key exchange:
*    Forward-secure non-PSK > forward-secure PSK > ECJPAKE > other non-PSK > other PSK
* 2. By key length and cipher:
*    AES-256 > Camellia-256 > AES-128 > Camellia-128 > 3DES
* 3. By cipher mode when relevant GCM > CCM > CBC > CCM_8
* 4. By hash function used when relevant
* 5. By key exchange/auth again: EC > non-EC
*/
static const int ciphersuite_preference[] =
{
#if defined(MBEDTLS_SSL_CIPHERSUITES)
	MBEDTLS_SSL_CIPHERSUITES,
#else
	TLS_AES_256_GCM_SHA384,
	TLS_AES_128_GCM_SHA256,
	TLS_CHACHA20_POLY1305_SHA256,
	TLS_AES_128_CCM_SHA256,
	TLS_AES_128_CCM_8_SHA256,
#endif /* MBEDTLS_SSL_CIPHERSUITES */
	0
};

static const mbedtls_ssl_ciphersuite_t ciphersuite_definitions[] =

{
#if defined(MBEDTLS_AES_C)

	

#if defined(MBEDTLS_GCM_C)
#if defined(MBEDTLS_SHA512_C)
    { TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384",
    MBEDTLS_CIPHER_AES_256_GCM, MBEDTLS_MD_SHA384,
    MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4,
    MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4 },
#endif /* MBEDTLS_SHA512_C */
	{ TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256",
	MBEDTLS_CIPHER_AES_128_GCM, MBEDTLS_MD_SHA256, 
	MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4,
	MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4},
#endif /* MBEDTLS_GCM_C */

#if defined(MBEDTLS_CCM_C)
	{ TLS_AES_128_CCM_SHA256, "TLS_AES_128_CCM_SHA256",
	MBEDTLS_CIPHER_AES_128_CCM, MBEDTLS_MD_SHA256, 
	MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4,
	MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4},
	{ TLS_AES_128_CCM_8_SHA256, "TLS_AES_128_CCM_8_SHA256",
	MBEDTLS_CIPHER_AES_128_CCM_8, MBEDTLS_MD_SHA256,
	MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4,
	MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4},
#endif /* MBEDTLS_CCM_C */
#endif /* MBEDTLS_AES_C */

	{ 0, "",
	MBEDTLS_CIPHER_NONE, MBEDTLS_MD_NONE,
	0, 0, 0, 0 }
};



#if defined(MBEDTLS_SSL_CIPHERSUITES)
const int *mbedtls_ssl_list_ciphersuites(void)
{
	return(ciphersuite_preference);
}
#else
#define MAX_CIPHERSUITES    sizeof( ciphersuite_definitions     ) /         \
                            sizeof( ciphersuite_definitions[0]  )
static int supported_ciphersuites[MAX_CIPHERSUITES];
static int supported_init = 0;

const int *mbedtls_ssl_list_ciphersuites(void)
{
	/*
	* On initial call filter out all ciphersuites not supported by current
	* build based on presence in the ciphersuite_definitions.
	*/
	if (supported_init == 0)
	{
		const int *p;
		int *q;

		for (p = ciphersuite_preference, q = supported_ciphersuites;
			*p != 0 && q < supported_ciphersuites + MAX_CIPHERSUITES - 1;
			p++)
		{
#if defined(MBEDTLS_REMOVE_ARC4_CIPHERSUITES)
			const mbedtls_ssl_ciphersuite_t *cs_info;
			if ((cs_info = mbedtls_ssl_ciphersuite_from_id(*p)) != NULL &&
				cs_info->cipher != MBEDTLS_CIPHER_ARC4_128)
#else
			if (mbedtls_ssl_ciphersuite_from_id(*p) != NULL)
#endif
				*(q++) = *p;
		}
		*q = 0;

		supported_init = 1;
	}

	return(supported_ciphersuites);
}
#endif /* MBEDTLS_SSL_CIPHERSUITES */

const mbedtls_ssl_ciphersuite_t *mbedtls_ssl_ciphersuite_from_string(
	const char *ciphersuite_name)
{
	const mbedtls_ssl_ciphersuite_t *cur = ciphersuite_definitions;

	if (NULL == ciphersuite_name)
		return(NULL);

	while (cur->id != 0)
	{
		if (0 == strcmp(cur->name, ciphersuite_name))
			return(cur);

		cur++;
	}

	return(NULL);
}

const mbedtls_ssl_ciphersuite_t *mbedtls_ssl_ciphersuite_from_id(int ciphersuite)
{
	const mbedtls_ssl_ciphersuite_t *cur = ciphersuite_definitions;

	while (cur->id != 0)
	{
		if (cur->id == ciphersuite)
			return(cur);

		cur++;
	}

	return(NULL);
}

const char *mbedtls_ssl_get_ciphersuite_name(const int ciphersuite_id)
{
	const mbedtls_ssl_ciphersuite_t *cur;

	cur = mbedtls_ssl_ciphersuite_from_id(ciphersuite_id);

	if (cur == NULL)
		return("unknown");

	return(cur->name);
}

int mbedtls_ssl_get_ciphersuite_id(const char *ciphersuite_name)
{
	const mbedtls_ssl_ciphersuite_t *cur;

	cur = mbedtls_ssl_ciphersuite_from_string(ciphersuite_name);

	if (cur == NULL)
		return(0);

	return(cur->id);
}
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

int mbedtls_hash_size_for_ciphersuite(const mbedtls_ssl_ciphersuite_t *ciphersuite)
{
	// We assume that the input parameter ciphersuite has been checked againt NULL already. 
	switch (ciphersuite->hash)
	{
	case MBEDTLS_MD_SHA256: return 32;
	case MBEDTLS_MD_SHA384: return 48;
	case MBEDTLS_MD_SHA512: return 64;
	default: 
		return -1;
	}
}

#endif


#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)

#if defined(MBEDTLS_PK_C)
mbedtls_pk_type_t mbedtls_ssl_get_ciphersuite_sig_pk_alg(const mbedtls_ssl_ciphersuite_t *info)
{
	switch (info->key_exchange)
	{
	case MBEDTLS_KEY_EXCHANGE_RSA:
	case MBEDTLS_KEY_EXCHANGE_DHE_RSA:
	case MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
	case MBEDTLS_KEY_EXCHANGE_RSA_PSK:
		return(MBEDTLS_PK_RSA);

	case MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
		return(MBEDTLS_PK_ECDSA);

	case MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
	case MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
		return(MBEDTLS_PK_ECKEY);

	default:
		return(MBEDTLS_PK_NONE);
	}
}
#endif /* MBEDTLS_PK_C */

#if defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C)
int mbedtls_ssl_ciphersuite_uses_ec(const mbedtls_ssl_ciphersuite_t *info)
{
	switch (info->key_exchange)
	{
	case MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
	case MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
	case MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
	case MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
	case MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
		return(1);

	default:
		return(0);
	}
}
#endif /* MBEDTLS_ECDH_C || MBEDTLS_ECDSA_C */

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
int mbedtls_ssl_ciphersuite_uses_psk(const mbedtls_ssl_ciphersuite_t *info)
{
	switch (info->key_exchange)
	{
	case MBEDTLS_KEY_EXCHANGE_PSK:
	case MBEDTLS_KEY_EXCHANGE_RSA_PSK:
	case MBEDTLS_KEY_EXCHANGE_DHE_PSK:
	case MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
		return(1);

	default:
		return(0);
	}
}
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
#endif /* MBEDTLS_SSL_TLS_C */
