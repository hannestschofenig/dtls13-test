/*
*  HKDF TLS Functions
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

#include "mbedtls/hkdf.h"
#include "mbedtls/hkdf-tls.h"
#include <stdint.h>
#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

int Derive_Secret(mbedtls_md_type_t hash_alg,
	              const unsigned char *secret, int slen,
                  const unsigned char *label, int llen, 
	              const unsigned char *message, int mlen, 
                  unsigned char *dstbuf, int buflen)
{
    int ret = 0;
    const mbedtls_md_info_t *md;
    int L;

    uint8_t *hashValue;

    md = mbedtls_md_info_from_type(hash_alg);

	L = mbedtls_md_get_size(md);

    if (L != 32 && L != 48 && L !=64) { 
		mbedtls_printf("Length of hash function incorrect.");
		return -1;  
	}

    hashValue = calloc(L,1);
    if (hashValue == NULL) {
		mbedtls_printf("calloc() failed in Derive_Secret().");
        return -1;  
    }

    memset(hashValue, 0, L);

	if (mlen != L) {
		mbedtls_printf("Derive_Secret: Incorrect length of hash - mlen (%d) != L (%d)\n",mlen, L);
		return -1;

	}
    memcpy(hashValue, message, L);

    ret = hkdfExpandLabel(hash_alg, secret, slen, label, llen, hashValue, L,
                          L, dstbuf, buflen);

    if (ret < 0) {
		mbedtls_printf("hkdfExpandLabel(): Error %d.\n", ret);
        return ret;
    }

    return ret;
}


/* 
* The traffic keying material is generated from the following input values:
*  - A secret value
*  - A purpose value indicating the specific value being generated
*  - The length of the key
*
* The traffic keying material is generated from an input traffic
* secret value using:
*  [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
*  [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv" , "", iv_length)
*
* [sender] denotes the sending side and the Secret value is provided by the function caller. 
* We generate server and client side keys in a single function call. 
*/
int makeTrafficKeys(int hash_alg, 
	const unsigned char *client_key, 
	const unsigned char *server_key,
	int slen, 
    int keyLen, int ivLen,
    KeySet *keys)
{
	int ret = 0; 

	keys->clientWriteKey = calloc(keyLen,1);
	if (keys->clientWriteKey == NULL) {
		mbedtls_printf("makeTrafficKeys(): Error allocating clientWriteKey.\n");
		return (MBEDTLS_ERR_HKDF_BUFFER_TOO_SMALL);
	}

    ret = hkdfExpandLabel(hash_alg, client_key, slen, (const unsigned char *) "key", 3,
                          (const unsigned char *)"", 0, keyLen,
                          keys->clientWriteKey, keyLen);

    if (ret < 0) {
		mbedtls_printf("makeTrafficKeys(): Error for clientWriteKey %d.\n", ret);
		return (ret);
	}

	keys->serverWriteKey = calloc(keyLen,1);
	if (keys->serverWriteKey == NULL) {
		mbedtls_printf("makeTrafficKeys(): Error allocating serverWriteKey.\n");
		return (ret);
	}

    ret = hkdfExpandLabel(hash_alg, server_key, slen, (const unsigned char *)"key", 3,
                          (const unsigned char *)"", 0, keyLen,
                          keys->serverWriteKey, keyLen);

    if (ret < 0) {
		mbedtls_printf("makeTrafficKeys(): Error for serverWriteKey %d.\n", ret);
		return (ret);
    }

    // Compute clientWriteIV
	keys->clientWriteIV = calloc(ivLen,1);
	if (keys->clientWriteIV == NULL) {
		mbedtls_printf("makeTrafficKeys(): Error allocating clientWriteIV.\n");
		return (ret);
	}

	ret = hkdfExpandLabel(hash_alg, client_key, slen, (const unsigned char *) "iv", 2,
		(const unsigned char *)"", 0, ivLen,
		keys->clientWriteIV, ivLen);

    if (ret < 0) {
		mbedtls_printf("makeTrafficKeys(): Error for clientWriteIV %d.\n", ret);
		return (ret);
	}

    // Compute serverWriteIV
 	keys->serverWriteIV = calloc(ivLen+4,1);
	if (keys->serverWriteIV == NULL) {
		mbedtls_printf("makeTrafficKeys(): Error allocating serverWriteIV.\n");
		return (ret);
	}

	ret = hkdfExpandLabel(hash_alg, server_key, slen, (const unsigned char *) "iv", 2,
		(const unsigned char *)"", 0, ivLen,
		keys->serverWriteIV, ivLen);

    if (ret < 0) {
		mbedtls_printf("makeTrafficKeys(): Error for serverWriteIV %d.\n", ret);
        return (ret);
    }

    return 0;
}

int hkdfExpandLabel(int hash_alg, const unsigned char *secret, int slen,
                    const unsigned char *label, int llen,
                    const unsigned char *hashValue, int hlen, int length,
                    unsigned char *buf, int blen)
{
    int ret = 0;
    int len;
	const mbedtls_md_info_t *md;
    unsigned char *temp_buffer = NULL;

    /* Compute length of the final output, which 
	 * is based on the length of the label and the 
	 * hash value.
	 */
    len = 2 + 1 + llen + 1 + hlen + 9;

#if defined(HKDF_DEBUG)
	// ----------------------------- DEBUG ---------------------------
	mbedtls_printf("HKDF Expand with label [TLS 1.3, ");
	for (int i = 0; i < llen; i++) {
		mbedtls_printf("%c", label[i]);
	}
	mbedtls_printf("] (%d)", llen);
	mbedtls_printf(", requested length = %d\n", blen);

	mbedtls_printf("PRK (%d):", slen);
	for (int i = 0; i < slen; i++) {
		mbedtls_printf("%02x", secret[i]);
	}
	mbedtls_printf("\n");

	mbedtls_printf("Hash (%d):", hlen);
	for (int i = 0; i <hlen; i++) {
		mbedtls_printf("%02x", hashValue[i]);
	}
	mbedtls_printf("\n");
	// ----------------------------- DEBUG ---------------------------
#endif

	temp_buffer = calloc(len,1);

    if (temp_buffer == NULL) {
		mbedtls_printf("calloc() failed in hkdfExpandLabel().");
        return (MBEDTLS_ERR_HKDF_BUFFER_TOO_SMALL);
    }

    ret = hkdfEncodeLabel(label, llen, hashValue, hlen, temp_buffer, length);
	
    if (ret < 0) {
		mbedtls_printf("hkdfEncodeLabel(): Error %d.\n", ret);
        goto clean_up;
    }

	md = mbedtls_md_info_from_type(hash_alg);

	if (md == NULL) {
		mbedtls_printf("mbedtls_md_info_from_type() failed in hkdfExpandLabel().");
		goto clean_up;
	}

    ret = mbedtls_hkdf_expand(md, secret, slen, temp_buffer, len, buf, blen);

    if (ret != 0) {
		mbedtls_printf("hkdfExpand(): Error %d.\n", ret);
        goto clean_up;
    }

#if defined(HKDF_DEBUG)
	// ----------------------------- DEBUG ---------------------------

	mbedtls_printf("Derived key (%d):", blen);
	for (int i = 0; i < blen; i++) {
		mbedtls_printf("%02x", buf[i]);
	}
	mbedtls_printf("\n");

	// ----------------------------- DEBUG ---------------------------
#endif
clean_up:
	mbedtls_free(temp_buffer);
    return ret;
}

/*
 * hkdfEncodeLabel creates the HkdfLabel structure.
 * 
 * HkdfLabel is specified as:
 * 
 * struct HkdfLabel {
 *   uint16 length;
 *   opaque label<9..255>;
 *   opaque hash_value<0..255>;
 * };
 * 
 * - HkdfLabel.length is Length
 * - HkdfLabel.label is "TLS 1.3, " + Label
 * - HkdfLabel.hash_value is HashValue.
 */

int hkdfEncodeLabel(const unsigned char *label, int llen,
                    const unsigned char *hashValue, int hlen,
                    unsigned char *buf, int length)
{
    unsigned char *p = buf;
    char constant[10] = "TLS 1.3, ";
    int labelLen; 

#if defined(HKDF_DEBUG)
   int total_length;
   total_length = 2 + 1 + labelLen + 1 + hlen;
#endif
    labelLen = (strlen((const char *)constant) + llen);

    // create header
    *p++ = (unsigned char)((length >> 8) & 0xFF);
    *p++ = (unsigned char)((length)&0xFF);
    *p++ = (unsigned char)((labelLen)&0xFF);

    // copy label
    memcpy(p, constant, strlen((const char *)constant));
    p += (unsigned char)strlen((const char *)constant);

    memcpy(p, label, llen);
    p += llen;

    // copy hash length
    *p++ = (unsigned char)((hlen)&0xFF);

    // copy hash value
    memcpy(p, hashValue, hlen);

    p += (unsigned char)hlen;

#if defined(HKDF_DEBUG)
	// ----------------------------- DEBUG ---------------------------

	mbedtls_printf("Info (%d): ", total_length);
	for (int i = 0; i < total_length; i++) {
		mbedtls_printf("%02x", buf[i]);
	}
	mbedtls_printf("\n");

	// ----------------------------- DEBUG ---------------------------
#endif

    return 0;
}
