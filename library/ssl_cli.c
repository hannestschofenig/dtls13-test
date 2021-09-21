/*
*  TLS 1.3 client-side functions
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

#include "mbedtls/hkdf-tls.h"
#include "mbedtls/hkdf.h"

#if defined(MBEDTLS_SSL_CLI_C)

#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"

#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#include <stdint.h>

#if defined(MBEDTLS_HAVE_TIME)
#include <time.h>
#endif

// Implementation that should never be optimized out by the compiler 
static void mbedtls_zeroize(void *v, size_t n) {
	volatile unsigned char *p = v; while (n--) *p++ = 0;
}


#if (defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C))

/* TODO: Code for MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED missing */
static int check_ecdh_params(const mbedtls_ssl_context *ssl)
{
	const mbedtls_ecp_curve_info *curve_info;

	curve_info = mbedtls_ecp_curve_info_from_grp_id(ssl->handshake->ecdh_ctx.grp.id);
	if (curve_info == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
	}

	MBEDTLS_SSL_DEBUG_MSG(2, ("ECDH curve: %s", curve_info->name));

#if defined(MBEDTLS_ECP_C)
	if (mbedtls_ssl_check_curve(ssl, ssl->handshake->ecdh_ctx.grp.id) != 0)
#else
	if (ssl->handshake->ecdh_ctx.grp.nbits < 163 ||
		ssl->handshake->ecdh_ctx.grp.nbits > 521)
#endif
		return(-1);

	MBEDTLS_SSL_DEBUG_ECP(3, "ECDH: Qp", &ssl->handshake->ecdh_ctx.Qp);

	return(0);
}
#endif /* MBEDTLS_ECDH_C || MBEDTLS_ECDSA_C */



#if defined(MBEDTLS_ZERO_RTT)
static int mbedtls_ssl_write_end_of_early_data(mbedtls_ssl_context *ssl)
{
	int ret;
	MBEDTLS_SSL_DEBUG_MSG(2, ("=> write EndOfEarlyData"));

	ssl->out_msglen = mbedtls_ssl_hs_hdr_len(ssl);  /* length of the handshake message header */;
	/* We will add the additional byte for the ContentType later */;
	ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
	ssl->out_msg[0] = MBEDTLS_SSL_HS_END_OF_EARLY_DATA;

#if defined(MBEDTLS_SSL_PROTO_DTLS)
	if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM)
		mbedtls_ssl_send_flight_completed(ssl);
#endif

	if ((ret = mbedtls_ssl_write_record(ssl)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_write_record", ret);
		return(ret);
	}

	if ((ret = mbedtls_ssl_flush_output(ssl)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_flush_output", ret);
		return(ret);
	}

	MBEDTLS_SSL_DEBUG_MSG(2, ("<= write EndOfEarlyData"));

	return(0);
}
#endif /* MBEDTLS_ZERO_RTT */


#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
static void ssl_write_hostname_ext(mbedtls_ssl_context *ssl,
	unsigned char *buf,
	size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + MBEDTLS_SSL_MAX_CONTENT_LEN;
	size_t hostname_len;

	*olen = 0;

	if (ssl->hostname == NULL)
		return;

	MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, adding server name extension: %s",
		ssl->hostname));

	hostname_len = strlen(ssl->hostname);

	if (end < p || (size_t)(end - p) < hostname_len + 9)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("buffer too small"));
		return;
	}

	/*
	* struct {
	*     NameType name_type;
	*     select (name_type) {
	*         case host_name: HostName;
	*     } name;
	* } ServerName;
	*
	* enum {
	*     host_name(0), (255)
	* } NameType;
	*
	* opaque HostName<1..2^16-1>;
	*
	* struct {
	*     ServerName server_name_list<1..2^16-1>
	* } ServerNameList;
	*/
	*p++ = (unsigned char)((MBEDTLS_TLS_EXT_SERVERNAME >> 8) & 0xFF);
	*p++ = (unsigned char)((MBEDTLS_TLS_EXT_SERVERNAME) & 0xFF);

	*p++ = (unsigned char)(((hostname_len + 5) >> 8) & 0xFF);
	*p++ = (unsigned char)(((hostname_len + 5)) & 0xFF);

	*p++ = (unsigned char)(((hostname_len + 3) >> 8) & 0xFF);
	*p++ = (unsigned char)(((hostname_len + 3)) & 0xFF);

	*p++ = (unsigned char)((MBEDTLS_TLS_EXT_SERVERNAME_HOSTNAME) & 0xFF);
	*p++ = (unsigned char)((hostname_len >> 8) & 0xFF);
	*p++ = (unsigned char)((hostname_len) & 0xFF);

	memcpy(p, ssl->hostname, hostname_len);

	*olen = hostname_len + 9;
}
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */


/* 
 * ssl_write_supported_versions_ext(): 
 * 
 * struct {
 *      ProtocolVersion versions<2..254>;
 * } SupportedVersions;
 */

static void ssl_write_supported_versions_ext(mbedtls_ssl_context *ssl,
	unsigned char *buf,
	size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + MBEDTLS_SSL_MAX_CONTENT_LEN;

	*olen = 0;

	MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, adding supported version extension"));

	if (end < p || (size_t)(end - p) < 8)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("buffer too small"));
		return;
	}

	*p++ = (unsigned char)((MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS >> 8) & 0xFF);
	*p++ = (unsigned char)((MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS) & 0xFF);

	// total length 
	*p++ = 0x00; 
	*p++ = 3; 

	// length of next field
	*p++ = 0x2;

	/* This implementation only supports a single TLS version, namey TLS 1.3. 
	 * Hence, max_major_ver == min_major_ver and max_minor_ver == min_minor_ver. 
	 */
/* #if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if defined(MBEDTLS_SSL_PROTO_DTLS) 
#if defined(TLS_DRAFT_VERSION_MAJOR) && defined(TLS_DRAFT_VERSION_MINOR)
	*p++ = (unsigned char)TLS_DRAFT_VERSION_MAJOR;
	*p++ = (unsigned char)TLS_DRAFT_VERSION_MINOR;
#endif // MBEDTLS_SSL_PROTO_DTLS 
#else 
	mbedtls_ssl_write_version(ssl->conf->max_major_ver, ssl->conf->max_minor_ver,
		ssl->conf->transport, p);
	p += 2;
#endif // MBEDTLS_SSL_PROTO_TLS1_3 */
	mbedtls_ssl_write_version(ssl->conf->max_major_ver, ssl->conf->max_minor_ver,
		ssl->conf->transport, p);
	p += 2;

	MBEDTLS_SSL_DEBUG_MSG(3, ("supported version: [%d:%d]", ssl->conf->max_major_ver, ssl->conf->max_minor_ver));

	*olen = 7;
}

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)

/* 
 * ssl_write_max_fragment_length_ext(): 
 *
 * enum{
 *    2^9(1), 2^10(2), 2^11(3), 2^12(4), (255)
 * } MaxFragmentLength;
 *
 */
static void ssl_write_max_fragment_length_ext(mbedtls_ssl_context *ssl,
	unsigned char *buf,
	size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + MBEDTLS_SSL_MAX_CONTENT_LEN;

	*olen = 0;

	if (ssl->conf->mfl_code == MBEDTLS_SSL_MAX_FRAG_LEN_NONE) {
		return;
	}

	if (end < p || (size_t)(end - p) < 5)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("buffer too small"));
		return;
	}

	MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, adding max_fragment_length extension"));

	*p++ = (unsigned char)((MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH >> 8) & 0xFF);
	*p++ = (unsigned char)((MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH) & 0xFF);

	*p++ = 0x00;
	*p++ = 1;

	*p++ = ssl->conf->mfl_code;
	MBEDTLS_SSL_DEBUG_MSG(3, ("Maximum fragment length = %d", ssl->conf->mfl_code));

	*olen = 5;
}
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */


#if defined(MBEDTLS_SSL_ALPN)
/* 
 * ssl_write_alpn_ext() structure: 
 * 
 * opaque ProtocolName<1..2^8-1>;
 *
 * struct {
 *     ProtocolName protocol_name_list<2..2^16-1>
 * } ProtocolNameList;
 *
 */
static void ssl_write_alpn_ext(mbedtls_ssl_context *ssl,
	unsigned char *buf, size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + MBEDTLS_SSL_MAX_CONTENT_LEN;
	size_t alpnlen = 0;
	const char **cur;

	*olen = 0;

	if (ssl->conf->alpn_list == NULL)
	{
		return;
	}

	for (cur = ssl->conf->alpn_list; *cur != NULL; cur++)
		alpnlen += (unsigned char)(strlen(*cur) & 0xFF) + 1;

	if (end < p || (size_t)(end - p) < 6 + alpnlen)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("buffer too small"));
		return;
	}

	MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, adding alpn extension"));

	*p++ = (unsigned char)((MBEDTLS_TLS_EXT_ALPN >> 8) & 0xFF);
	*p++ = (unsigned char)((MBEDTLS_TLS_EXT_ALPN) & 0xFF);

	/*
	* opaque ProtocolName<1..2^8-1>;
	*
	* struct {
	*     ProtocolName protocol_name_list<2..2^16-1>
	* } ProtocolNameList;
	*/

	/* Skip writing extension and list length for now */
	p += 4;

	for (cur = ssl->conf->alpn_list; *cur != NULL; cur++)
	{
		*p = (unsigned char)(strlen(*cur) & 0xFF);
		memcpy(p + 1, *cur, *p);
		p += 1 + *p;
	}

	*olen = p - buf;

	/* List length = olen - 2 (ext_type) - 2 (ext_len) - 2 (list_len) */
	buf[4] = (unsigned char)(((*olen - 6) >> 8) & 0xFF);
	buf[5] = (unsigned char)((*olen - 6) & 0xFF);

	/* Extension length = olen - 2 (ext_type) - 2 (ext_len) */
	buf[2] = (unsigned char)(((*olen - 4) >> 8) & 0xFF);
	buf[3] = (unsigned char)((*olen - 4) & 0xFF);
}
#endif /* MBEDTLS_SSL_ALPN */

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED) 

/* 
 * ssl_write_psk_key_exchange_modes_ext() structure: 
 * 
 * enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
 *
 * struct {
 *     PskKeyExchangeMode ke_modes<1..255>;
 * } PskKeyExchangeModes;
 */ 

static int ssl_write_psk_key_exchange_modes_ext(mbedtls_ssl_context *ssl,
	const unsigned char *buf,
	size_t *olen)
{
	unsigned char *p = (unsigned char *) buf;
	const unsigned char *end = ssl->out_msg + MBEDTLS_SSL_MAX_CONTENT_LEN;
	*olen = 0;

	// Check whether we have any PSK credentials configured. 
	if (ssl->conf->psk == NULL || ssl->conf->psk_identity == NULL ||
		ssl->conf->psk_identity_len == 0 || ssl->conf->psk_len == 0)
	{
		MBEDTLS_SSL_DEBUG_MSG(3, ("No key for use with the pre_shared_key extension available."));
		return(MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED);
	}

	// max length of this extension is 7 bytes 
	if ((size_t)(end - p) < (7))
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("Not enough buffer"));
		return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
	}

	MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, adding psk_key_exchange_modes extension"));

	// Extension Type
	*p++ = (unsigned char)((MBEDTLS_TLS_EXT_PSK_KEY_EXCHANGE_MODES >> 8) & 0xFF);
	*p++ = (unsigned char)((MBEDTLS_TLS_EXT_PSK_KEY_EXCHANGE_MODES) & 0xFF);

	if (ssl->conf->key_exchange_modes == KEY_EXCHANGE_MODE_PSK_ALL) {
	
		// Extension Length
		*p++ = 0;
		*p++ = 3; 

		// 1 byte length field for array of PskKeyExchangeMode
		*p++ = 2;
		*p++ = KEY_EXCHANGE_MODE_PSK_KE;
		*p++ = KEY_EXCHANGE_MODE_PSK_DHE_KE;
		*olen = 7; 
	}
	else {
		// Extension Length
		*p++ = 0;
		*p++ = 2;

		// 1 byte length field for array of PskKeyExchangeMode
		*p++ = 1;
		*p++= ssl->conf->key_exchange_modes;
		*olen = 6;
	}
	
	return (0);
}
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */


/*
* ssl_write_pre_shared_key_ext() structure:
*
* struct {
*   opaque identity<1..2^16-1>;
*   uint32 obfuscated_ticket_age;
* } PskIdentity;
*
* opaque PskBinderEntry<32..255>;
*
* struct {
*   select (Handshake.msg_type) {
*
*     case client_hello:
*       PskIdentity identities<7..2^16-1>;
*       PskBinderEntry binders<33..2^16-1>;
*
*     case server_hello:
*       uint16 selected_identity;
*   };
*
* } PreSharedKeyExtension;
*
*
* dummy_run = 0 --> initial run
* dummy_run == 1 --> second run
*/

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)

/* ssl_create_binder():

0
|
v
PSK ->  HKDF-Extract
|
v
Early Secret
|
|
+------> Derive-Secret(.,
|                      "external psk binder key" |
|                      "resumption psk binder key",
|                      "")
|                     = binder_key
|
+-----> Derive-Secret(., "client early traffic secret",
|                     ClientHello)
|                     = client_early_traffic_secret
*/

int ssl_create_binder(mbedtls_ssl_context *ssl, unsigned char *psk, size_t psk_len, const mbedtls_md_info_t *md, const mbedtls_ssl_ciphersuite_t *suite_info, unsigned char *buffer, size_t blen, unsigned char *result) {
	int ret = 0;
	int hash_length;
	unsigned char salt[MBEDTLS_MD_MAX_SIZE];
	unsigned char padbuf[MBEDTLS_MD_MAX_SIZE];
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];
	unsigned char binder_key[MBEDTLS_MD_MAX_SIZE];
	unsigned char finished_key[MBEDTLS_MD_MAX_SIZE];

#if defined(MBEDTLS_SHA256_C)
	mbedtls_sha256_context sha256;
#endif

#if defined(MBEDTLS_SHA512_C)
	mbedtls_sha512_context sha512;
#endif

	hash_length = mbedtls_hash_size_for_ciphersuite(suite_info);

	if (hash_length == -1) {
		MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_hash_size_for_ciphersuite == -1, ssl_create_binder failed"));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
	}

	/*

	Compute Early Secret with HKDF-Extract(0, PSK)

	*/
	memset(salt, 0x0, hash_length);
	ret = mbedtls_hkdf_extract(md, salt, hash_length, psk, psk_len, ssl->handshake->early_secret);

	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_hkdf_extract() with early_secret", ret);
		return ret;
	}

	MBEDTLS_SSL_DEBUG_MSG(5, ("HKDF Extract -- early_secret"));
	MBEDTLS_SSL_DEBUG_BUF(5, "Salt", salt, hash_length);
	MBEDTLS_SSL_DEBUG_BUF(5, "Input", psk, psk_len);
	MBEDTLS_SSL_DEBUG_BUF(5, "Output", ssl->handshake->early_secret, hash_length);

	/*

	Compute binder_key with Derive-Secret(early_secret, "external psk binder key" | "resumption psk binder key","")

	*/

	/* Create hash of empty message first.
	* TBD: replace by constant.
	*
	* For SHA256 the constant is
	* e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	*
	* For SHA384 the constant is
	* 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b
	*/

	if (suite_info->hash == MBEDTLS_MD_SHA256) {
#if defined(MBEDTLS_SHA256_C) 
		mbedtls_sha256((const unsigned char *)"", 0, hash, 0);
#else 
		MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_ssl_derive_master_secret: Unknow hash function."));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
#endif 
	}
	else if (suite_info->hash == MBEDTLS_MD_SHA384) {
#if defined(MBEDTLS_SHA512_C)
		mbedtls_sha512( (const unsigned char *)"", 0, hash, 1 /* for SHA384 */);
#else 
		MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_ssl_derive_master_secret: Unknow hash function."));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
#endif 
	}

	if (ssl->conf->resumption_mode == 1) {
		ret = Derive_Secret(mbedtls_md_get_type(md),
			ssl->handshake->early_secret, hash_length,
			 (const unsigned char *)"resumption psk binder key", strlen("resumption psk binder key"),
			hash, hash_length, binder_key, hash_length);
		MBEDTLS_SSL_DEBUG_MSG(5, ("Derive Early Secret with 'resumption psk binder key'"));
	}
	else
	{
		ret = Derive_Secret(mbedtls_md_get_type(md),
			ssl->handshake->early_secret, hash_length,
			 (const unsigned char *)"external psk binder key", strlen("external psk binder key"),
			hash, hash_length, binder_key, hash_length);
		MBEDTLS_SSL_DEBUG_MSG(5, ("Derive Early Secret with 'external psk binder key'"));
	}

	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(1, "Derive_Secret() with binder_key: Error", ret);
		return ret;
	}

	if (suite_info->hash == MBEDTLS_MD_SHA256) {
#if defined(MBEDTLS_SHA256_C) 

		mbedtls_sha256_init(&sha256);
		mbedtls_sha256_starts(&sha256, 0 /* = use SHA256 */);
		// TBD: Should we clone the hash?
		//		mbedtls_sha256_clone(&sha256, &ssl->handshake->fin_sha256);
		MBEDTLS_SSL_DEBUG_BUF(5, "finished sha256 state", (unsigned char *)sha256.state, sizeof(sha256.state));
		mbedtls_sha256_update(&sha256, buffer, blen);
		MBEDTLS_SSL_DEBUG_BUF(5, "input buffer for psk binder", buffer, blen);
		mbedtls_sha256_finish(&sha256, padbuf);
		MBEDTLS_SSL_DEBUG_BUF(5, "handshake hash for psk binder", padbuf, 32);
#else 
		MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_ssl_derive_master_secret: Unknow hash function."));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
#endif 
	}
	else if (suite_info->hash == MBEDTLS_MD_SHA384) {
#if defined(MBEDTLS_SHA512_C)
		mbedtls_sha512_init(&sha512);
		mbedtls_sha512_starts(&sha512, 1 /* = use SHA384 */);
		mbedtls_sha512_clone(&sha512, &ssl->handshake->fin_sha512);
		MBEDTLS_SSL_DEBUG_BUF(4, "finished sha384 state", (unsigned char *)sha512.state, 48);
		mbedtls_sha512_update(&sha512, buffer, blen);
		mbedtls_sha512_finish(&sha512, padbuf);
		MBEDTLS_SSL_DEBUG_BUF(5, "handshake hash for psk binder", padbuf, 48);
	}
	else if (suite_info->hash == MBEDTLS_MD_SHA512) {
		mbedtls_sha512_init(&sha512);
		mbedtls_sha512_starts(&sha512, 0 /* = use SHA512 */);
		mbedtls_sha512_clone(&sha512, &ssl->handshake->fin_sha512);
		MBEDTLS_SSL_DEBUG_BUF(4, "finished sha512 state", (unsigned char *)sha512.state, 64);
		mbedtls_sha512_update(&sha512, buffer, blen);
		mbedtls_sha512_finish(&sha512, padbuf);
		MBEDTLS_SSL_DEBUG_BUF(5, "handshake hash for psk binder", padbuf, 64);
	}
	else {
#else 
		MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_ssl_derive_master_secret: Unknow hash function."));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
#endif 
	}

	/*
	* finished_key =
	*    HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
	*
	* The binding_value is computed in the same way as the Finished message
	* but with the BaseKey being the binder_key.
	*/

	ret = hkdfExpandLabel(suite_info->hash, binder_key, hash_length,  (const unsigned char *)"finished", strlen("finished"),  (const unsigned char *)"", 0, hash_length, finished_key, hash_length);

	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(2, "Creating the finished_key failed", ret);
		return (ret);
	}

	MBEDTLS_SSL_DEBUG_BUF(3, "finished_key", finished_key, hash_length);

	// compute mac and write it into the buffer
	ret = mbedtls_md_hmac(md, finished_key, hash_length, padbuf, hash_length, result);

	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_md_hmac", ret);
		return (ret);
	}

	MBEDTLS_SSL_DEBUG_MSG(3, ("verify_data of psk binder"));
	MBEDTLS_SSL_DEBUG_BUF(3, "Input", padbuf, hash_length);
	MBEDTLS_SSL_DEBUG_BUF(3, "Key", finished_key, hash_length);
	MBEDTLS_SSL_DEBUG_BUF(3, "Output", result, hash_length);

#if defined(MBEDTLS_SHA256_C)
	if (suite_info->hash == MBEDTLS_MD_SHA256) {
		mbedtls_sha256_free(&sha256);
	}
	else
#endif
#if defined(MBEDTLS_SHA512_C)
		if (suite_info->hash == MBEDTLS_MD_SHA384) {
			mbedtls_sha512_free(&sha512);
		}
		else
#endif 
		{
			MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_ssl_derive_master_secret: Unknow hash function."));
			return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
		}

	//	mbedtls_zeroize(padbuf, hash_length); 
	mbedtls_zeroize(finished_key, hash_length);

	return ret;
}


int ssl_write_pre_shared_key_ext(mbedtls_ssl_context *ssl,
	const unsigned char *buf,
	size_t *olen, int dummy_run)
{
	unsigned char *p = (unsigned char *) buf, *truncated_clienthello_end, *truncated_clienthello_start = ssl->out_msg;
	const unsigned char *end = ssl->out_msg + MBEDTLS_SSL_MAX_CONTENT_LEN;
	size_t ext_length = 0;
	uint32_t obfuscated_ticket_age=0;
	const mbedtls_ssl_ciphersuite_t *suite_info;
	int hash_len=-1, ret;
	const int *ciphersuites;
#if defined(MBEDTLS_HAVE_TIME)
	time_t now;
#endif

	*olen = 0;

	MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, adding pre_shared_key extension"));


	if (!(ssl->handshake->extensions_present & PSK_KEY_EXCHANGE_MODES_EXTENSION)) {
		MBEDTLS_SSL_DEBUG_MSG(1, ("The psk_key_exchange_modes extension has not been added."));
		return(MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	/*
	* Ciphersuite list
	*/
	ciphersuites = ssl->conf->ciphersuite_list[ssl->minor_ver];

	for (int i = 0; ciphersuites[i] != 0; i++)
	{
		suite_info = mbedtls_ssl_ciphersuite_from_id(ciphersuites[i]);

		if (suite_info == NULL)
			continue;

		hash_len = mbedtls_hash_size_for_ciphersuite(suite_info);

		if (hash_len == -1)
		{
			MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_hash_size_for_ciphersuite in ssl_write_pre_shared_key_ext failed: Unknown hash function"));
			return(MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
		}

		// In this implementation we only add one pre-shared-key extension.
		ssl->session_negotiate->ciphersuite = ciphersuites[i];
		ssl->transform_negotiate->ciphersuite_info = suite_info;
#if defined(MBEDTLS_ZERO_RTT)
		/* Even if we include a key_share extension in the ClientHello
		* message it will not be used at this stage for the key derivation.
		*/
		if (ssl->handshake->early_data == MBEDTLS_SSL_EARLY_DATA_ON) {
			ssl->session_negotiate->key_exchange = KEY_EXCHANGE_MODE_PSK_KE;
		}
#endif 
		break;
	}
	if (hash_len == -1)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_hash_size_for_ciphersuite in ssl_write_pre_shared_key_ext failed: Unknown hash function"));
		return(MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	/* 
	* The length (excluding the extension header) includes:
	*
	*  - 2 bytes for total length of identities
	*     - 2 bytes for length of first identity value
	*     - identity value (of length len; min(len)>=1)
	*     - 4 bytes for obfuscated_ticket_age
	*                ...
	*  - 2 bytes for total length of psk binders
	*      - 1 byte for length of first psk binder value
	*      - 32 bytes (with SHA256), or 48 bytes (with SHA384) for psk binder value
	*                ...
	*
    * Note: Currently we assume we have only one PSK credential configured per server.
	*/
	ext_length = 4 + ssl->conf->psk_identity_len + 4 + 2 + 1 + hash_len;

	// ext_length + Extension Type (2 bytes) + Extension Length (2 bytes) 
	if (end < p || (size_t)(end - p) < (ext_length + 4))
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("buffer too short"));
		return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
	}

	if (dummy_run == 0) {
		memset(p, 0, ext_length);
	}
	else {
		// Extension Type
		*p++ = (unsigned char)((MBEDTLS_TLS_EXT_PRE_SHARED_KEY >> 8) & 0xFF);
		*p++ = (unsigned char)((MBEDTLS_TLS_EXT_PRE_SHARED_KEY) & 0xFF);

		// Extension Length
		*p++ = (unsigned char)((ext_length >> 8) & 0xFF);
		*p++ = (unsigned char)(ext_length & 0xFF);

		// 2 bytes length field for array of PskIdentity 
		*p++ = (unsigned char)(((ssl->conf->psk_identity_len + 2) >> 8) & 0xFF);
		*p++ = (unsigned char)((ssl->conf->psk_identity_len + 2) & 0xFF);

		// 2 bytes length field for psk_identity
		*p++ = (unsigned char)(((ssl->conf->psk_identity_len) >> 8) & 0xFF);
		*p++ = (unsigned char)((ssl->conf->psk_identity_len) & 0xFF);

		// actual psk_identity
		memcpy(p, ssl->conf->psk_identity, ssl->conf->psk_identity_len);

		p += ssl->conf->psk_identity_len;

		// Calculate obfuscated_ticket_age
		// (but not for externally configured PSKs)
		if (ssl->conf->ticket_age_add > 0) {
#if defined(MBEDTLS_HAVE_TIME)
			now = time(NULL);

			if (!(ssl->conf->ticket_received <= now && now - ssl->conf->ticket_received < 7 * 86400 * 1000)) {
				MBEDTLS_SSL_DEBUG_MSG(3, ("ticket expired"));
				// TBD: We would have to fall back to another PSK 
				return(MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
			}

			obfuscated_ticket_age = (uint32_t)(now - ssl->conf->ticket_received) + ssl->conf->ticket_age_add;
			MBEDTLS_SSL_DEBUG_MSG(5, ("obfuscated_ticket_age = %d", obfuscated_ticket_age));
#endif /* MBEDTLS_HAVE_TIME */
		}
		// add obfuscated ticket age
		memcpy(p, &obfuscated_ticket_age, 4 /* bytes */);
		p += 4;

		/* Store this pointer since we need it to compute the psk binder */
		truncated_clienthello_end = p;

		/* Add PSK binder for included identity */

		// 2 bytes length field for array of psk binders
		*p++ = (unsigned char)(((hash_len + 1) >> 8) & 0xFF);
		*p++ = (unsigned char)((hash_len + 1) & 0xFF);

		// 1 bytes length field for next psk binder
		*p++ = (unsigned char)((hash_len) & 0xFF);

		MBEDTLS_SSL_DEBUG_BUF(3, "ssl_calc_binder computed over ", truncated_clienthello_start, truncated_clienthello_end - truncated_clienthello_start);

		ret = ssl_create_binder(ssl, ssl->conf->psk, ssl->conf->psk_len, mbedtls_md_info_from_type(suite_info->hash),
			suite_info, truncated_clienthello_start, truncated_clienthello_end - truncated_clienthello_start, p);


		if (ret != 0)
		{
			MBEDTLS_SSL_DEBUG_RET(1, "create_binder in ssl_write_pre_shared_key_ext failed: %d", ret);
			return(MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
		}
	}
	*olen = ext_length + 4;
	return 0;
}


#endif	/* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED  */


/*
* Generate random bytes for ClientHello
*/
static int ssl_generate_random(mbedtls_ssl_context *ssl)
{
	int ret;
	unsigned char *p = ssl->handshake->randbytes;
#if defined(MBEDTLS_HAVE_TIME) && !defined(MBEDTLS_SSL_PROTO_TLS1_3)
	time_t t;
#endif

	/*
	* When responding to a verify request, MUST reuse random (RFC 6347 4.2.1)
	*/
#if defined(MBEDTLS_SSL_PROTO_DTLS)
	if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
		ssl->handshake->verify_cookie != NULL)
	{
		return(0);
	}
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
	/* In TLS 1.3 we only use 32 bytes of random data
	*/
	if ((ret = ssl->conf->f_rng(ssl->conf->p_rng, p, 28)) != 0)
		return(ret);

#else 

#if defined(MBEDTLS_HAVE_TIME)
	t = time(NULL);
	*p++ = (unsigned char)(t >> 24);
	*p++ = (unsigned char)(t >> 16);
	*p++ = (unsigned char)(t >> 8);
	*p++ = (unsigned char)(t);

	MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, current time: %lu", t));
#else
	if ((ret = ssl->conf->f_rng(ssl->conf->p_rng, p, 4)) != 0)
		return(ret);

	p += 4;
#endif /* MBEDTLS_HAVE_TIME */

	if ((ret = ssl->conf->f_rng(ssl->conf->p_rng, p, 28)) != 0)
		return(ret);
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

	return(0);
}



#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
static int ssl_write_cookie_ext(mbedtls_ssl_context *ssl,
	const unsigned char *buf,
	size_t *olen)
{
	unsigned char *p = (unsigned char *) buf;
	const unsigned char *end = ssl->out_msg + MBEDTLS_SSL_MAX_CONTENT_LEN;
	//	size_t ext_length = 0;
	*olen = 0;

	if (ssl->handshake->verify_cookie == NULL) {
		MBEDTLS_SSL_DEBUG_MSG(3, ("no cookie to send; skip extension"));
		return 0; 
	}

	MBEDTLS_SSL_DEBUG_BUF(3, "client hello, cookie",
		ssl->handshake->verify_cookie,
		ssl->handshake->verify_cookie_len);

	if (end < p || (end - p) < (ssl->handshake->verify_cookie_len + 4))
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("buffer too small"));
		return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
	}

	MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, adding cookie extension"));

	// Extension Type
	*p++ = (unsigned char)((MBEDTLS_TLS_EXT_COOKIE >> 8) & 0xFF);
	*p++ = (unsigned char)((MBEDTLS_TLS_EXT_COOKIE) & 0xFF);

	// Extension Length
	*p++ = (unsigned char)((ssl->handshake->verify_cookie_len >> 8) & 0xFF);
	*p++ = (unsigned char)(ssl->handshake->verify_cookie_len & 0xFF);

	memcpy(p, ssl->handshake->verify_cookie, ssl->handshake->verify_cookie_len);
	
	p += ssl->handshake->verify_cookie_len;

	*olen = ssl->handshake->verify_cookie_len + 4;

	return 0;
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3*/

#if defined(MBEDTLS_ECDH_C)
/*

Supported Groups Extension

In versions of TLS prior to TLS 1.3, this extension was named
'elliptic_curves' and only contained elliptic curve groups.
*/

static int ssl_write_supported_groups_ext(mbedtls_ssl_context *ssl,
	unsigned char *buf,
	size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + MBEDTLS_SSL_MAX_CONTENT_LEN;
	unsigned char *elliptic_curve_list = p + 6;
	size_t elliptic_curve_len = 0;
	const mbedtls_ecp_curve_info *info;
#if defined(MBEDTLS_ECP_C)
	const mbedtls_ecp_group_id *grp_id;
#else
	((void)ssl);
#endif

	*olen = 0;

#if defined(MBEDTLS_ECP_C)
	for (grp_id = ssl->conf->curve_list; *grp_id != MBEDTLS_ECP_DP_NONE; grp_id++)
	{
		info = mbedtls_ecp_curve_info_from_grp_id(*grp_id);
#else
	for (info = mbedtls_ecp_curve_list(); info->grp_id != MBEDTLS_ECP_DP_NONE; info++)
	{
#endif
		elliptic_curve_len += 2;
	}

	if (elliptic_curve_len == 0) {
		/* If we have no curves configured then we are in trouble. */
		MBEDTLS_SSL_DEBUG_MSG(1, ("No curves configured."));
		return -1;
	}

	if (end < p || (size_t)(end - p) < 6 + elliptic_curve_len)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("buffer too small"));
		return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
	}

	MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, adding supported_groups extension"));

	elliptic_curve_len = 0;

#if defined(MBEDTLS_ECP_C)
	for (grp_id = ssl->conf->curve_list; *grp_id != MBEDTLS_ECP_DP_NONE; grp_id++)
	{
		info = mbedtls_ecp_curve_info_from_grp_id(*grp_id);
#else
	for (info = mbedtls_ecp_curve_list(); info->grp_id != MBEDTLS_ECP_DP_NONE; info++)
	{
#endif
		elliptic_curve_list[elliptic_curve_len++] = info->tls_id >> 8;
		elliptic_curve_list[elliptic_curve_len++] = info->tls_id & 0xFF;
	}

	if (elliptic_curve_len == 0)
		return -1;

	*p++ = (unsigned char)((MBEDTLS_TLS_EXT_SUPPORTED_GROUPS >> 8) & 0xFF);
	*p++ = (unsigned char)((MBEDTLS_TLS_EXT_SUPPORTED_GROUPS) & 0xFF);

	*p++ = (unsigned char)(((elliptic_curve_len + 2) >> 8) & 0xFF);
	*p++ = (unsigned char)(((elliptic_curve_len + 2)) & 0xFF);

	*p++ = (unsigned char)(((elliptic_curve_len) >> 8) & 0xFF);
	*p++ = (unsigned char)(((elliptic_curve_len)) & 0xFF);

	MBEDTLS_SSL_DEBUG_BUF(3, "Supported groups extension", buf + 4, elliptic_curve_len + 2);

	*olen = 6 + elliptic_curve_len;
	return 0;
}
#endif /* defined(MBEDTLS_ECDH_C) */



/*

Key Shares Extension

enum {
  // Elliptic Curve Groups (ECDHE)
  obsolete_RESERVED(1..22),
  secp256r1(23), secp384r1(24), secp521r1(25),
  obsolete_RESERVED(26..28),
  x25519(29), x448(30),

  // Finite Field Groups (DHE)
  ffdhe2048(256), ffdhe3072(257), ffdhe4096(258),
  ffdhe6144(259), ffdhe8192(260),

  // Reserved Code Points
  ffdhe_private_use(0x01FC..0x01FF),
  ecdhe_private_use(0xFE00..0xFEFF),
  obsolete_RESERVED(0xFF01..0xFF02),
  (0xFFFF)
} NamedGroup;

struct {
  NamedGroup group;
  opaque key_exchange<1..2^16-1>;
} KeyShareEntry;

struct {
  select (role) {
    case client:
      KeyShareEntry client_shares<0..2^16-1>;
    case server:
      KeyShareEntry server_share;
  }
} KeyShare;
*/

#if (defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C))

static int ssl_write_key_shares_ext(mbedtls_ssl_context *ssl,
	unsigned char *buf,
	size_t *olen)
{
	unsigned char *p = buf + 6;
	unsigned char *header = buf; // Pointer where the header has to go.
	size_t len;
	int ret;
	const int *ciphersuites;

	const mbedtls_ecp_curve_info *info = NULL;
	const mbedtls_ecp_group_id *grp_id;
	int max_size = 0; 
	const mbedtls_ssl_ciphersuite_t *suite_info;

	*olen = 0;

	if (ssl->conf->curve_list == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, key share extension: empty curve list"));
		return -1;
	}

	MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, adding key share extension"));

	if (ssl->session_negotiate == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("ssl->session_negotiate == NULL"));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
	}


	/*
	* Ciphersuite list
	*/
	ciphersuites = ssl->conf->ciphersuite_list[ssl->minor_ver];

	for (int i = 0; ciphersuites[i] != 0; i++)
	{
		suite_info = mbedtls_ssl_ciphersuite_from_id(ciphersuites[i]);

		if (suite_info == NULL)
			continue;

		if (suite_info->hash == MBEDTLS_MD_SHA256) max_size = 128;
		else if (suite_info->hash == MBEDTLS_MD_SHA384) max_size = 384;
	}

	MBEDTLS_SSL_DEBUG_MSG(3, ("Ciphersuites require a key length of max %d bits", max_size));


	/* Traverse list of supported curves and add key shares one-by-one.
	 * Currently we just provide one key share based on the first match.
	 */

	for (grp_id = ssl->conf->curve_list; *grp_id != MBEDTLS_ECP_DP_NONE; grp_id++) {

		info = mbedtls_ecp_curve_info_from_grp_id(*grp_id);

		/* Check whether the key share matches the selected ciphersuite
		* in terms of key length.
        *
		* Hence, AES-128 should go with a group bit size of 192 and 224 bits.
		*/
		switch (max_size) { 
			case 128: if (info->bit_size != 256 && info->bit_size!=192 && info->bit_size!= 224) continue;
				break;
			case 384: if (info->bit_size != 384) continue;
				break;
		}

		MBEDTLS_SSL_DEBUG_MSG(2, ("ECDHE curve: %s", info->name));

		if ((ret = mbedtls_ecp_group_load(&ssl->handshake->ecdh_ctx.grp, info->grp_id)) != 0) {
			MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ecp_group_load", ret);
			return(ret);
		} else break;
	}

	if ((ret = mbedtls_ecdh_make_params(&ssl->handshake->ecdh_ctx, &len,
		p, MBEDTLS_SSL_MAX_CONTENT_LEN - *olen,
		ssl->conf->f_rng, ssl->conf->p_rng)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ecdh_make_params", ret);
		return(ret);
	}

	p += len;

	MBEDTLS_SSL_DEBUG_ECP(3, "ECDHE: Q ", &ssl->handshake->ecdh_ctx.Q);

	// Write extension header 
	*header++ = (unsigned char)((MBEDTLS_TLS_EXT_KEY_SHARES >> 8) & 0xFF);
	*header++ = (unsigned char)((MBEDTLS_TLS_EXT_KEY_SHARES) & 0xFF);

	// Write total extension length
	*header++ = (unsigned char)(((len + 2) >> 8) & 0xFF);
	*header++ = (unsigned char)(((len + 2)) & 0xFF);

	// Write length of the first (and currently only) client_share entry
	*header++ = (unsigned char)(((len) >> 8) & 0xFF);
	*header++ = (unsigned char)(((len)) & 0xFF);

	*olen = len + 6; // 6 bytes for fixed header + length of key share
	return 0;
}

#endif /* MBEDTLS_ECDH_C && MBEDTLS_ECDSA_C */

static int ssl_write_client_hello(mbedtls_ssl_context *ssl)
{
	int ret;
	size_t i, n, olen =0, ext_len = 0;
	unsigned char *buf, *extension_start; //  , *start_point;
	unsigned char *p, *q;
#if defined(MBEDTLS_ZLIB_SUPPORT)
	unsigned char offer_compress;
#endif
	const int *ciphersuites;
	const mbedtls_ssl_ciphersuite_t *ciphersuite_info;

	MBEDTLS_SSL_DEBUG_MSG(2, ("=> write client hello"));
	ssl->handshake->extensions_present = NO_EXTENSION;

	if (ssl->conf->f_rng == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("no RNG provided"));
		return(MBEDTLS_ERR_SSL_NO_RNG);
	}

	ssl->major_ver = ssl->conf->min_major_ver;
	ssl->minor_ver = ssl->conf->min_minor_ver;


	if (ssl->conf->max_major_ver == 0)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("configured max major version is invalid, "
			"consider using mbedtls_ssl_config_defaults()"));
		return(MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
	}

	/*
	*     0  .   0   handshake type
	*     1  .   3   handshake length
	*     4  .   5   highest version supported
	*     6  .   9   current UNIX time
	*    10  .  37   random bytes
	*/
	buf = ssl->out_msg;
	p = buf + 4;


	/* We use the legacy version number {0x03, 0x03}
	*  instead of the true version number. 
	*/
	*p++ = 0x03; 
	*p++ = 0x03;

	/* 32 bytes generated by a secure random number generator. */
	if ((ret = ssl_generate_random(ssl)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "ssl_generate_random", ret);
		return(ret);
	}

	memcpy(p, &ssl->handshake->randbytes[0], 32);
	MBEDTLS_SSL_DEBUG_BUF(3, "client hello, random bytes", p, 32);
	p += 32;

	/* In TLS 1.3 we do not make use of session resumption. 
	 * For every TLS 1.3 ClientHello, this vector MUST contain 
	 * exactly one byte set to zero, which corresponds to 
	 * the "null" compression method in prior versions of TLS.
	 */
	*p++ = 0; // session id length

	/*
	* DTLS cookie
	*/
#if defined(MBEDTLS_SSL_PROTO_DTLS)
	if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM)
	{
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
		/* For DTLS 1.3 we don't put the cookie in the ClientHello header
		 * but rather into an extension.
		*/
		MBEDTLS_SSL_DEBUG_MSG(3, ("DTLS 1.3: no cookie in header"));
		*p++ = 0; // Cookie length set to zero
	}
#else 
		if (ssl->handshake->verify_cookie == NULL)
		{
			MBEDTLS_SSL_DEBUG_MSG(3, ("no verify cookie to send"));
			*p++ = 0;
		}
		else
		{
			MBEDTLS_SSL_DEBUG_BUF(3, "client hello, cookie",
				ssl->handshake->verify_cookie,
				ssl->handshake->verify_cookie_len);

			*p++ = ssl->handshake->verify_cookie_len;
			memcpy(p, ssl->handshake->verify_cookie,
				ssl->handshake->verify_cookie_len);
			p += ssl->handshake->verify_cookie_len;
		}
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#endif /* MBEDTLS_SSL_PROTO_DTLS */

	/*
	* Ciphersuite list
	* 
	* This is a list of the symmetric cipher options supported by 
	* the client, specifically the record protection algorithm 
	* (including secret key length) and a hash to be used with 
	* HKDF, in descending order of client preference.
	*/
	ciphersuites = ssl->conf->ciphersuite_list[ssl->minor_ver];

	/* Skip writing ciphersuite length for now */
	n = 0;
	q = p;
	p += 2;

	for (i = 0; ciphersuites[i] != 0; i++)
	{
		ciphersuite_info = mbedtls_ssl_ciphersuite_from_id(ciphersuites[i]);

		if (ciphersuite_info == NULL)
			continue;
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
		if (ciphersuite_info->min_minor_ver != MBEDTLS_SSL_MINOR_VERSION_4 ||
			ciphersuite_info->max_minor_ver != MBEDTLS_SSL_MINOR_VERSION_4)
			continue;
#else
		if (ciphersuite_info->min_minor_ver > ssl->conf->max_minor_ver ||
			ciphersuite_info->max_minor_ver < ssl->conf->min_minor_ver)
			continue;
#endif 
/*#if defined(MBEDTLS_SSL_PROTO_DTLS)
		if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
			(ciphersuite_info->flags & MBEDTLS_CIPHERSUITE_NODTLS))
			continue;
#endif
*/
		MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, add ciphersuite: %04x, %s",
			ciphersuites[i], ciphersuite_info->name));

		n++;
		*p++ = (unsigned char)(ciphersuites[i] >> 8);
		*p++ = (unsigned char)(ciphersuites[i]);
#if defined(MBEDTLS_ZERO_RTT)
		// For ZeroRTT we only add a single ciphersuite. 
		break; 
#endif 
	}
	/* write ciphersuite length now */
	*q++ = (unsigned char)(n >> 7);
	*q++ = (unsigned char)(n << 1);

	MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, got %d ciphersuites", n));

	/* For every TLS 1.3 ClientHello, this vector MUST contain exactly 
	 * one byte set to zero, which corresponds to the “null” compression 
	 * method in prior versions of TLS.
     */ 

	*p++ = 1;
	*p++ = MBEDTLS_SSL_COMPRESS_NULL;

	// First write extensions, then the total length
	extension_start = p;

	/* Supported Versions Extension is mandatory with TLS 1.3 */
	ssl_write_supported_versions_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
	/* For TLS / DTLS 1.3 we need to support the use of cookies 
	 * (if the server provided them) */
	ssl_write_cookie_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#if defined(MBEDTLS_SSL_ALPN)
	ssl_write_alpn_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif /* MBEDTLS_SSL_ALPN */

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
	ssl_write_max_fragment_length_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_ZERO_RTT)
	ssl_write_early_data_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif /* MBEDTLS_ZERO_RTT */

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
	ssl_write_hostname_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
	/* For PSK-based ciphersuites we need the pre-shared-key extension
	 * and the psk_key_exchange_modes extension.
	 *
	 * The pre_shared_key_ext extension MUST be the last extension in the ClientHello.
	 * Servers MUST check that it is the last extension and otherwise fail the handshake
	 * with an "illegal_parameter" alert.
	 */

	 /* Add the psk_key_exchange_modes extension.
	 */
	if (ssl->conf->key_exchange_modes != KEY_EXCHANGE_MODE_ECDHE_ECDSA) {
		ret = ssl_write_psk_key_exchange_modes_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;

		if (ret == 0) ssl->handshake->extensions_present += PSK_KEY_EXCHANGE_MODES_EXTENSION;
	}
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

#if defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)

	/* The supported_groups and the key_share extensions are
 	 * REQUIRED for ECDHE ciphersuites.
	 */
	if (ssl->conf->key_exchange_modes == KEY_EXCHANGE_MODE_ECDHE_ECDSA ||
		ssl->conf->key_exchange_modes == KEY_EXCHANGE_MODE_PSK_DHE_KE ||
		ssl->conf->key_exchange_modes == KEY_EXCHANGE_MODE_PSK_ALL) {

		ret = ssl_write_supported_groups_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;

		if (ret == 0) ssl->handshake->extensions_present += SUPPORTED_GROUPS_EXTENSION;
	}
	/* The supported_signature_algorithms extension is REQUIRED for
	* certificate authenticated ciphersuites.
	*/

	if (ssl->conf->key_exchange_modes == KEY_EXCHANGE_MODE_ECDHE_ECDSA) {
		ret = ssl_write_signature_algorithms_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;

		if (ret == 0) ssl->handshake->extensions_present += SIGNATURE_ALGORITHM_EXTENSION;
	}
	/* We need to send the key shares under two conditions:
	 * 1) A certificate-based ciphersuite is being offered. In this case
	 *    supported_groups and supported_signature extensions have been successfully added.
	 * 2) A PSK-based ciphersuite with ECDHE is offered. In this case the
	 *    psk_key_exchange_modes has been added. The will have to be added last pre_shared_key extension.
	 */
	if (ssl->conf->key_exchange_modes == KEY_EXCHANGE_MODE_PSK_DHE_KE || 
		ssl->conf->key_exchange_modes == KEY_EXCHANGE_MODE_PSK_ALL) {
		// We are using a PSK-based key exchange with DHE
		ret = ssl_write_key_shares_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;

		if (ret == 0) ssl->handshake->extensions_present += KEY_SHARE_EXTENSION;
	} 	
	else if (ssl->handshake->extensions_present & SUPPORTED_GROUPS_EXTENSION && ssl->handshake->extensions_present & SIGNATURE_ALGORITHM_EXTENSION) {
		// We are using a certificate-based key exchange
		ret = ssl_write_key_shares_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;

		if (ret == 0) ssl->handshake->extensions_present += KEY_SHARE_EXTENSION;
	}
#endif /* MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)

	if (ssl->conf->key_exchange_modes == KEY_EXCHANGE_MODE_PSK_ALL ||
		ssl->conf->key_exchange_modes == KEY_EXCHANGE_MODE_PSK_KE ||
		ssl->conf->key_exchange_modes == KEY_EXCHANGE_MODE_PSK_DHE_KE) {

		//start_point = p + 2 + ext_len; 
		ssl->handshake->pre_shared_key_pointer = p + 2 + ext_len;
		ret = ssl_write_pre_shared_key_ext(ssl, p + 2 + ext_len, &olen,0 );
		ext_len += olen;

		if (ret == 0) ssl->handshake->extensions_present += PRE_SHARED_KEY_EXTENSION;
	} 
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */
	

	MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, total extension length: %d",
		ext_len));

	MBEDTLS_SSL_DEBUG_BUF(3, "client hello extensions", extension_start, ext_len);

	if (ext_len > 0)
	{
		*p++ = (unsigned char)((ext_len >> 8) & 0xFF);
		*p++ = (unsigned char)((ext_len) & 0xFF);
		p += ext_len;
	}

	ssl->out_msglen = p - buf;
	ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
	ssl->out_msg[0] = MBEDTLS_SSL_HS_CLIENT_HELLO;

	MBEDTLS_SSL_DEBUG_BUF(3, "ClientHello", ssl->out_msg, ssl->out_msglen);

	if ((ret = mbedtls_ssl_write_record(ssl)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_write_record", ret);
		return(ret);
	}

	MBEDTLS_SSL_DEBUG_MSG(2, ("<= write client hello"));

	return(0);
}


#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
static int ssl_parse_max_fragment_length_ext(mbedtls_ssl_context *ssl,
	const unsigned char *buf,
	size_t len)
{
	/*
	* server should use the extension only if we did,
	* and if so the server's value should match ours (and len is always 1)
	*/
	if (ssl->conf->mfl_code == MBEDTLS_SSL_MAX_FRAG_LEN_NONE ||
		len != 1 ||
		buf[0] != ssl->conf->mfl_code)
	{
		return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);
	}

	return(0);
}
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */


#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED) 

/*
 * struct {
 *   opaque identity<1..2^16-1>;
 *   uint32 obfuscated_ticket_age;
 * } PskIdentity;
 *
 * opaque PskBinderEntry<32..255>;
 *
 * struct {
 *   select (Handshake.msg_type) {
 *     case client_hello:
 *          PskIdentity identities<7..2^16-1>;
 *          PskBinderEntry binders<33..2^16-1>;
 *     case server_hello:
 *          uint16 selected_identity;
 *   };
 *
 * } PreSharedKeyExtension;
 *
 */

static int ssl_parse_server_psk_identity_ext(mbedtls_ssl_context *ssl,
	const unsigned char *buf,
	size_t len)
{
	int ret = 0;
	size_t selected_identity;

	if (ssl->conf->f_psk == NULL &&
		(ssl->conf->psk == NULL || ssl->conf->psk_identity == NULL ||
			ssl->conf->psk_identity_len == 0 || ssl->conf->psk_len == 0))
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("got no pre-shared key"));
		return(MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED);
	}

	if (len != (size_t)2)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("bad psk_identity extension in server hello message"));
		return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);
	}

	selected_identity = (buf[0] << 8) | buf[1];

	if (selected_identity > 0) {
		MBEDTLS_SSL_DEBUG_MSG(1, ("Unknown identity"));

		if ((ret = mbedtls_ssl_send_alert_message(ssl,
			MBEDTLS_SSL_ALERT_LEVEL_FATAL,
			MBEDTLS_SSL_ALERT_MSG_UNKNOWN_PSK_IDENTITY)) != 0)
		{
			return(ret);
		}

		return(MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY);
	}

	buf += 2;
	ssl->handshake->extensions_present += PRE_SHARED_KEY_EXTENSION;
	return(0);
}

#endif

#if (defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C))

/* TODO: Code for MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED missing */
/*

ssl_parse_key_shares_ext() verifies whether the information in the extension
is correct and stores the provided key shares.

*/

/*
*
*    struct {
select (Handshake.msg_type) {
case client_hello:
KeyShareEntry client_shares<0..2^16-1>;

case hello_retry_request:
NamedGroup selected_group;

case server_hello:
KeyShareEntry server_share;
};
} KeyShare;

*/

static int ssl_parse_key_shares_ext(mbedtls_ssl_context *ssl,
	const unsigned char *buf,
	size_t len) {

	int ret = 0;
	unsigned char *end = (unsigned char*)buf + len;
	unsigned char *start = (unsigned char*)buf;

	int match_found = 0;

	const mbedtls_ecp_group_id *gid;

	// Is there a key share available at the server config? 
	/* if (ssl->conf->keyshare_ctx == NULL)
	{
	MBEDTLS_SSL_DEBUG_MSG(1, ("got no key share context"));

	if ((ret = mbedtls_ssl_send_fatal_handshake_failure(ssl)) != 0)
	return(ret);

	return MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO;
	}
	*/

/*	// read named group
	n = (buf[0] << 8) | buf[1];

	buf += 2; 

    // read length 
	n = (buf[0] << 8) | buf[1];

	if (n + 2 + 2 != len)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("bad key share extension in server hello message"));
		return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_KEY_SHARE);
	}

	// Jump over length field to the KeyShareEntry
	start += 4;
	*/

	// copy to ssl->handshake->ecdh_ctx
	//memcpy(&ssl->handshake->ecdh_ctx, &ssl->handshake->keyshare_ctx, sizeof(mbedtls_ecdh_context));
	//mbedtls_ecdh_context *redirect=NULL; 
	//redirect = &ssl->handshake->ecdh_ctx;
	//redirect = &ssl->conf->keyshare_ctx;

	if ((ret = mbedtls_ecdh_read_params(&ssl->handshake->ecdh_ctx,
		(const unsigned char **)&start, end)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, ("mbedtls_ecdh_read_params"), ret);
		return(ret);
	}

	if (check_ecdh_params(ssl) != 0)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("check_ecdh_params() failed!"));
		return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE);
	}

	// Does the provided key share match any of our supported groups
	// We should also check what we provided in the initial Client Hello
	for (gid = ssl->conf->curve_list; *gid != MBEDTLS_ECP_DP_NONE; gid++) {
		// Currently we only support a single key share
		// Hence, we do not need a loop
		if (ssl->handshake->ecdh_ctx.grp.id == *gid) {
			match_found = 1;
			break;
		}
	}

	if (match_found == 0)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("no matching curve for ECDHE"));
		return(-1);
	}

	ssl->handshake->extensions_present += KEY_SHARE_EXTENSION;
	return ret;
}
#endif
 
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
static int ssl_write_certificate_verify(mbedtls_ssl_context *ssl, int from)
{

int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
//const mbedtls_ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;
size_t n = 0, offset = 0;
unsigned char hash[MBEDTLS_MD_MAX_SIZE];
unsigned char *hash_start = hash;
mbedtls_md_type_t md_alg = MBEDTLS_MD_NONE;
unsigned int hashlen;

MBEDTLS_SSL_DEBUG_MSG(2, ("=> write certificate verify"));

// CertificateVerify is only sent with a cert-based key exchange 
if (ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK ||
	ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK)
{
	MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip write certificate verify"));
	return(0);
}

/* Clients MUST send this message whenever authenticating via a Certificate 
 * (i.e., when the Certificate message is non-empty). 
 */

if (ssl->client_auth == 0 || mbedtls_ssl_own_cert(ssl) == NULL || ssl->conf->authmode == MBEDTLS_SSL_VERIFY_NONE)
{
	MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip write certificate verify"));
	return(0);
}

if (mbedtls_ssl_own_key(ssl) == NULL)
{
	MBEDTLS_SSL_DEBUG_MSG(1, ("got no private key for certificate"));
	return(MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED);
}

/*
* Create signature of the handshake digests
*/
ssl->handshake->calc_verify(ssl, hash, from);

if (ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_4)
{
	/*
	* digitally-signed struct {
	*     opaque handshake_messages[handshake_messages_length];
	* };
	*
	* Taking shortcut here. We assume that the server always allows the
	* PRF Hash function and has sent it in the allowed signature
	* algorithms list received in the Certificate Request message.
	*
	* Until we encounter a server that does not, we will take this
	* shortcut.
	*
	* Reason: Otherwise we should have running hashes for SHA512 and SHA224
	*         in order to satisfy 'weird' needs from the server side.
	*/
	if (ssl->transform_negotiate->ciphersuite_info->hash ==
		MBEDTLS_MD_SHA384)
	{
		md_alg = MBEDTLS_MD_SHA384;
		ssl->out_msg[4] = MBEDTLS_SSL_HASH_SHA384;
	}
	else
	{
		md_alg = MBEDTLS_MD_SHA256;
		ssl->out_msg[4] = MBEDTLS_SSL_HASH_SHA256;
	}
	ssl->out_msg[5] = mbedtls_ssl_sig_from_pk(mbedtls_ssl_own_key(ssl));

	/* Info from md_alg will be used instead */
	hashlen = 0;
	offset = 2;
}
else 
{
	MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
	return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
}

if ((ret = mbedtls_pk_sign(mbedtls_ssl_own_key(ssl), md_alg, hash_start, hashlen,
	ssl->out_msg + 6 + offset, &n,
	ssl->conf->f_rng, ssl->conf->p_rng)) != 0)
{
	MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_pk_sign", ret);
	return(ret);
}

ssl->out_msg[4 + offset] = (unsigned char)(n >> 8);
ssl->out_msg[5 + offset] = (unsigned char)(n);

ssl->out_msglen = 6 + n + offset;
ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
ssl->out_msg[0] = MBEDTLS_SSL_HS_CERTIFICATE_VERIFY;

if ((ret = mbedtls_ssl_write_record(ssl)) != 0)
{
	MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_write_record", ret);
	return(ret);
}

MBEDTLS_SSL_DEBUG_MSG(2, ("<= write certificate verify"));

return(ret);
}
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED && MBEDTLS_SSL_PROTO_TLS1_3 */

#if defined(MBEDTLS_SSL_ALPN)
static int ssl_parse_alpn_ext(mbedtls_ssl_context *ssl,
	const unsigned char *buf, size_t len)
{
	size_t list_len, name_len;
	const char **p;

	/* If we didn't send it, the server shouldn't send it */
	if (ssl->conf->alpn_list == NULL)
		return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);

	/*
	* opaque ProtocolName<1..2^8-1>;
	*
	* struct {
	*     ProtocolName protocol_name_list<2..2^16-1>
	* } ProtocolNameList;
	*
	* the "ProtocolNameList" MUST contain exactly one "ProtocolName"
	*/

	/* Min length is 2 (list_len) + 1 (name_len) + 1 (name) */
	if (len < 4)
		return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);

	list_len = (buf[0] << 8) | buf[1];
	if (list_len != len - 2)
		return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);

	name_len = buf[2];
	if (name_len != list_len - 1)
		return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);

	/* Check that the server chosen protocol was in our list and save it */
	for (p = ssl->conf->alpn_list; *p != NULL; p++)
	{
		if (name_len == strlen(*p) &&
			memcmp(buf + 3, *p, name_len) == 0)
		{
			ssl->alpn_chosen = *p;
			return(0);
		}
	}

	return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);
}
#endif /* MBEDTLS_SSL_ALPN */



#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

/* ssl_parse_hello_retry_request()

Otherwise, the client MUST send a ClientHello with an updated KeyShare
extension to the server.The client MUST append a new KeyShareEntry for
the group indicated in the selected_group field to the groups in its
original KeyShare.

Upon re - sending the ClientHello and receiving the server's ServerHello
/ KeyShare, the client MUST verify that the selected CipherSuite and
NamedGroup match that supplied in the HelloRetryRequest. If either of
these values differ, the client MUST abort the connection with a fatal
"handshake_failure" alert.
*/

static int ssl_parse_hello_retry_request(mbedtls_ssl_context *ssl,
	const unsigned char *buf, size_t len)
{
	const unsigned char *p = buf; // ssl->in_msg + mbedtls_ssl_hs_hdr_len(ssl);
	int major_ver, minor_ver;

	/* Pointer to the extension buffer. */
	unsigned char *ext;
	/* Total length of the all possible extensions contained on the
	message based on message length len minus the fixed length
	field mandatorily present in the message. */
	size_t ext_expected_len;
	/* Length of a single extension as retrieved from the extension
	* length field itself. */
	size_t ext_size;
	/* Extension ID as retrieved from the extension id field. */
	unsigned int ext_id;
	const mbedtls_ssl_ciphersuite_t *suite_info;
	int i;

#if defined(MBEDTLS_ECDH_C)
	const mbedtls_ecp_group_id *grp_id, *first=NULL;
    const mbedtls_ecp_curve_info *info, *first_curve = NULL;
	int tls_id; 
#endif

	MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse hello retry request"));

	/*
	* struct {
	*    ProtocolVersion server_version;
	*    CipherSuite cipher_suite;
	*    Extension extensions<2..2^16-1>;
	* } HelloRetryRequest;
	*/

	MBEDTLS_SSL_DEBUG_BUF(3, "server version", p, 2);
	mbedtls_ssl_read_version(&major_ver, &minor_ver, ssl->conf->transport, p);
	p += 2;

	/*
	* We only accept a TLS/DTLS 1.3 version. 
	*/
	if (major_ver != MBEDTLS_SSL_MAJOR_VERSION_3 && 
		minor_ver != MBEDTLS_SSL_MINOR_VERSION_4 && 
		major_ver != ssl->conf->max_major_ver &&
		minor_ver != ssl->conf->max_minor_ver)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("bad server version; TLS/DTLS 1.3 assumed"));

		mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
			MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION);

		return(MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION);
	}

	// read server-selected ciphersuite
	i = (p[0] << 8) | p[1];
	p += 2; 

	// Configure ciphersuites
	ssl->transform_negotiate->ciphersuite_info = mbedtls_ssl_ciphersuite_from_id(i);

	if (ssl->transform_negotiate->ciphersuite_info == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("ciphersuite info for %04x not found", i));
		return(MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
	}

	// mbedtls_ssl_optimize_checksum(ssl, ssl->transform_negotiate->ciphersuite_info);

	// TBD: Check whether the server-selected ciphersuite matches what we have previously sent
	ssl->session_negotiate->ciphersuite = i;

	suite_info = mbedtls_ssl_ciphersuite_from_id(ssl->session_negotiate->ciphersuite);
	if (suite_info == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("bad server hello message"));
		return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);
	}
	MBEDTLS_SSL_DEBUG_MSG(3, ("hello retry request, chosen ciphersuite: (%04x) - %s", i, suite_info->name));

	// total length of the extensions
	ext_expected_len = ((p[0] << 8) | (p[1]));
	p += 2; 

	MBEDTLS_SSL_DEBUG_MSG(2, ("hello retry request, total extension length: %d", ext_expected_len));

	/* 
	 * Upon receipt of a HelloRetryRequest, the client MUST verify that the extensions block is 
	 * not empty and otherwise MUST abort the handshake with a “decode_error” alert.
	 * 
	 */
	if (ext_expected_len == 0) {
			MBEDTLS_SSL_DEBUG_MSG(1, ("Extensions of the HelloRetryRequest message must not be empty"));
			mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL, MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
			return(MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST);
	}
	
	if (ext_expected_len == len -6 ) {

		ext = (unsigned char*)p;

		while (ext_expected_len != 0)
		{
			ext_id = ((ext[0] << 8) | (ext[1]));
			ext_size = ((ext[2] << 8) | (ext[3]));

			if (ext_size + 4 > ext_expected_len)
			{
				MBEDTLS_SSL_DEBUG_MSG(1, ("bad hello retry request message"));
				return(MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST);
			}
			ext += 4; // skip header

			switch (ext_id)
			{
#if defined(MBEDTLS_SSL_COOKIE_C)
			case MBEDTLS_TLS_EXT_COOKIE:

				MBEDTLS_SSL_DEBUG_BUF(3, "cookie extension", ext, ext_size);

				mbedtls_free(ssl->handshake->verify_cookie);

				ssl->handshake->verify_cookie = mbedtls_calloc(1, ext_size);
				if (ssl->handshake->verify_cookie == NULL)
				{
					MBEDTLS_SSL_DEBUG_MSG(1, ("alloc failed (%d bytes)", ext_size));
					return(MBEDTLS_ERR_SSL_ALLOC_FAILED);
				}

				memcpy(ssl->handshake->verify_cookie, ext, ext_size);
				ssl->handshake->verify_cookie_len = (unsigned char)ext_size;
				break;
#endif /* MBEDTLS_SSL_COOKIE_C */


#if defined(MBEDTLS_ECDH_C)
			case MBEDTLS_TLS_EXT_KEY_SHARES:

				MBEDTLS_SSL_DEBUG_BUF(3, "key_share extension", ext, ext_size);

				// Read selected_group
				tls_id = ((ext[0] << 8) | (ext[1]));
				MBEDTLS_SSL_DEBUG_MSG(3, ("selected_group (%d)", tls_id));

				/* 
				 * Upon receipt of this extension in a HelloRetryRequest, the client
				 * MUST first verify that the selected_group field corresponds to a
				 * group which was provided in the "supported_groups" extension in the
				 * original ClientHello.
				 * 
				 * The supported_group was based on the info in ssl->conf->curve_list.
 				 */ 
				
				for (grp_id = ssl->conf->curve_list; *grp_id != MBEDTLS_ECP_DP_NONE; grp_id++) {
					// In the ClientHello we transmitted the key share for the first entry in the list.
					if (first == NULL) first = grp_id; 
					info = mbedtls_ecp_curve_info_from_grp_id(*grp_id);					
					if (info->tls_id == tls_id) break; 
				}

				/* 
				 * It MUST then verify that the selected_group
				 * field does not correspond to a group which was provided in the
				 * "key_share" extension in the original ClientHello.If either of
				 * these checks fails, then the client MUST abort the handshake with an
				 * "illegal_parameter" alert.
				 *
				 * We sent a single key share only, which was the first one on the list. 
				 * If *grp_id != MBEDTLS_ECP_DP_NONE then we found a match and 
				 * now we only need to find out whether the named group from the
				 * HelloRetryRequest matches the named group we sent in the ClientHello.
				 */
				if (*grp_id != MBEDTLS_ECP_DP_NONE) {
					first_curve = mbedtls_ecp_curve_info_from_grp_id(*first);
				  if (first_curve->grp_id != info->grp_id) {
					  mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL, MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
					  MBEDTLS_SSL_DEBUG_MSG(1, ("bad hello retry request message (key share didn't match)"));
					  return(MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST);
				  }
				}

				break;
#endif /* MBEDTLS_ECDH_C */
			default:
				MBEDTLS_SSL_DEBUG_MSG(3, ("unknown extension found: %d (ignoring)", ext_id));
			}

			// Jump to next extension
			ext += ext_size;
			ext_expected_len = ext_expected_len - ext_size - 4;
		}
	}
	else {
		MBEDTLS_SSL_DEBUG_MSG(1, ("bad hello retry request message"));
		return(MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST);
	}


	/* Start over at ClientHello */
	//	ssl->state = MBEDTLS_SSL_CLIENT_HELLO;
	//mbedtls_ssl_reset_checksum(ssl);

#if defined(MBEDTLS_SSL_PROTO_DTLS)
	mbedtls_ssl_recv_flight_completed(ssl);
#endif 
	MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse hello retry request"));

	return(0);
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#if !defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
static int ssl_parse_certificate_request(mbedtls_ssl_context *ssl)
{
	const mbedtls_ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;

	MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse certificate request"));

	if (ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK ||
		ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK )
	{
		MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip parse certificate request"));
		ssl->state++;
		return(0);
	}

	MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
	return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
}
#else
static int ssl_parse_certificate_request(mbedtls_ssl_context *ssl)
{
	int ret;
	unsigned char *p, *ext;
	size_t ext_len = 0, total_len;
	int context_len=0;

	MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse certificate request"));

	if (ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK ||
		ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK)
	{
		MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip parse certificate request"));
		return(0);
	}

	if (ssl->record_read == 0)
	{
		if ((ret = mbedtls_ssl_read_record(ssl)) != 0)
		{
			MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_read_record", ret);
			return(ret);
		}

		if (ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE)
		{
			MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate request message"));
			return(MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE);
		}

		ssl->record_read = 1;
	}

	ssl->client_auth = 0;

	// Determine whether we got a certificate request message or not
	if (ssl->in_msg[0] == MBEDTLS_SSL_HS_CERTIFICATE_REQUEST)
		ssl->client_auth++;

	MBEDTLS_SSL_DEBUG_MSG(3, ("got %s certificate request",
		ssl->client_auth ? "a" : "no"));

	if (ssl->client_auth == 0) {
		// We don't do client auth.
		MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip parse certificate request (no client auth)"));
		return (0);
	}
		
	ssl->record_read = 0;

	/*
	*
	* struct {
	*   opaque certificate_request_context<0..2^8-1>;
	*   Extension extensions<2..2^16-1>;
	* } CertificateRequest;
	*
	*/

	p = ssl->in_msg;

	// Determine total message length
	total_len = (p[2] << 8) | p[3];

	p += mbedtls_ssl_hs_hdr_len(ssl);

	/*
	* Parse certificate_request_context
	*/
	context_len = p[0];

	// skip context_len
	p++;

	/* Fixed length fields are: 
	 *  - 1 for length of context  
	 *  - 2 for length of extensions
	 * -----
	 *    3 bytes
	 */

	if (total_len< (size_t) (3 + context_len)) {
		MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate request message"));
		return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST);
	}

	// store context (if necessary)
	if (context_len > 0) {
		MBEDTLS_SSL_DEBUG_BUF(3, "Certificate Request Context", p, context_len);

		ssl->handshake->certificate_request_context= mbedtls_calloc(context_len,1);
		if (ssl->handshake->certificate_request_context == NULL) {
			MBEDTLS_SSL_DEBUG_MSG(1, ("buffer too small"));
			return (MBEDTLS_ERR_SSL_ALLOC_FAILED);
		}
		memcpy(ssl->handshake->certificate_request_context, p, context_len);

		// jump over certificate_request_context
		p += context_len;
	}

	/*
	* Parse extensions
	*/
	ext_len = (p[0] << 8) | (p[1]);

	// At least one extension needs to be present, namely signature_algorithms ext.
	if (ext_len < 4)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate request message"));
		return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST);
	}

	// skip total extension length
	p += 2; 

	ext = p; // jump to extensions
	while (ext_len)
	{

		unsigned int ext_id = ((ext[0] << 8) | (ext[1]));
		unsigned int ext_size = ((ext[2] << 8) | (ext[3]));

		if (ext_size + 4 > ext_len)
		{
			MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate request message"));
			return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST);
		}

		switch (ext_id)
		{

		case MBEDTLS_TLS_EXT_SIG_ALG:
			MBEDTLS_SSL_DEBUG_MSG(3, ("found signature_algorithms extension"));

			if ((ret = ssl_parse_signature_algorithms_ext(ssl, ext + 4, (size_t)ext_size)) != 0)
			{
				MBEDTLS_SSL_DEBUG_RET(1, "ssl_parse_signature_algorithms_ext", ret);
				return(ret);
			}
			break;

		default:
			MBEDTLS_SSL_DEBUG_MSG(3, ("unknown extension found: %d (ignoring)",
				ext_id));
		}

		ext_len -= 4 + ext_size;
		ext += 4 + ext_size;

		if (ext_len > 0 && ext_len < 4)
		{
			MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate request message"));
			return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST);
		}
	}

	MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse certificate request"));

	return(0);
}
#endif /* !MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */


static int ssl_parse_encrypted_extensions(mbedtls_ssl_context *ssl)
{
	int ret=0;
	size_t ext_len;
	unsigned char *buf, *ext;

	MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse encrypted extension"));

	if ((ret = mbedtls_ssl_read_record(ssl)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_read_record", ret);
		return(ret);
	}

	if (ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("bad handshake message"));
		return(MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE);
	}

	buf = ssl->in_msg; 
	if (buf[0] != MBEDTLS_SSL_HS_ENCRYPTED_EXTENSION) {
	
		MBEDTLS_SSL_DEBUG_MSG(1, ("bad encrypted extensions message"));
		return(MBEDTLS_ERR_SSL_BAD_HS_ENCRYPTED_EXTENSIONS);
	}

	// skip handshake header
	buf += mbedtls_ssl_hs_hdr_len(ssl);

	ext_len = ((buf[0] << 8) | (buf[1]));

	buf += 2; // skip extension length
	ext = buf;

	if ((ext_len > 0 && ext_len < 4) || ssl->in_hslen != mbedtls_ssl_hs_hdr_len(ssl) + 2 + ext_len)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("bad encrypted extensions message"));
		return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);
	}

	MBEDTLS_SSL_DEBUG_MSG(2, ("encrypted extensions, total extension length: %d", ext_len));

	MBEDTLS_SSL_DEBUG_BUF(3, "encrypted extensions extensions", ext, ext_len);

	while (ext_len)
	{
		unsigned int ext_id = ((ext[0] << 8)
			| (ext[1]));
		unsigned int ext_size = ((ext[2] << 8)
			| (ext[3]));

		if (ext_size + 4 > ext_len)
		{
			MBEDTLS_SSL_DEBUG_MSG(1, ("bad encrypted extensions message"));
			return(MBEDTLS_ERR_SSL_BAD_HS_ENCRYPTED_EXTENSIONS);
		}

		switch (ext_id)
		{

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
		case MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH:
			MBEDTLS_SSL_DEBUG_MSG(3, ("found max_fragment_length extension"));

			if ((ret = ssl_parse_max_fragment_length_ext(ssl,
				ext + 4, ext_size)) != 0)
			{
				return(ret);
			}

			break;
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */


#if defined(MBEDTLS_SSL_ALPN)
		case MBEDTLS_TLS_EXT_ALPN:
			MBEDTLS_SSL_DEBUG_MSG(3, ("found alpn extension"));

			if ((ret = ssl_parse_alpn_ext(ssl, ext + 4, (size_t)ext_size)) != 0)
				return(ret);

			break;
#endif /* MBEDTLS_SSL_ALPN */


		default:
			MBEDTLS_SSL_DEBUG_MSG(3, ("unknown extension found: %d (ignoring)",
				ext_id));
		}

			ext_len -= 4 + ext_size;
			ext += 4 + ext_size;

			if (ext_len > 0 && ext_len < 4)
			{
				MBEDTLS_SSL_DEBUG_MSG(1, ("bad encrypted extensions message"));
				return(MBEDTLS_ERR_SSL_BAD_HS_ENCRYPTED_EXTENSIONS);
			}
	}

	MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse encrypted extension"));

	return ret;
}

/* ssl_parse_server_hello() for processing the ServerHello message. 
 * 
 * The structure of the message is defined as: 
 *
 * struct {
 *    ProtocolVersion version;
 *    Random random;
 *    CipherSuite cipher_suite;
 *    Extension extensions<0..2^16-1>;
 * } ServerHello;
 * 
 * The header upfront is: 
 *     0  .   0   handshake type
 *     1  .   3   handshake length
*/

static int ssl_parse_server_hello(mbedtls_ssl_context *ssl)
{
	int ret, i, total_len;
	//    size_t n;
	size_t ext_len;
	unsigned char *buf, *ext;
	const mbedtls_ssl_ciphersuite_t *suite_info;
	
	if ((ret = mbedtls_ssl_read_record(ssl)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_read_record", ret);
		return(ret);
	}

	buf = ssl->in_msg;
	// length information is in header 
	total_len = (buf[2] << 8) | buf[3];

	if (ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("unexpected message"));
		return(MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE);
	}

#if defined(MBEDTLS_SSL_PROTO_DTLS) && !defined(MBEDTLS_SSL_PROTO_TLS1_3)
	if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM)
	{
#if defined (MBEDTLS_SSL_DTLS_HELLO_VERIFY)
		if (buf[0] == MBEDTLS_SSL_HS_HELLO_VERIFY_REQUEST)
		{
			MBEDTLS_SSL_DEBUG_MSG(2, ("received hello verify request"));

			if ((ret = ssl_parse_hello_verify_request(ssl)) != 0)
			{
				MBEDTLS_SSL_DEBUG_RET(1, "ssl_parse_hello_verify_request", ret);
			}
			else {
				// Change state back to the initial state to return ClientHello with Cookie
				ssl->state = MBEDTLS_SSL_CLIENT_HELLO;
			}
			return(ret);
		}
		else
#endif
		{
			/* We made it through the verification process */
			mbedtls_free(ssl->handshake->verify_cookie);
			ssl->handshake->verify_cookie = NULL;
			ssl->handshake->verify_cookie_len = 0;
		}
	}
#endif /* MBEDTLS_SSL_PROTO_DTLS && !MBEDTLS_SSL_PROTO_TLS1_3 */

	// Check whether this message is a HelloRetryRequest message
	if (buf[0] == MBEDTLS_SSL_HS_HELLO_RETRY_REQUEST)
	{
		size_t orig_msg_len;
		unsigned char *orig_buf;

		unsigned char transcript[MBEDTLS_MD_MAX_SIZE + 4]; // used to store the ClientHello1 msg
		int hash_length;
//		unsigned char padbuf[MBEDTLS_MD_MAX_SIZE]; // used to store the transcript hash

		orig_buf = &ssl->in_msg[0];
		orig_msg_len = ssl->in_msglen;

		MBEDTLS_SSL_DEBUG_MSG(2, ("received HelloRetryRequest message"));

		// skip header
		buf += mbedtls_ssl_hs_hdr_len(ssl);

		if ((ret = ssl_parse_hello_retry_request(ssl, buf, total_len)) != 0)
		{
			MBEDTLS_SSL_DEBUG_RET(1, "ssl_parse_hello_retry_request", ret);
		}
		else {
			// Change state back to the initial state to return ClientHello with Cookie
			// if (ssl->handshake->hello_retry_requests_received == 0) ssl->state = MBEDTLS_SSL_CLIENT_HELLO;
			
			ssl->handshake->hello_retry_requests_received++;

			MBEDTLS_SSL_DEBUG_MSG(5, ("--- Update Checksum (ssl_prepare_handshake_record)"));

			/* A special handling of the transcript hash is needed. We skipped
			* updating the transcript hash when the HRR message was received.
			*
			* 1. The current transcript hash was computed over the first ClientHello.
			* We need to compute a final hash of ClientHello1 and then put it
			* into the following structure:
			*
			*  Transcript-Hash(ClientHello1, HelloRetryRequest, ... MN) =
			*     Hash(message_hash ||        // Handshake Type
			*          00 00 Hash.length ||   // Handshake message length
			*	       Hash(ClientHello1) ||  // Hash of ClientHello1
			*          HelloRetryRequest ... MN)
			*
			* 2. Then, we need to reset the transcript and put the hash of the above-
			*    computed value.
			*
			*/

			transcript[0] = MBEDTLS_SSL_HS_MESSAGE_HASH;
			transcript[1] = 0;
			transcript[2] = 0;

			hash_length = mbedtls_hash_size_for_ciphersuite(ssl->transform_negotiate->ciphersuite_info);

			if (hash_length == -1) {
				MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_hash_size_for_ciphersuite == -1"));
				return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
			}

			transcript[3] = (uint8_t)hash_length;

/* #if defined(MBEDTLS_SHA256_C)
			mbedtls_sha256_context sha256;
#endif

#if defined(MBEDTLS_SHA512_C)
			mbedtls_sha512_context sha512;
#endif
*/
			if (ssl->transform_negotiate->ciphersuite_info->hash == MBEDTLS_MD_SHA256) {
#if defined(MBEDTLS_SHA256_C) 
				mbedtls_sha256_finish(&ssl->handshake->fin_sha256, &transcript[4]);
				MBEDTLS_SSL_DEBUG_BUF(5, "ClientHello1 hash", &transcript[4], 32);

				// reset transcript
				mbedtls_sha256_init(&ssl->handshake->fin_sha256);
				mbedtls_sha256_starts(&ssl->handshake->fin_sha256, 0 /* = use SHA256 */);
				//mbedtls_sha256_update(&ssl->handshake->fin_sha256, &transcript[0], hash_length + 4);
#else 
				MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_ssl_derive_master_secret: Unknow hash function."));
				return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
#endif 
			}
			else if (ssl->transform_negotiate->ciphersuite_info->hash == MBEDTLS_MD_SHA384) {
#if defined(MBEDTLS_SHA512_C)
				mbedtls_sha512_finish(&ssl->handshake->fin_sha512, &transcript[4]);
				MBEDTLS_SSL_DEBUG_BUF(5, "ClientHello1 hash", &transcript[4], 48);

				// reset transcript
				mbedtls_sha512_init(&ssl->handshake->fin_sha512);
				mbedtls_sha512_starts(&ssl->handshake->fin_sha512, 1 /* = use SHA384 */);
				//mbedtls_sha256_update(&ssl->handshake->fin_sha512, &transcript[0], hash_length + 4);
#else 
				MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_ssl_derive_master_secret: Unknow hash function."));
				return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
#endif 
			}
			else if (ssl->transform_negotiate->ciphersuite_info->hash == MBEDTLS_MD_SHA512) {
#if defined(MBEDTLS_SHA512_C)
				mbedtls_sha512_finish(&ssl->handshake->fin_sha512, &transcript[4]);
				MBEDTLS_SSL_DEBUG_BUF(5, "ClientHello1 hash", &transcript[4], 64);
				
				// reset transcript
				mbedtls_sha512_init(&ssl->handshake->fin_sha512);
				mbedtls_sha512_starts(&ssl->handshake->fin_sha512, 0 /* = use SHA512 */);
				//mbedtls_sha256_update(&ssl->handshake->fin_sha512, &transcript[0], hash_length + 4); 
			}
			else {
#else 
				MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_ssl_derive_master_secret: Unknow hash function."));
				return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
#endif 
			}

			// hash modified transcript for ClientHello1
			ssl->handshake->update_checksum(ssl, &transcript[0], hash_length + 4);
			// Add transcript for HRR
			ssl->handshake->update_checksum(ssl, orig_buf, orig_msg_len);
		}
		return(ret);
	}

	MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse server hello"));

	// Check whether we got a ServerHello message
	if (buf[0] != MBEDTLS_SSL_HS_SERVER_HELLO)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("bad server hello message"));
		return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);
	}

	// Check for minimal length

	// 36 = 32 (random bytes) + 2 (ciphersuite) + 2 (version)
	if (ssl->in_hslen < 36 + mbedtls_ssl_hs_hdr_len(ssl)) {
		MBEDTLS_SSL_DEBUG_MSG(1, ("bad server hello message - min size not reached"));
		return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);
	}

	MBEDTLS_SSL_DEBUG_BUF(3, "server hello", ssl->in_msg, ssl->in_msglen);

	// skip header
	buf += mbedtls_ssl_hs_hdr_len(ssl);

	MBEDTLS_SSL_DEBUG_BUF(3, "server hello, version", buf + 0, 2);
	mbedtls_ssl_read_version(&ssl->major_ver, &ssl->minor_ver,
		ssl->conf->transport, buf + 0);

#if defined(TLS_DRAFT_VERSION_MAJOR) && defined(TLS_DRAFT_VERSION_MINOR)
// For test purposes we fix the version numbers. 
	ssl->major_ver = 0x03;
	ssl->minor_ver = 0x04;
#endif 

	if (ssl->conf->max_major_ver != ssl->major_ver ||
		ssl->conf->max_minor_ver != ssl->minor_ver)
	{


		/* Server provided version does not match the version 
		 * provided by the client in supported_versions extension.
		 */ 
		MBEDTLS_SSL_DEBUG_MSG(1, ("Unsupported version of TLS. Supported is [%d:%d]",
			ssl->conf->max_major_ver, ssl->conf->max_minor_ver));

		mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
			MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION);

		return(MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION);
	}

	// skip version 
	buf += 2;

	// server-provided random values
	memcpy(ssl->handshake->randbytes + 32, buf, 32);
	MBEDTLS_SSL_DEBUG_BUF(3, "server hello, random bytes", buf + 2, 32);

	// skip random bytes
	buf += 32;

	// read server-selected ciphersuite, which follows random bytes
	i = (buf[0] << 8) | buf[1];

	// skip ciphersuite
	buf += 2;

	// TBD: Check whether we have offered this ciphersuite 
	// Via the force_ciphersuite version we may have instructed the client 
	// to use a difference ciphersuite. 

	// Configure ciphersuites
	ssl->transform_negotiate->ciphersuite_info = mbedtls_ssl_ciphersuite_from_id(i);

	if (ssl->transform_negotiate->ciphersuite_info == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("ciphersuite info for %04x not found", i));
		return(MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
	}

	mbedtls_ssl_optimize_checksum(ssl, ssl->transform_negotiate->ciphersuite_info);

	ssl->session_negotiate->ciphersuite = i;

	suite_info = mbedtls_ssl_ciphersuite_from_id(ssl->session_negotiate->ciphersuite);
	if (suite_info == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("bad server hello message"));
		return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);
	}

	MBEDTLS_SSL_DEBUG_MSG(3, ("server hello, chosen ciphersuite: (%04x) - %s", i, suite_info->name));

#if defined(MBEDTLS_HAVE_TIME)
	ssl->session_negotiate->start = time(NULL);
#endif

	i = 0;
	while (1)
	{
		if (ssl->conf->ciphersuite_list[ssl->minor_ver][i] == 0)
		{
			MBEDTLS_SSL_DEBUG_MSG(1, ("bad server hello message"));
			return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);
		}

		if (ssl->conf->ciphersuite_list[ssl->minor_ver][i++] ==
			ssl->session_negotiate->ciphersuite)
		{
			break;
		}
	}

	if (ssl->in_hslen > mbedtls_ssl_hs_hdr_len(ssl) + 36)
	{
		ext_len = ((buf[0] << 8) | (buf[1]));

		if ((ext_len > 0 && ext_len < 4) || ssl->in_hslen != mbedtls_ssl_hs_hdr_len(ssl) + 38 + ext_len)
		{
			MBEDTLS_SSL_DEBUG_MSG(1, ("bad server hello message"));
			return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);
		}
	}
	else if (ssl->in_hslen == mbedtls_ssl_hs_hdr_len(ssl) + 38)
	{
		ext_len = 0;
	}
	else
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("bad server hello message"));
		return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);
	}

	buf += 2; // skip extension length
	ext = buf; 

	MBEDTLS_SSL_DEBUG_MSG(3, ("server hello, total extension length: %d", ext_len));

	MBEDTLS_SSL_DEBUG_BUF(3, "server hello extensions", ext, ext_len);

	ext = buf; // jump to extensions
	while (ext_len)
	{
		unsigned int ext_id = ((ext[0] << 8)
			| (ext[1]));
		unsigned int ext_size = ((ext[2] << 8)
			| (ext[3]));

		if (ext_size + 4 > ext_len)
		{
			MBEDTLS_SSL_DEBUG_MSG(1, ("bad server hello message"));
			return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);
		}

		switch (ext_id)
		{

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
		case MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH:
			MBEDTLS_SSL_DEBUG_MSG(3, ("found max_fragment_length extension"));

			if ((ret = ssl_parse_max_fragment_length_ext(ssl,
				ext + 4, ext_size)) != 0)
			{
				MBEDTLS_SSL_DEBUG_MSG(1, ("ssl_parse_max_fragment_length_ext (%d)", ret));
				return(ret);
			}

			break;
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

/* 
#if defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)

		case MBEDTLS_TLS_EXT_SIG_ALG:
			MBEDTLS_SSL_DEBUG_MSG(3, ("found supported_signature_algorithms extension"));

			if ((ret = ssl_parse_supported_signature_algorithms_client_ext(ssl,	ext + 4, ext_size)) != 0)
			{
				MBEDTLS_SSL_DEBUG_MSG(1, ("ssl_parse_supported_signature_algorithms_client_ext (%d)", ret));
				return(ret);
			}

			break;
#endif // MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED
*/

#if defined(MBEDTLS_SSL_ALPN)
		case MBEDTLS_TLS_EXT_ALPN:
			MBEDTLS_SSL_DEBUG_MSG(3, ("found alpn extension"));

			if ((ret = ssl_parse_alpn_ext(ssl, ext + 4, (size_t)ext_size)) != 0) {
				MBEDTLS_SSL_DEBUG_MSG(1, ("ssl_parse_alpn_ext (%d)", ret));
				return(ret);
			}

			break;
#endif /* MBEDTLS_SSL_ALPN */

#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
		case MBEDTLS_TLS_EXT_PRE_SHARED_KEY:
			MBEDTLS_SSL_DEBUG_MSG(3, ("found pre_shared_key extension"));
			if ((ret = ssl_parse_server_psk_identity_ext(ssl, ext + 4, (size_t) ext_size)) != 0)
			{
				MBEDTLS_SSL_DEBUG_RET(1, ("ssl_parse_server_psk_identity_ext"), ret);
				return(ret);
			}

			break;

#endif /* MBEDTLS_KEY_EXCHANGE_PSK_ENABLED */

#if defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) 
		case MBEDTLS_TLS_EXT_KEY_SHARES:
			MBEDTLS_SSL_DEBUG_MSG(3, ("found key_shares extension"));

			if ((ret = ssl_parse_key_shares_ext(ssl, ext + 4, (size_t) ext_size)) != 0)
			{
				MBEDTLS_SSL_DEBUG_RET(1, "ssl_parse_key_shares_ext", ret);
				return(ret);
			}
/*
			if (suite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK) {
				// Assume that the pre_shared_key extension has been processed already

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

				if ((ret = mbedtls_ssl_derive_master_secret(ssl, MBEDTLS_KEY_EXCHANGE_PSK)) != 0)
				{
					MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_derive_master_secret", ret);
					return(ret);
				}

#else 

				if ((ret = mbedtls_ssl_psk_derive_premaster(ssl, MBEDTLS_KEY_EXCHANGE_PSK)) != 0)
				{
					MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_psk_derive_premaster", ret);
					return(ret);
				}
#endif
			}
*/
			/*
			switch (suite_info->key_exchange)
			{
			case MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
			// Assume that the pre_shared_key extension has been processed already
			if ((ret = mbedtls_ssl_psk_derive_premaster(ssl,
			MBEDTLS_KEY_EXCHANGE_PSK)) != 0)
			{
			MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_psk_derive_premaster", ret);
			return(ret);
			}
			break;
			case MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
			MBEDTLS_SSL_DEBUG_RET(1, "server hello: ECDHE_ECDSA key exchange not yet implemented", ret);
			return(ret);
			break;
			case MBEDTLS_KEY_EXCHANGE_PSK:
			MBEDTLS_SSL_DEBUG_RET(1, "server hello: pre-shared key extension not compatible with PSK-only ciphersuite", ret);
			return(ret);
			break;
			default:
			MBEDTLS_SSL_DEBUG_RET(1, "server hello: unknown key exchange", ret);
			return(ret);
			}
			*/
			break;
#endif

		default:
			MBEDTLS_SSL_DEBUG_MSG(3, ("unknown extension found: %d (ignoring)",
				ext_id));
		}

		ext_len -= 4 + ext_size;
		ext += 4 + ext_size;

		if (ext_len > 0 && ext_len < 4)
		{
			MBEDTLS_SSL_DEBUG_MSG(1, ("bad server hello message"));
			return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);
		}
	}

#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
	/*
	* Renegotiation security checks
	*
	* NOT SUPPORTED IN TLS 1.3 */
	
	if( ssl->secure_renegotiation == MBEDTLS_SSL_LEGACY_RENEGOTIATION &&
	ssl->conf->allow_legacy_renegotiation == MBEDTLS_SSL_LEGACY_BREAK_HANDSHAKE )
	{
	MBEDTLS_SSL_DEBUG_MSG( 1, ( "legacy renegotiation, breaking off handshake" ) );
	handshake_failure = 1;
	}

	if( handshake_failure == 1 )
	{
	if( ( ret = mbedtls_ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
	return( ret );

	return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
	}
#endif

	/* We need to set the key exchange algorithm based on the  
	 * following rules: 
	 *   1) IF PRE_SHARED_KEY extension received THEN set MBEDTLS_KEY_EXCHANGE_PSK  
	 *   2) IF PRE_SHARED_KEY extension received && KEY_SHARE received THEN set MBEDTLS_KEY_EXCHANGE_ECDHE_PSK
	 *   3) IF KEY_SHARES extension received && SIG_ALG extension received THEN set MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA
	 *   ELSE unknown key exchange mechanism. 
	 */

	if (ssl->handshake->extensions_present & PRE_SHARED_KEY_EXTENSION) 
	{
		if (ssl->handshake->extensions_present & KEY_SHARE_EXTENSION) 
			ssl->session_negotiate->key_exchange = MBEDTLS_KEY_EXCHANGE_ECDHE_PSK;
		else 
			ssl->session_negotiate->key_exchange = MBEDTLS_KEY_EXCHANGE_PSK;
	}
	else if (ssl->handshake->extensions_present & KEY_SHARE_EXTENSION) 
		ssl->session_negotiate->key_exchange = MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA;
	else 
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("Unknown key exchange."));
		return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);
	}

	MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse server hello"));
	return(0);
}


/*
* SSL handshake -- client side -- single step
*/
int mbedtls_ssl_handshake_client_step(mbedtls_ssl_context *ssl)
{
	int ret = 0;

	if (ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER || ssl->handshake == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(2, ("Handshake completed but ssl->handshake is NULL.\n"));
		return(MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
	}
	MBEDTLS_SSL_DEBUG_MSG(2, ("client state: %d", ssl->state));

	if ((ret = mbedtls_ssl_flush_output(ssl)) != 0)
		return(ret);

#if defined(MBEDTLS_SSL_PROTO_DTLS)
	if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
		ssl->handshake->retransmit_state == MBEDTLS_SSL_RETRANS_SENDING)
	{
		if ((ret = mbedtls_ssl_resend(ssl)) != 0)
			return(ret);
	}
#endif

	switch (ssl->state)
	{
	case MBEDTLS_SSL_HELLO_REQUEST:
		ssl->state = MBEDTLS_SSL_CLIENT_HELLO;
		// Reset hello_retry_requests_receive since we have not seen an HRR msg yet. 
		ssl->handshake->hello_retry_requests_received = 0;
		break;

		/*
		*  ==>   ClientHello
		*/
	case MBEDTLS_SSL_CLIENT_HELLO:

		ret = ssl_write_client_hello(ssl);
		if (ret != 0) {
			MBEDTLS_SSL_DEBUG_RET(1, "ssl_write_client_hello", ret);
			return (ret);
		}

#if defined(MBEDTLS_ZERO_RTT)
		if (ssl->handshake->early_data == MBEDTLS_SSL_EARLY_DATA_ON) {
			ssl->state = MBEDTLS_SSL_EARLY_APP_DATA;
	}
		else
#endif /* MBEDTLS_ZERO_RTT */
		{
			ssl->state = MBEDTLS_SSL_SERVER_HELLO;
		}

#if defined(MBEDTLS_SSL_PROTO_DTLS)
		if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM)
			mbedtls_ssl_send_flight_completed(ssl);
#endif
		break;

#if defined(MBEDTLS_ZERO_RTT)
	case MBEDTLS_SSL_EARLY_APP_DATA:

		ret = mbedtls_ssl_early_data_key_derivation(ssl);
		if (ret != 0) {
			MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_key_derivation", ret);
			return (ret);
		}

		// TBD: Add bounds check here. 
		memcpy(ssl->out_msg, ssl->conf->early_data_buf, ssl->conf->early_data_len);
		ssl->out_msglen = ssl->conf->early_data_len;
		ssl->out_msg[ssl->out_msglen] = MBEDTLS_SSL_MSG_APPLICATION_DATA;
		ssl->out_msgtype = MBEDTLS_SSL_MSG_APPLICATION_DATA;
		ssl->out_msglen++;

		MBEDTLS_SSL_DEBUG_BUF(3, "Early Data", ssl->out_msg, ssl->out_msglen);

		ret = mbedtls_ssl_write_record(ssl); 
//		ret = mbedtls_ssl_write(ssl, buf, strlen(buf));

		if (ret != 0) {
			MBEDTLS_SSL_DEBUG_RET(1, "ssl_write_real", ret);
			return (ret);
		}

#if defined(MBEDTLS_SSL_PROTO_DTLS)
		if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM)
			mbedtls_ssl_send_flight_completed(ssl);
#endif
		ssl->state = MBEDTLS_SSL_SERVER_HELLO;
		break;
#endif /* MBEDTLS_ZERO_RTT */

	case MBEDTLS_SSL_SERVER_HELLO:
		/* In this state the client is expecting a ServerHello
		* message but the server could also return a HelloRetryRequest.
		*/
		// reset extensions we have seen so far
		ssl->handshake->extensions_present = NO_EXTENSION;
		ret = ssl_parse_server_hello(ssl);
		if (ret != 0) {
			MBEDTLS_SSL_DEBUG_RET(1, "ssl_parse_server_hello", ret);
			return (ret);
		}
		// If we received the HRR msg then we send another ClientHello
		if (ssl->handshake->hello_retry_requests_received > 0) {
			ssl->state = MBEDTLS_SSL_SECOND_CLIENT_HELLO; 
		} else {
			ssl->state = MBEDTLS_SSL_ENCRYPTED_EXTENSIONS;
		}
		break;

	case MBEDTLS_SSL_SECOND_CLIENT_HELLO:
		ret = ssl_write_client_hello(ssl);
		if (ret != 0) {
			MBEDTLS_SSL_DEBUG_RET(1, "ssl_write_client_hello", ret);
			return (ret);
		}
		ssl->state = MBEDTLS_SSL_SECOND_SERVER_HELLO;

#if defined(MBEDTLS_SSL_PROTO_DTLS)
		if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM)
			mbedtls_ssl_send_flight_completed(ssl);
#endif
		break;

	case MBEDTLS_SSL_SECOND_SERVER_HELLO:
		/* In this state the client is expecting a ServerHello
		* message and not the HRR anymore. 
		*/
		// reset extensions we have seen so far
		ssl->handshake->extensions_present = NO_EXTENSION;
		ret = ssl_parse_server_hello(ssl);
		if (ret != 0) {
			MBEDTLS_SSL_DEBUG_RET(1, "ssl_parse_server_hello", ret);
			return (ret);
		}
		
		// if we received a second HRR we abort
		if (ssl->handshake->hello_retry_requests_received == 2) {
			MBEDTLS_SSL_DEBUG_MSG(1, ("Too many HelloRetryRequests received from server; I give up."));
			mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL, MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE);
			return (MBEDTLS_ERR_SSL_BAD_HS_TOO_MANY_HRR);
		}
		ssl->state = MBEDTLS_SSL_ENCRYPTED_EXTENSIONS;
		break;

	case MBEDTLS_SSL_ENCRYPTED_EXTENSIONS:
		
		if (ssl->transform_in == NULL) {
			ret = mbedtls_ssl_key_derivation(ssl);
			if (ret != 0) {
				MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_key_derivation", ret);
				return (ret);
			}
		}
		ret = ssl_parse_encrypted_extensions(ssl);
		if (ret != 0) {
			MBEDTLS_SSL_DEBUG_RET(1, "ssl_parse_encrypted_extensions", ret);
			return (ret);
		}
#if defined(MBEDTLS_ZERO_RTT)
		if (ssl->handshake->early_data == MBEDTLS_SSL_EARLY_DATA_ON) {
			ssl->state = MBEDTLS_SSL_SERVER_FINISHED;
		}
		else 
#endif /* MBEDTLS_ZERO_RTT */
		{
			ssl->state = MBEDTLS_SSL_CERTIFICATE_REQUEST;
		}
		break;

	case MBEDTLS_SSL_CERTIFICATE_REQUEST:
		ret = ssl_parse_certificate_request(ssl);
		if (ret != 0) {
			MBEDTLS_SSL_DEBUG_RET(1, "ssl_parse_certificate_request", ret);
			return (ret);
		}
		ssl->state = MBEDTLS_SSL_SERVER_CERTIFICATE;
		break;

	case MBEDTLS_SSL_SERVER_CERTIFICATE:
		ret = mbedtls_ssl_parse_certificate(ssl);
		if (ret != 0) {
			MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_parse_certificate", ret);
			return (ret);
		}
		ssl->state = MBEDTLS_SSL_CERTIFICATE_VERIFY; 
		break;

	case MBEDTLS_SSL_CERTIFICATE_VERIFY:
		ret = mbedtls_ssl_parse_certificate_verify(ssl, MBEDTLS_SSL_IS_SERVER);
		if (ret != 0) {
			MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_parse_certificate_verify", ret);
			return (ret);
		}
		ssl->state= MBEDTLS_SSL_SERVER_FINISHED;
		break;
	
	case MBEDTLS_SSL_SERVER_FINISHED:
        ret = mbedtls_ssl_parse_finished(ssl);
		if (ret != 0) {
			MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_parse_finished", ret);
			return (ret);
		}

#if defined(MBEDTLS_ZERO_RTT)
		if (ssl->handshake->early_data == MBEDTLS_SSL_EARLY_DATA_ON) {
			ssl->state = MBEDTLS_SSL_EARLY_DATA; 
		}
		else
#endif /* MBEDTLS_ZERO_RTT */
		{
			ssl->state = MBEDTLS_SSL_CLIENT_CERTIFICATE;
		}
		break;

#if defined(MBEDTLS_ZERO_RTT)
	case MBEDTLS_SSL_EARLY_DATA:
		ret = mbedtls_ssl_early_data_key_derivation(ssl);
		if (ret != 0) {
			MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_key_derivation", ret);
			return (ret);
		}

		ret = mbedtls_ssl_write_end_of_early_data(ssl);
		if (ret != 0) {
			MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_write_end_of_early_data", ret);
			return (ret);
		}

		ssl->state = MBEDTLS_SSL_CLIENT_FINISHED;
		break;
#endif /* MBEDTLS_ZERO_RTT */

	case MBEDTLS_SSL_CLIENT_CERTIFICATE:
		ssl->transform_out = ssl->transform_negotiate;
		ssl->session_out = ssl->session_negotiate;
		memset(ssl->transform_out->sequence_number_enc, 0x0, 12); /* Set sequence number to zero */
		
		ret = mbedtls_ssl_write_certificate(ssl);
		if (ret != 0) {
			MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_write_certificate", ret);
			return (ret);
		}
		ssl->state = MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY;
		break;

	case MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY:
		ret = ssl_write_certificate_verify(ssl, MBEDTLS_SSL_IS_CLIENT);
		if (ret != 0) {
			MBEDTLS_SSL_DEBUG_RET(1, "ssl_write_certificate_verify", ret);
			return (ret);
		}
		ssl->state = MBEDTLS_SSL_CLIENT_FINISHED;
		break;
	
	case MBEDTLS_SSL_CLIENT_FINISHED:
#if defined(MBEDTLS_ZERO_RTT)
		if (ssl->handshake->early_data == MBEDTLS_SSL_EARLY_DATA_ON) {
			ssl->transform_out = ssl->transform_negotiate;
			ssl->session_out = ssl->session_negotiate;
			memset(ssl->transform_out->sequence_number_enc, 0x0, 12); /* Set sequence number to zero */

			ret = mbedtls_ssl_key_derivation(ssl);
			if (ret != 0) {
				MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_key_derivation", ret);
				return (ret);
			}
		}
#endif /* MBEDTLS_ZERO_RTT */

		ret = mbedtls_ssl_write_finished(ssl);
		if (ret != 0) {
			MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_write_finished", ret);
			return (ret);
		}

		ret = mbedtls_ssl_generate_application_traffic_keys(ssl);
		if (ret != 0) {
			MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_generate_application_traffic_keys", ret);
			return (ret);
		}

		ret = mbedtls_set_traffic_key(ssl);
		if (ret != 0) {
			MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_set_traffic_key", ret);
			return (ret);
		}

		ssl->state = MBEDTLS_SSL_FLUSH_BUFFERS;
		break;

	case MBEDTLS_SSL_FLUSH_BUFFERS:
		MBEDTLS_SSL_DEBUG_MSG(2, ("handshake: done"));
		ssl->state = MBEDTLS_SSL_HANDSHAKE_WRAPUP;
		break;

	case MBEDTLS_SSL_HANDSHAKE_WRAPUP:
		mbedtls_ssl_handshake_wrapup(ssl);
		ssl->state = MBEDTLS_SSL_HANDSHAKE_OVER;
		break;

	default:
		MBEDTLS_SSL_DEBUG_MSG(1, ("invalid state %d", ssl->state));
		return(MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
	}

	return(ret);
}



/*
* Parse HelloVerifyRequest.  Only called after verifying the HS type.
*/
#if defined(MBEDTLS_SSL_PROTO_DTLS) && !defined(MBEDTLS_SSL_PROTO_TLS1_3)
static int ssl_parse_hello_verify_request(mbedtls_ssl_context *ssl)
{
	const unsigned char *p = ssl->in_msg + mbedtls_ssl_hs_hdr_len(ssl);
	int major_ver, minor_ver;
	unsigned char cookie_len;

	MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse hello verify request"));

	/*
	* struct {
	*   ProtocolVersion server_version;
	*   opaque cookie<0..2^8-1>;
	* } HelloVerifyRequest;
	*/
	MBEDTLS_SSL_DEBUG_BUF(3, "server version", p, 2);
	mbedtls_ssl_read_version(&major_ver, &minor_ver, ssl->conf->transport, p);
	p += 2;

	/*
	* Since the RFC is not clear on this point, accept DTLS 1.0 (TLS 1.1)
	* even is lower than our min version.
	*/
	if (major_ver < MBEDTLS_SSL_MAJOR_VERSION_3 ||
		minor_ver < MBEDTLS_SSL_MINOR_VERSION_2 ||
		major_ver > ssl->conf->max_major_ver ||
		minor_ver > ssl->conf->max_minor_ver)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("bad server version"));

		mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
			MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION);

		return(MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION);
	}

	cookie_len = *p++;
	MBEDTLS_SSL_DEBUG_BUF(3, "cookie", p, cookie_len);

	mbedtls_free(ssl->handshake->verify_cookie);

	ssl->handshake->verify_cookie = mbedtls_calloc(1, cookie_len);
	if (ssl->handshake->verify_cookie == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("alloc failed (%d bytes)", cookie_len));
		return(MBEDTLS_ERR_SSL_ALLOC_FAILED);
	}

	memcpy(ssl->handshake->verify_cookie, p, cookie_len);
	ssl->handshake->verify_cookie_len = cookie_len;

	/* Start over at ClientHello */
	//	ssl->state = MBEDTLS_SSL_CLIENT_HELLO;
	mbedtls_ssl_reset_checksum(ssl);

	mbedtls_ssl_recv_flight_completed(ssl);

	MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse hello verify request"));

	return(0);
}
#endif /* MBEDTLS_SSL_PROTO_DTLS && !MBEDTLS_SSL_PROTO_TLS1_3 */



#endif /* MBEDTLS_SSL_CLI_C */
