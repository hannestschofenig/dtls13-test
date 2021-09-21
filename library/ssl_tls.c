/*
 *  SSLv3/TLSv1 shared functions
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
/*
 *  The SSL 3.0 specification was drafted by Netscape in 1996,
 *  and became an IETF standard in 1999.
 *
 *  http://wp.netscape.com/eng/ssl3/
 *  http://www.ietf.org/rfc/rfc2246.txt
 *  http://www.ietf.org/rfc/rfc4346.txt
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SSL_TLS_C)

#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/hkdf-tls.h"
#include "mbedtls/hkdf.h"
#include <string.h>

#if defined(MBEDTLS_X509_CRT_PARSE_C) && \
    defined(MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE)
#include "mbedtls/oid.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

/* Length of the "epoch" field in the record header */
static inline size_t ssl_ep_len( const mbedtls_ssl_context *ssl )
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        return( 2 );
#else
    ((void) ssl);
#endif
    return( 0 );
}

/*
 * Start a timer.
 * Passing millisecs = 0 cancels a running timer.
 */
static void ssl_set_timer( mbedtls_ssl_context *ssl, uint32_t millisecs )
{
    if( ssl->f_set_timer == NULL )
        return;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "set_timer to %d ms", (int) millisecs ) );
    ssl->f_set_timer( ssl->p_timer, millisecs / 4, millisecs );
}

/*
 * Return -1 is timer is expired, 0 if it isn't.
 */
static int ssl_check_timer( mbedtls_ssl_context *ssl )
{
    if( ssl->f_get_timer == NULL )
        return( 0 );

    if( ssl->f_get_timer( ssl->p_timer ) == 2 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "timer expired" ) );
        return( -1 );
    }

    return( 0 );
}

#if defined(MBEDTLS_SSL_PROTO_DTLS)
/*
 * Double the retransmit timeout value, within the allowed range,
 * returning -1 if the maximum value has already been reached.
 */
static int ssl_double_retransmit_timeout( mbedtls_ssl_context *ssl )
{
    uint32_t new_timeout;

    if( ssl->handshake->retransmit_timeout >= ssl->conf->hs_timeout_max )
        return( -1 );

    new_timeout = 2 * ssl->handshake->retransmit_timeout;

    /* Avoid arithmetic overflow and range overflow */
    if( new_timeout < ssl->handshake->retransmit_timeout ||
        new_timeout > ssl->conf->hs_timeout_max )
    {
        new_timeout = ssl->conf->hs_timeout_max;
    }

    ssl->handshake->retransmit_timeout = new_timeout;
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "update timeout value to %d millisecs",
                        ssl->handshake->retransmit_timeout ) );

    return( 0 );
}

static void ssl_reset_retransmit_timeout( mbedtls_ssl_context *ssl )
{
    ssl->handshake->retransmit_timeout = ssl->conf->hs_timeout_min;
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "update timeout value to %d millisecs",
                        ssl->handshake->retransmit_timeout ) );
}
#endif /* MBEDTLS_SSL_PROTO_DTLS */

/*
* ssl_write_signature_algorithms_ext()
*
* enum {
*    ....
*  // ECDSA algorithms
*   ecdsa_secp256r1_sha256(0x0403),
*	ecdsa_secp384r1_sha384(0x0503),
*	ecdsa_secp521r1_sha512(0x0603),
*    ....
* } SignatureScheme;
*
* struct {
*    SignatureScheme supported_signature_algorithms<2..2^16-2>;
* } SignatureSchemeList;
*
* Only if we handle at least one key exchange that needs signatures.
*/

#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
int ssl_write_signature_algorithms_ext(mbedtls_ssl_context *ssl,
	unsigned char *buf,
	size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + MBEDTLS_SSL_MAX_CONTENT_LEN;
	size_t sig_alg_len = 0;
	const int *md;
	unsigned char *sig_alg_list = buf + 6;

	*olen = 0;

	MBEDTLS_SSL_DEBUG_MSG(3, ("adding signature_algorithms extension"));

	/*
	 * Determine length of the signature scheme list
	 */
	for (md = ssl->conf->signature_schemes; *md != SIGNATURE_NONE; md++)
	{
#if defined(MBEDTLS_ECDSA_C)
		sig_alg_len += 2;
#endif
#if defined(MBEDTLS_RSA_C)
		sig_alg_len += 2;
#endif
	}

	if (end < p || (size_t)(end - p) < sig_alg_len + 6)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("buffer too small"));
		return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
	}

	/*
	* Write signature schemes
	*/

	for (md = ssl->conf->signature_schemes; *md != SIGNATURE_NONE; md++)
	{
		*sig_alg_list++ = (unsigned char)((*md >> 8) & 0xFF);
		*sig_alg_list++ = (unsigned char)((*md) & 0xFF);
		MBEDTLS_SSL_DEBUG_MSG(3, ("signature scheme [%x]", *md));
	}

	/*
	* Write extension header
	*/

	*p++ = (unsigned char)((MBEDTLS_TLS_EXT_SIG_ALG >> 8) & 0xFF);
	*p++ = (unsigned char)((MBEDTLS_TLS_EXT_SIG_ALG) & 0xFF);

	*p++ = (unsigned char)(((sig_alg_len + 2) >> 8) & 0xFF);
	*p++ = (unsigned char)(((sig_alg_len + 2)) & 0xFF);

	*p++ = (unsigned char)((sig_alg_len >> 8) & 0xFF);
	*p++ = (unsigned char)((sig_alg_len) & 0xFF);

	*olen = 6 + sig_alg_len;

	return 0;
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 && MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && \
    defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
int ssl_parse_signature_algorithms_ext(mbedtls_ssl_context *ssl,
	const unsigned char *buf,
	size_t len)
{
	size_t sig_alg_list_size;
	const unsigned char *p;
	const unsigned char *end = buf + len;
	const int *md_cur;
	int offered_signature_scheme;

	sig_alg_list_size = ((buf[0] << 8) | (buf[1]));
	if (sig_alg_list_size + 2 != len ||
		sig_alg_list_size % 2 != 0)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("bad signature_algorithms extension"));
		return(MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	for (md_cur = ssl->conf->signature_schemes; *md_cur != SIGNATURE_NONE; md_cur++) {
		for (p = buf + 2; p < end; p += 2) {
			offered_signature_scheme = (p[0] << 8) | p[1];

			if (*md_cur == offered_signature_scheme) {
				ssl->handshake->signature_scheme = offered_signature_scheme;
				goto have_sig_alg;
			}
		}
	}

	MBEDTLS_SSL_DEBUG_MSG(3, ("no signature_algorithm in common"));
	return(0);

have_sig_alg:
	MBEDTLS_SSL_DEBUG_MSG(3, ("signature_algorithm ext: %d", ssl->handshake->signature_scheme));

	return(0);
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 && MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */


#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
/*
 * Convert max_fragment_length codes to length.
 * RFC 6066 says:
 *    enum{
 *        2^9(1), 2^10(2), 2^11(3), 2^12(4), (255)
 *    } MaxFragmentLength;
 * and we add 0 -> extension unused
 */
static unsigned int mfl_code_to_length[MBEDTLS_SSL_MAX_FRAG_LEN_INVALID] =
{
    MBEDTLS_SSL_MAX_CONTENT_LEN,    /* MBEDTLS_SSL_MAX_FRAG_LEN_NONE */
    512,                    /* MBEDTLS_SSL_MAX_FRAG_LEN_512  */
    1024,                   /* MBEDTLS_SSL_MAX_FRAG_LEN_1024 */
    2048,                   /* MBEDTLS_SSL_MAX_FRAG_LEN_2048 */
    4096,                   /* MBEDTLS_SSL_MAX_FRAG_LEN_4096 */
};
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_SSL_CLI_C)
static int ssl_session_copy( mbedtls_ssl_session *dst, const mbedtls_ssl_session *src )
{
    mbedtls_ssl_session_free( dst );
    memcpy( dst, src, sizeof( mbedtls_ssl_session ) );

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if( src->peer_cert != NULL )
    {
        int ret;

        dst->peer_cert = mbedtls_calloc( 1, sizeof(mbedtls_x509_crt) );
        if( dst->peer_cert == NULL )
            return( MBEDTLS_ERR_SSL_ALLOC_FAILED );

        mbedtls_x509_crt_init( dst->peer_cert );

        if( ( ret = mbedtls_x509_crt_parse_der( dst->peer_cert, src->peer_cert->raw.p,
                                        src->peer_cert->raw.len ) ) != 0 )
        {
            mbedtls_free( dst->peer_cert );
            dst->peer_cert = NULL;
            return( ret );
        }
    }
#endif /* MBEDTLS_X509_CRT_PARSE_C */

	/* 
#if (defined(MBEDTLS_SSL_SESSION_TICKETS) || defined(MBEDTLS_SSL_NEW_SESSION_TICKET)) && defined(MBEDTLS_SSL_CLI_C)
    if( src->ticket != NULL )
    {
        dst->ticket = mbedtls_calloc( 1, src->ticket_len );
        if( dst->ticket == NULL )
            return( MBEDTLS_ERR_SSL_ALLOC_FAILED );

        memcpy( dst->ticket, src->ticket, src->ticket_len );
    }
#endif // ( MBEDTLS_SSL_SESSION_TICKETS || MBEDTLS_SSL_NEW_SESSION_TICKET ) && MBEDTLS_SSL_CLI_C 
*/
    return( 0 );
}
#endif /* MBEDTLS_SSL_CLI_C */

#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
int (*mbedtls_ssl_hw_record_init)( mbedtls_ssl_context *ssl,
                     const unsigned char *key_enc, const unsigned char *key_dec,
                     size_t keylen,
                     const unsigned char *iv_enc,  const unsigned char *iv_dec,
                     size_t ivlen,
                     const unsigned char *mac_enc, const unsigned char *mac_dec,
                     size_t maclen ) = NULL;
int (*mbedtls_ssl_hw_record_activate)( mbedtls_ssl_context *ssl, int direction) = NULL;
int (*mbedtls_ssl_hw_record_reset)( mbedtls_ssl_context *ssl ) = NULL;
int (*mbedtls_ssl_hw_record_write)( mbedtls_ssl_context *ssl ) = NULL;
int (*mbedtls_ssl_hw_record_read)( mbedtls_ssl_context *ssl ) = NULL;
int (*mbedtls_ssl_hw_record_finish)( mbedtls_ssl_context *ssl ) = NULL;
#endif /* MBEDTLS_SSL_HW_RECORD_ACCEL */

/*
 * Key material generation
 */
#if defined(MBEDTLS_SSL_PROTO_SSL3)
static int ssl3_prf( const unsigned char *secret, size_t slen,
                     const char *label,
                     const unsigned char *random, size_t rlen,
                     unsigned char *dstbuf, size_t dlen )
{
    size_t i;
    mbedtls_md5_context md5;
    mbedtls_sha1_context sha1;
    unsigned char padding[16];
    unsigned char sha1sum[20];
    ((void)label);

    mbedtls_md5_init(  &md5  );
    mbedtls_sha1_init( &sha1 );

    /*
     *  SSLv3:
     *    block =
     *      MD5( secret + SHA1( 'A'    + secret + random ) ) +
     *      MD5( secret + SHA1( 'BB'   + secret + random ) ) +
     *      MD5( secret + SHA1( 'CCC'  + secret + random ) ) +
     *      ...
     */
    for( i = 0; i < dlen / 16; i++ )
    {
        memset( padding, (unsigned char) ('A' + i), 1 + i );

        mbedtls_sha1_starts( &sha1 );
        mbedtls_sha1_update( &sha1, padding, 1 + i );
        mbedtls_sha1_update( &sha1, secret, slen );
        mbedtls_sha1_update( &sha1, random, rlen );
        mbedtls_sha1_finish( &sha1, sha1sum );

        mbedtls_md5_starts( &md5 );
        mbedtls_md5_update( &md5, secret, slen );
        mbedtls_md5_update( &md5, sha1sum, 20 );
        mbedtls_md5_finish( &md5, dstbuf + i * 16 );
    }

    mbedtls_md5_free(  &md5  );
    mbedtls_sha1_free( &sha1 );

    mbedtls_zeroize( padding, sizeof( padding ) );
    mbedtls_zeroize( sha1sum, sizeof( sha1sum ) );

    return( 0 );
}
#endif /* MBEDTLS_SSL_PROTO_SSL3 */

#if defined(MBEDTLS_SSL_PROTO_TLS1) || defined(MBEDTLS_SSL_PROTO_TLS1_1)
static int tls1_prf( const unsigned char *secret, size_t slen,
                     const char *label,
                     const unsigned char *random, size_t rlen,
                     unsigned char *dstbuf, size_t dlen )
{
    size_t nb, hs;
    size_t i, j, k;
    const unsigned char *S1, *S2;
    unsigned char tmp[128];
    unsigned char h_i[20];
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t md_ctx;
    int ret;

    mbedtls_md_init( &md_ctx );

    if( sizeof( tmp ) < 20 + strlen( label ) + rlen )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    hs = ( slen + 1 ) / 2;
    S1 = secret;
    S2 = secret + slen - hs;

    nb = strlen( label );
    memcpy( tmp + 20, label, nb );
    memcpy( tmp + 20 + nb, random, rlen );
    nb += rlen;

    /*
     * First compute P_md5(secret,label+random)[0..dlen]
     */
    if( ( md_info = mbedtls_md_info_from_type( MBEDTLS_MD_MD5 ) ) == NULL )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    if( ( ret = mbedtls_md_setup( &md_ctx, md_info, 1 ) ) != 0 )
        return( ret );

    mbedtls_md_hmac_starts( &md_ctx, S1, hs );
    mbedtls_md_hmac_update( &md_ctx, tmp + 20, nb );
    mbedtls_md_hmac_finish( &md_ctx, 4 + tmp );

    for( i = 0; i < dlen; i += 16 )
    {
        mbedtls_md_hmac_reset ( &md_ctx );
        mbedtls_md_hmac_update( &md_ctx, 4 + tmp, 16 + nb );
        mbedtls_md_hmac_finish( &md_ctx, h_i );

        mbedtls_md_hmac_reset ( &md_ctx );
        mbedtls_md_hmac_update( &md_ctx, 4 + tmp, 16 );
        mbedtls_md_hmac_finish( &md_ctx, 4 + tmp );

        k = ( i + 16 > dlen ) ? dlen % 16 : 16;

        for( j = 0; j < k; j++ )
            dstbuf[i + j]  = h_i[j];
    }

    mbedtls_md_free( &md_ctx );

    /*
     * XOR out with P_sha1(secret,label+random)[0..dlen]
     */
    if( ( md_info = mbedtls_md_info_from_type( MBEDTLS_MD_SHA1 ) ) == NULL )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    if( ( ret = mbedtls_md_setup( &md_ctx, md_info, 1 ) ) != 0 )
        return( ret );

    mbedtls_md_hmac_starts( &md_ctx, S2, hs );
    mbedtls_md_hmac_update( &md_ctx, tmp + 20, nb );
    mbedtls_md_hmac_finish( &md_ctx, tmp );

    for( i = 0; i < dlen; i += 20 )
    {
        mbedtls_md_hmac_reset ( &md_ctx );
        mbedtls_md_hmac_update( &md_ctx, tmp, 20 + nb );
        mbedtls_md_hmac_finish( &md_ctx, h_i );

        mbedtls_md_hmac_reset ( &md_ctx );
        mbedtls_md_hmac_update( &md_ctx, tmp, 20 );
        mbedtls_md_hmac_finish( &md_ctx, tmp );

        k = ( i + 20 > dlen ) ? dlen % 20 : 20;

        for( j = 0; j < k; j++ )
            dstbuf[i + j] = (unsigned char)( dstbuf[i + j] ^ h_i[j] );
    }

    mbedtls_md_free( &md_ctx );

    mbedtls_zeroize( tmp, sizeof( tmp ) );
    mbedtls_zeroize( h_i, sizeof( h_i ) );

    return( 0 );
}
#endif /* MBEDTLS_SSL_PROTO_TLS1) || MBEDTLS_SSL_PROTO_TLS1_1 */

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && !defined(MBEDTLS_SSL_PROTO_TLS1_3)
static int tls_prf_generic( mbedtls_md_type_t md_type,
                            const unsigned char *secret, size_t slen,
                            const char *label,
                            const unsigned char *random, size_t rlen,
                            unsigned char *dstbuf, size_t dlen )
{
    size_t nb;
    size_t i, j, k, md_len;
    unsigned char tmp[128];
    unsigned char h_i[MBEDTLS_MD_MAX_SIZE];
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t md_ctx;
    int ret;

    mbedtls_md_init( &md_ctx );

    if( ( md_info = mbedtls_md_info_from_type( md_type ) ) == NULL )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    md_len = mbedtls_md_get_size( md_info );

    if( sizeof( tmp ) < md_len + strlen( label ) + rlen )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    nb = strlen( label );
    memcpy( tmp + md_len, label, nb );
    memcpy( tmp + md_len + nb, random, rlen );
    nb += rlen;

    /*
     * Compute P_<hash>(secret, label + random)[0..dlen]
     */
    if ( ( ret = mbedtls_md_setup( &md_ctx, md_info, 1 ) ) != 0 )
        return( ret );

    mbedtls_md_hmac_starts( &md_ctx, secret, slen );
    mbedtls_md_hmac_update( &md_ctx, tmp + md_len, nb );
    mbedtls_md_hmac_finish( &md_ctx, tmp );

    for( i = 0; i < dlen; i += md_len )
    {
        mbedtls_md_hmac_reset ( &md_ctx );
        mbedtls_md_hmac_update( &md_ctx, tmp, md_len + nb );
        mbedtls_md_hmac_finish( &md_ctx, h_i );

        mbedtls_md_hmac_reset ( &md_ctx );
        mbedtls_md_hmac_update( &md_ctx, tmp, md_len );
        mbedtls_md_hmac_finish( &md_ctx, tmp );

        k = ( i + md_len > dlen ) ? dlen % md_len : md_len;

        for( j = 0; j < k; j++ )
            dstbuf[i + j]  = h_i[j];
    }

    mbedtls_md_free( &md_ctx );

    mbedtls_zeroize( tmp, sizeof( tmp ) );
    mbedtls_zeroize( h_i, sizeof( h_i ) );

    return( 0 );
}

#if defined(MBEDTLS_SHA256_C)
static int tls_prf_sha256( const unsigned char *secret, size_t slen,
                           const char *label,
                           const unsigned char *random, size_t rlen,
                           unsigned char *dstbuf, size_t dlen )
{
    return( tls_prf_generic( MBEDTLS_MD_SHA256, secret, slen,
                             label, random, rlen, dstbuf, dlen ) );
}
#endif /* MBEDTLS_SHA256_C */

#if defined(MBEDTLS_SHA512_C)
static int tls_prf_sha384( const unsigned char *secret, size_t slen,
                           const char *label,
                           const unsigned char *random, size_t rlen,
                           unsigned char *dstbuf, size_t dlen )
{
	if (slen == 48) return( tls_prf_generic( MBEDTLS_MD_SHA384, secret, slen,
                             label, random, rlen, dstbuf, dlen ) );
	else if (slen == 64) return(tls_prf_generic(MBEDTLS_MD_SHA512, secret, slen,
		label, random, rlen, dstbuf, dlen));
	else return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
}
#endif /* MBEDTLS_SHA512_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 && !MBEDTLS_SSL_PROTO_TLS1_3 */

static void ssl_update_checksum_start( mbedtls_ssl_context *, const unsigned char *, size_t );

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

#if defined(MBEDTLS_SHA256_C)
static void ssl_update_checksum_sha256( mbedtls_ssl_context *, const unsigned char *, size_t );
static int ssl_calc_verify_tls_sha256( mbedtls_ssl_context *,unsigned char *, int );
static int ssl_calc_finished_tls_sha256( mbedtls_ssl_context *,unsigned char *, int);
#endif /* MBEDTLS_SHA256_C */

#if defined(MBEDTLS_SHA512_C)
static void ssl_update_checksum_sha384( mbedtls_ssl_context *, const unsigned char *, size_t );
static int ssl_calc_verify_tls_sha384( mbedtls_ssl_context *, unsigned char *, int );
static int ssl_calc_finished_tls_sha384( mbedtls_ssl_context *, unsigned char *, int);
#endif /* MBEDTLS_SHA512_C */

#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

/* mbedtls_ssl_derive_traffic_keys() generates keys necessary for 
 * protecting the handshake messages, as described in Section 7 of
 * TLS 1.3.
 */

int mbedtls_ssl_derive_traffic_keys(mbedtls_ssl_context *ssl)
{
	int ret = 0;
	const mbedtls_cipher_info_t *cipher_info;
	const mbedtls_md_info_t *md_info;
//	mbedtls_ssl_session *session = ssl->session_negotiate;
	mbedtls_ssl_transform *transform = ssl->transform_negotiate;
	mbedtls_ssl_handshake_params *handshake = ssl->handshake;
	KeySet traffic_keys;
	unsigned char *key1=NULL, *key2=NULL;
    const mbedtls_ssl_ciphersuite_t *suite_info;

#if defined(MBEDTLS_SHA256_C) 
	mbedtls_sha256_context sha256;
#endif
#if defined(MBEDTLS_SHA512_C)
	mbedtls_sha512_context sha512;
#endif

	unsigned char hash[MBEDTLS_MD_MAX_SIZE];


	MBEDTLS_SSL_DEBUG_MSG(2, ("=> derive traffic keys"));

	cipher_info = mbedtls_cipher_info_from_type(transform->ciphersuite_info->cipher);
	if (cipher_info == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("cipher info for %d not found",
			transform->ciphersuite_info->cipher));
		return(MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
	}

	md_info = mbedtls_md_info_from_type(transform->ciphersuite_info->hash);
	if (md_info == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_md info for %d not found",
			transform->ciphersuite_info->hash));
		return(MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
	}

	suite_info = mbedtls_ssl_ciphersuite_from_id(ssl->session_negotiate->ciphersuite);
	if (suite_info == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_ssl_ciphersuite_from_id in mbedtls_ssl_derive_traffic_keys failed"));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
	}

	if (mbedtls_hash_size_for_ciphersuite(suite_info) == 32) {
#if defined(MBEDTLS_SHA256_C)
		handshake->calc_verify = ssl_calc_verify_tls_sha256;
		handshake->calc_finished = ssl_calc_finished_tls_sha256;
#else
		MBEDTLS_SSL_DEBUG_MSG(1, ("MBEDTLS_SHA256_C not set but ciphersuite with SHA256 negotiated"));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
#endif /* MBEDTLS_SHA256_C */
	}

	if (mbedtls_hash_size_for_ciphersuite(suite_info) == 48) {
#if defined(MBEDTLS_SHA512_C)
		handshake->calc_verify = ssl_calc_verify_tls_sha384;
		handshake->calc_finished = ssl_calc_finished_tls_sha384;
#else 
		MBEDTLS_SSL_DEBUG_MSG(1, ("MBEDTLS_SHA512_C not set but ciphersuite with SHA384 negotiated"));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
#endif /* MBEDTLS_SHA512_C */
	}

	if ((mbedtls_hash_size_for_ciphersuite(suite_info) != 32) && (mbedtls_hash_size_for_ciphersuite(suite_info) != 48) ) { 
		MBEDTLS_SSL_DEBUG_MSG(1, ("Unknown hash function negotiated."));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
	}


#if defined(MBEDTLS_SHA256_C) 
	if (mbedtls_hash_size_for_ciphersuite(suite_info) == 32) {
		mbedtls_sha256_clone(&sha256, &ssl->handshake->fin_sha256);
		mbedtls_sha256_finish(&sha256, hash);
	}
	else
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA512_C)
		if (mbedtls_hash_size_for_ciphersuite(suite_info) == 48) {
			mbedtls_sha512_clone(&sha512, &ssl->handshake->fin_sha512);
			mbedtls_sha512_finish(&sha512, hash);
		}
		else
#endif /* MBEDTLS_SHA512_C */
		{
			MBEDTLS_SSL_DEBUG_MSG(2, ("Unsupported hash function in mbedtls_ssl_derive_traffic_keys"));
			return (MBEDTLS_ERR_SSL_INTERNAL_ERROR);
		}

	MBEDTLS_SSL_DEBUG_BUF(3, "rolling hash", hash, mbedtls_hash_size_for_ciphersuite(suite_info));

	/*
	*
	* Handshake Secret
	* |
	* +-----> Derive-Secret(., "c hs traffic",
	* |                     ClientHello...ServerHello)
	* |                     = client_handshake_traffic_secret
	* |
	* +-----> Derive-Secret(., "s hs traffic",
	* |                     ClientHello...ServerHello)
	* |                     = server_handshake_traffic_secret
	*
	*/


	/*
     * Compute client_handshake_traffic_secret with 
	 *	 Derive-Secret(., "c hs traffic", ClientHello...ServerHello) 
	 */

	ret = Derive_Secret(mbedtls_md_get_type(md_info), 
		(const unsigned char*) ssl->handshake->handshake_secret, (int) mbedtls_hash_size_for_ciphersuite(suite_info), 
		(const unsigned char*) "c hs traffic", strlen("c hs traffic"),
		(const unsigned char *) hash, (int) mbedtls_hash_size_for_ciphersuite(suite_info),
		(unsigned char *) ssl->handshake->client_handshake_traffic_secret, (int) mbedtls_hash_size_for_ciphersuite(suite_info));

	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(1, "Derive_Secret() with client_handshake_traffic_secret: Error", ret);
		return ret;
	}

	MBEDTLS_SSL_DEBUG_MSG(5, ("HKDF Expand: label=[TLS 1.3, c hs traffic], requested length %d", mbedtls_hash_size_for_ciphersuite(suite_info)));
	MBEDTLS_SSL_DEBUG_BUF(5, "Secret: ", ssl->handshake->handshake_secret, mbedtls_hash_size_for_ciphersuite(suite_info));
	MBEDTLS_SSL_DEBUG_BUF(5, "Hash:", hash, mbedtls_hash_size_for_ciphersuite(suite_info));
	MBEDTLS_SSL_DEBUG_BUF(5, "client_handshake_traffic_secret", ssl->handshake->client_handshake_traffic_secret, mbedtls_hash_size_for_ciphersuite(suite_info));

	/*
     * Compute server_handshake_traffic_secret with
	 *   Derive-Secret(., "s hs traffic", ClientHello...ServerHello)
	 */

	ret = Derive_Secret(mbedtls_md_get_type(md_info),
		ssl->handshake->handshake_secret, mbedtls_hash_size_for_ciphersuite(suite_info),
		(const unsigned char*) "s hs traffic", strlen("s hs traffic"),
		hash, mbedtls_hash_size_for_ciphersuite(suite_info),
		ssl->handshake->server_handshake_traffic_secret, mbedtls_hash_size_for_ciphersuite(suite_info));

	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(1, "Derive_Secret() with server_handshake_traffic_secret: Error", ret);
		return ret;
	}

	MBEDTLS_SSL_DEBUG_MSG(5, ("HKDF Expand: label=[TLS 1.3, s hs traffic], requested length %d", mbedtls_hash_size_for_ciphersuite(suite_info)));
	MBEDTLS_SSL_DEBUG_BUF(5, "Secret: ", ssl->handshake->handshake_secret, mbedtls_hash_size_for_ciphersuite(suite_info));
	MBEDTLS_SSL_DEBUG_BUF(5, "Hash:", hash, mbedtls_hash_size_for_ciphersuite(suite_info));
	MBEDTLS_SSL_DEBUG_BUF(5, "server_handshake_traffic_secret", ssl->handshake->server_handshake_traffic_secret, mbedtls_hash_size_for_ciphersuite(suite_info));

	/*
	 * Compute exporter_secret with
	 *   DeriveSecret(Master Secret,  "exp master", ClientHello...Server Finished)
	 */

	ret = Derive_Secret(mbedtls_md_get_type(md_info),
		ssl->handshake->master_secret, mbedtls_hash_size_for_ciphersuite(suite_info),
		(const unsigned char*)"exp master", strlen("exp master"),
		hash, mbedtls_hash_size_for_ciphersuite(suite_info),
		ssl->handshake->exporter_secret, mbedtls_hash_size_for_ciphersuite(suite_info));

	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(1, "Derive_Secret() with exporter_secret: Error", ret);
		return ret;
	}

	MBEDTLS_SSL_DEBUG_BUF(5, "exporter_secret", ssl->handshake->exporter_secret, mbedtls_hash_size_for_ciphersuite(suite_info));

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)

	// TBD: Optimization: We only need to create the resumption_secret when we resume an exchange with a ticket
//	if (ssl->handshake->resume == 1) {

	/*
	 * Compute resumption_master_secret with
	 *   DeriveSecret(Master Secret, "res master", ClientHello...client Finished
	 */
		
		ret = Derive_Secret(mbedtls_md_get_type(md_info),
			ssl->handshake->master_secret, mbedtls_hash_size_for_ciphersuite(suite_info),
			(const unsigned char*)"res master", strlen("res master"),
			hash, mbedtls_hash_size_for_ciphersuite(suite_info),
			ssl->session_negotiate->resumption_master_secret, mbedtls_hash_size_for_ciphersuite(suite_info));

		if (ret != 0) {
			MBEDTLS_SSL_DEBUG_RET(1, "Derive_Secret() with resumption_master_secret: Error", ret);
			return ret;
		}

		MBEDTLS_SSL_DEBUG_BUF(5, "resumption_master_secret", ssl->session_negotiate->resumption_master_secret, mbedtls_hash_size_for_ciphersuite(suite_info));

//	}
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */
	/*
	 * Compute keys to protect the handshake messages utilizing MakeTrafficKey
	 */

	 /* Settings for GCM, CCM, and CCM_8 */
	transform->maclen = 0;
	transform->fixed_ivlen = 4;
	transform->ivlen = cipher_info->iv_size;
	transform->keylen = cipher_info->key_bitlen / 8;

	/* Minimum length for an encrypted handshake message is
	*  - Handshake header
	*  - 1 byte for handshake type appended to the end of the message
	*  - Authentication tag (which depends on the mode of operation)
	*/
	if (transform->ciphersuite_info->cipher == MBEDTLS_CIPHER_AES_128_CCM_8) transform->minlen = 8;
	else transform->minlen = 16;

	transform->minlen += mbedtls_ssl_hs_hdr_len(ssl);

	transform->minlen += 1;

	MBEDTLS_SSL_DEBUG_MSG(3, ("-->>Calling makeTrafficKeys() with the following parameters:")); 
	MBEDTLS_SSL_DEBUG_MSG(3, ("-- Hash Algorithm: %s", mbedtls_md_get_name(md_info)));
	MBEDTLS_SSL_DEBUG_MSG(3, ("-- Handshake Traffic Secret Length: %d bytes", mbedtls_hash_size_for_ciphersuite(suite_info)));
	MBEDTLS_SSL_DEBUG_MSG(3, ("-- Key Length: %d bytes", transform->keylen));
	MBEDTLS_SSL_DEBUG_MSG(3, ("-- IV Length: %d bytes", transform->ivlen));

	if ((ret = makeTrafficKeys(mbedtls_md_get_type(md_info), 
		ssl->handshake->client_handshake_traffic_secret,
		ssl->handshake->server_handshake_traffic_secret,
		mbedtls_hash_size_for_ciphersuite(suite_info), 
		transform->keylen, transform->ivlen, &traffic_keys)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "makeTrafficKeys failed", ret);
		return(ret);
	}

	MBEDTLS_SSL_DEBUG_BUF(3, "[TLS 1.3, ] + handshake key expansion, clientWriteKey:", traffic_keys.clientWriteKey, transform->keylen);
	MBEDTLS_SSL_DEBUG_BUF(3, "[TLS 1.3, ] + handshake key expansion, serverWriteKey:", traffic_keys.serverWriteKey, transform->keylen);
	MBEDTLS_SSL_DEBUG_BUF(3, "[TLS 1.3, ] + handshake key expansion, clientWriteIV:", traffic_keys.clientWriteIV, transform->ivlen);
	MBEDTLS_SSL_DEBUG_BUF(3, "[TLS 1.3, ] + handshake key expansion, serverWriteIV:", traffic_keys.serverWriteIV, transform->ivlen);

	if ((ret = mbedtls_cipher_setup(&transform->cipher_ctx_enc,
		cipher_info)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_setup", ret);
		return(ret);
	}

	if ((ret = mbedtls_cipher_setup(&transform->cipher_ctx_dec,
		cipher_info)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_setup", ret);
		return(ret);
	}

#if defined(MBEDTLS_SSL_SRV_C)
	if (ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER)
	{

		key1 = traffic_keys.serverWriteKey; // encryption key for the server
		key2 = traffic_keys.clientWriteKey; // decryption key for the server

		transform->iv_enc = traffic_keys.serverWriteIV; 
		transform->iv_dec = traffic_keys.clientWriteIV; 
	}
#endif
#if defined(MBEDTLS_SSL_CLI_C)
	if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT)
	{
		key1 = traffic_keys.clientWriteKey; // encryption key for the client
		key2 = traffic_keys.serverWriteKey; // decryption key for the client

		transform->iv_enc = traffic_keys.clientWriteIV;
		transform->iv_dec = traffic_keys.serverWriteIV;
	}
#endif

	if ((ret = mbedtls_cipher_setkey(&transform->cipher_ctx_enc, key1,
		cipher_info->key_bitlen,
		MBEDTLS_ENCRYPT)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_setkey", ret);
		return(ret);
	}

	if ((ret = mbedtls_cipher_setkey(&transform->cipher_ctx_dec, key2,
		cipher_info->key_bitlen,
		MBEDTLS_DECRYPT)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_setkey", ret);
		return(ret);
	}

	MBEDTLS_SSL_DEBUG_MSG(2, ("<= derive traffic keys"));

	return(0);
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

int incrementSequenceNumber(unsigned char *sequenceNumber, unsigned char *nonce, size_t ivlen) {

	if (ivlen == 0) return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);

	for (size_t i = ivlen - 1; i > ivlen - 8; i--) {
		sequenceNumber[i]++;
		nonce[i] ^= (sequenceNumber[i] - 1) ^ sequenceNumber[i];
			if (sequenceNumber[i] != 0) {
				return (0);
			}
	}

	return(MBEDTLS_ERR_SSL_COUNTER_WRAPPING);
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if defined(MBEDTLS_SHA256_C)
static int ssl_calc_verify_tls_sha256(mbedtls_ssl_context *ssl, unsigned char hash[32], int from)
{
	mbedtls_sha256_context sha256;
	unsigned char handshake_hash[32];
	mbedtls_ssl_session *session = ssl->session_negotiate;
	unsigned char *verify_buffer;
	unsigned char *context_string;
	size_t context_string_len; 

	if (!session) session = ssl->session;

	mbedtls_sha256_init(&sha256);

	MBEDTLS_SSL_DEBUG_MSG(2, ("=> calc verify sha256"));

	mbedtls_sha256_clone(&sha256, &ssl->handshake->fin_sha256);
	mbedtls_sha256_finish(&sha256, handshake_hash);

	MBEDTLS_SSL_DEBUG_BUF(3, "handshake hash", handshake_hash, 32);

	/* 
	 * The digital signature is then computed using the signing key over the concatenation of:
	 *    - 64 bytes of octet 32
	 *    - The context string (which is either "TLS 1.3, client CertificateVerify" or "TLS 1.3, server CertificateVerify")
	 *    - A single 0 byte which servers as the separator
	 *    - The content to be signed, which is Hash(Handshake Context + Certificate) + Hash(resumption_context)
	 * 
 	 */

	if (from == MBEDTLS_SSL_IS_CLIENT) {
		context_string_len = strlen("TLS 1.3, client CertificateVerify"); 
		context_string = mbedtls_calloc(context_string_len,1);

		if (context_string == NULL) {
			MBEDTLS_SSL_DEBUG_MSG(1, ("malloc failed in ssl_calc_verify_tls_sha256()"));
			return(MBEDTLS_ERR_SSL_ALLOC_FAILED);
		}
		memcpy(context_string, "TLS 1.3, client CertificateVerify", context_string_len);
	} else { // from == MBEDTLS_SSL_IS_SERVER
		context_string_len = strlen("TLS 1.3, server CertificateVerify");
		context_string = mbedtls_calloc(context_string_len,1);
		if (context_string == NULL) {
			MBEDTLS_SSL_DEBUG_MSG(1, ("malloc failed in ssl_calc_verify_tls_sha256()"));
			return(MBEDTLS_ERR_SSL_ALLOC_FAILED);
		}
		memcpy(context_string, "TLS 1.3, server CertificateVerify", context_string_len);
	}

	verify_buffer = mbedtls_calloc(64 + context_string_len + 1 + 32 + 32,1);

	if (verify_buffer == NULL) {
		MBEDTLS_SSL_DEBUG_MSG(1, ("malloc failed in ssl_calc_verify_tls_sha256()"));
		mbedtls_free(context_string); 
		return(MBEDTLS_ERR_SSL_ALLOC_FAILED);
	}

	memset(verify_buffer, 32, 64);
	memcpy(verify_buffer + 64, context_string, context_string_len);
	verify_buffer[64 + context_string_len] = 0x0; 
	memcpy(verify_buffer + 64 + context_string_len + 1, handshake_hash, 32);

	MBEDTLS_SSL_DEBUG_BUF(3, "verify buffer", verify_buffer, 64 + context_string_len + 1 + 32);

	mbedtls_sha256(verify_buffer, 64 + context_string_len + 1 + 32, hash, 0 /* for SHA-256 instead of SHA-224 */);

	MBEDTLS_SSL_DEBUG_BUF(3, "verify hash", hash, 32);

	MBEDTLS_SSL_DEBUG_MSG(2, ("<= calc verify"));

	mbedtls_sha256_free(&sha256);
	mbedtls_free(verify_buffer);
	mbedtls_free(context_string);

	return 0;
}
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA512_C)
static int ssl_calc_verify_tls_sha384(mbedtls_ssl_context *ssl, unsigned char hash[48], int from)
{
	mbedtls_sha512_context sha384;
	unsigned char handshake_hash[48];
	mbedtls_ssl_session *session = ssl->session_negotiate;
	unsigned char *verify_buffer;
	unsigned char *context_string;
	size_t context_string_len;

	if (!session) session = ssl->session;

	mbedtls_sha512_init(&sha384);
	mbedtls_sha512_starts(&sha384, 1 /* = use SHA384 */);

	MBEDTLS_SSL_DEBUG_MSG(2, ("=> calc verify sha384"));

	mbedtls_sha512_clone(&sha384, &ssl->handshake->fin_sha512);
	mbedtls_sha512_finish(&sha384, handshake_hash);

	MBEDTLS_SSL_DEBUG_BUF(3, "handshake hash", handshake_hash, 48);

	/*
	* The digital signature is then computed using the signing key over the concatenation of:
	*    - 64 bytes of octet 32
	*    - The context string (which is either "TLS 1.3, client CertificateVerify" or "TLS 1.3, server CertificateVerify")
	*    - A single 0 byte which servers as the separator
	*    - The content to be signed, which is Hash(Handshake Context + Certificate) + Hash(resumption_context)
	*
	*/

	if (from == MBEDTLS_SSL_IS_CLIENT) {
		context_string_len = strlen("TLS 1.3, client CertificateVerify");
		context_string = mbedtls_calloc(context_string_len, 1);

		if (context_string == NULL) {
			MBEDTLS_SSL_DEBUG_MSG(1, ("malloc failed in ssl_calc_verify_tls_sha384()"));
			return(MBEDTLS_ERR_SSL_ALLOC_FAILED);
		}
		memcpy(context_string, "TLS 1.3, client CertificateVerify", context_string_len);
	}
	else { // from == MBEDTLS_SSL_IS_SERVER
		context_string_len = strlen("TLS 1.3, server CertificateVerify");
		context_string = mbedtls_calloc(context_string_len, 1);
		if (context_string == NULL) {
			MBEDTLS_SSL_DEBUG_MSG(1, ("malloc failed in ssl_calc_verify_tls_sha384()"));
			return(MBEDTLS_ERR_SSL_ALLOC_FAILED);
		}
		memcpy(context_string, "TLS 1.3, server CertificateVerify", context_string_len);
	}

	verify_buffer = mbedtls_calloc(64 + context_string_len + 1 + 48 + 48, 1);

	if (verify_buffer == NULL) {
		MBEDTLS_SSL_DEBUG_MSG(1, ("malloc failed in ssl_calc_verify_tls_sha384()"));
		mbedtls_free(context_string);
		return(MBEDTLS_ERR_SSL_ALLOC_FAILED);
	}

	memset(verify_buffer, 32, 64);
	memcpy(verify_buffer + 64, context_string, context_string_len);
	verify_buffer[64 + context_string_len] = 0x0;
	memcpy(verify_buffer + 64 + context_string_len + 1, handshake_hash, 48);

	MBEDTLS_SSL_DEBUG_BUF(3, "verify buffer", verify_buffer, 64 + context_string_len + 1 + 48);

	mbedtls_sha512(verify_buffer, 64 + context_string_len + 1 + 48, hash, 1 /* for SHA-384 */);

	MBEDTLS_SSL_DEBUG_BUF(3, "verify hash", hash, 48);

	MBEDTLS_SSL_DEBUG_MSG(2, ("<= calc verify"));

	mbedtls_sha512_free(&sha384);
	mbedtls_free(verify_buffer);
	mbedtls_free(context_string);

	return 0;
}
#endif /* MBEDTLS_SHA512_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
/* mbedtls_ssl_derive_master_secret() 
 * 
 * Generates the keys based on the TLS 1.3 key hierachy:
 * 
 *     0
 *     |
 *     v
 *     PSK ->  HKDF-Extract = Early Secret
 *     |
 *     v
 *     Derive-Secret(., "derived", "")
 *     |
 *     v
 *     (EC)DHE -> HKDF-Extract = Handshake Secret
 *     |
 *     v
 *     Derive-Secret(., "derived", "")
 *     |
 *     v
 *     0 -> HKDF-Extract = Master Secret
 *
 */ 
int mbedtls_ssl_derive_master_secret(mbedtls_ssl_context *ssl) {

#if defined(MBEDTLS_SHA256_C) && !defined(MBEDTLS_SHA512_C) 
	unsigned char salt[32];
	unsigned char ECDHE[32];
	unsigned char null_ikm[32];
	unsigned char intermediary_secret[32];
#else // MBEDTLS_SHA512_C 
	unsigned char salt[64];
	unsigned char ECDHE[66];
	unsigned char null_ikm[64];
	unsigned char intermediary_secret[64];
#endif

#if defined(MBEDTLS_SHA256_C)
	// SHA256 hash of "" string of length 0. 
	static const unsigned char NULL_HASH_SHA256[32] =
	{ 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 };
#endif /* MBEDTLS_SHA256_C */

#if defined(MBEDTLS_SHA512_C) 
	// SHA384 hash of "" string of length 0. 
	static const unsigned char NULL_HASH_SHA384[48] =
	{ 0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b };
#endif /* MBEDTLS_SHA512_C */

	size_t ECDHE_len;
	int ret = 0;
	const mbedtls_md_info_t *md;
	const mbedtls_ssl_ciphersuite_t *suite_info;
	unsigned char *psk;
	size_t psk_len;
	unsigned char *padbuf; 
	
#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
	psk = ssl->conf->psk;
	psk_len = ssl->conf->psk_len;
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

	if (ssl->transform_in == NULL) {
		MBEDTLS_SSL_DEBUG_MSG(1, ("transform_in == NULL, mbedtls_ssl_derive_master_secret failed"));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
	}

	if (ssl->session_negotiate == NULL) {
		MBEDTLS_SSL_DEBUG_MSG(1, ("session_negotiate == NULL, mbedtls_ssl_derive_master_secret failed"));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
	}

	md = mbedtls_md_info_from_type(ssl->transform_in->ciphersuite_info->hash);
	if (md == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("md == NULL, mbedtls_ssl_derive_master_secret failed"));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
	}

	suite_info = mbedtls_ssl_ciphersuite_from_id(ssl->session_negotiate->ciphersuite);
	if (suite_info == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("suite_info == NULL, mbedtls_ssl_derive_master_secret failed"));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
	}

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
	/* If the psk callback was called, use its result */
	if ((ssl->handshake->psk != NULL) && 
	   (ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK ||
		ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK))
	{
		psk = ssl->handshake->psk;
		psk_len = ssl->handshake->psk_len;
	}
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
	if (ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA) {

		/* If we are not using a PSK-based ciphersuite then the
		 * psk identity is set to a 0 vector.
		 */
		psk = mbedtls_calloc(mbedtls_hash_size_for_ciphersuite(suite_info),1);
		if (psk == NULL) {
			MBEDTLS_SSL_DEBUG_MSG(1, ("malloc for psk == NULL, mbedtls_ssl_derive_master_secret failed"));
			return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
		}
		memset(psk, 0x0, mbedtls_hash_size_for_ciphersuite(suite_info));
		psk_len = mbedtls_hash_size_for_ciphersuite(suite_info);
	}
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */

	/* We point the padbuf variable to the appropriate constant */
	if (mbedtls_hash_size_for_ciphersuite(suite_info) == 32) {
#if defined(MBEDTLS_SHA256_C)
		padbuf = (unsigned char*) NULL_HASH_SHA256;
#else 
		MBEDTLS_SSL_DEBUG_MSG(1, ("MBEDTLS_SHA256_C not set but ciphersuite with SHA256 negotiated"));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
#endif 
	}

	if (mbedtls_hash_size_for_ciphersuite(suite_info) == 48) {
#if defined(MBEDTLS_SHA512_C)
		padbuf = (unsigned char*) NULL_HASH_SHA384;
#else 
		MBEDTLS_SSL_DEBUG_MSG(1, ("MBEDTLS_SHA512_C not set but ciphersuite with SHA384 negotiated"));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
#endif
	}

	/*
	 * Compute Early Secret with HKDF-Extract(0, PSK)
	 */

	memset(salt, 0x0, mbedtls_hash_size_for_ciphersuite(suite_info));
	ret = mbedtls_hkdf_extract(md, salt, mbedtls_hash_size_for_ciphersuite(suite_info),
		psk, psk_len, ssl->handshake->early_secret);

	 if (ret != 0) {
		 MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_hkdf_extract() with early_secret", ret);
		 return ret;
	 }

   MBEDTLS_SSL_DEBUG_MSG(5, ("HKDF Extract -- early_secret"));
   MBEDTLS_SSL_DEBUG_BUF(5, "Salt", salt, mbedtls_hash_size_for_ciphersuite(suite_info));
   MBEDTLS_SSL_DEBUG_BUF(5, "Input", psk, psk_len);
   MBEDTLS_SSL_DEBUG_BUF(5, "Output", ssl->handshake->early_secret, mbedtls_hash_size_for_ciphersuite(suite_info));

   /*
    * Derive-Secret(., "derived", "")
    */
/*
   if (mbedtls_hash_size_for_ciphersuite(suite_info) == 32) {
#if defined(MBEDTLS_SHA256_C)
	   mbedtls_sha256((const unsigned char*) "", 0, padbuf, 0); // / 0 = use SHA256 
#else 
	   MBEDTLS_SSL_DEBUG_MSG(1, ("MBEDTLS_SHA256_C not set but ciphersuite with SHA256 negotiated"));
	   return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
#endif 
   }

   if (mbedtls_hash_size_for_ciphersuite(suite_info) == 48) {
#if defined(MBEDTLS_SHA512_C)
	   mbedtls_sha512((const unsigned char*) "", 0, padbuf, 1 ); // 1 = use SHA384 
#else 
	   MBEDTLS_SSL_DEBUG_MSG(1, ("MBEDTLS_SHA512_C not set but ciphersuite with SHA384 negotiated"));
	   return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
#endif
   }
*/

	ret = Derive_Secret(ssl->transform_in->ciphersuite_info->hash,
		   ssl->handshake->early_secret, mbedtls_hash_size_for_ciphersuite(suite_info),
		   (const unsigned char*)"derived", strlen("derived"),
		   padbuf, mbedtls_hash_size_for_ciphersuite(suite_info),
		   intermediary_secret, mbedtls_hash_size_for_ciphersuite(suite_info));
   
  if (ret != 0) {
	  MBEDTLS_SSL_DEBUG_RET(1, "Derive-Secret(., 'derived', ''): Error", ret);
	  return ret;
  }

	/* 
     * Compute Handshake Secret with HKDF-Extract(Intermediary Secret, ECDHE)
	 */

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__ECDHE_ENABLED)
	if ((ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK) ||
		(ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA)){

		if (&ssl->handshake->ecdh_ctx == NULL)
			return(MBEDTLS_ERR_ECP_BAD_INPUT_DATA);

		if ((ret = mbedtls_ecdh_calc_secret(&ssl->handshake->ecdh_ctx,
			&ECDHE_len,
			ECDHE,
			sizeof(ECDHE),
			ssl->conf->f_rng, ssl->conf->p_rng)) != 0)
		{
			MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ecdh_calc_secret", ret);
			return(ret);
		}

		MBEDTLS_SSL_DEBUG_MPI(3, "ECDHE:", &ssl->handshake->ecdh_ctx.z);

	} else 
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__ECDHE_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
	if (ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK) {
		memset(ECDHE, 0x0, mbedtls_hash_size_for_ciphersuite(suite_info));
		MBEDTLS_SSL_DEBUG_BUF(3, "ECDHE", ECDHE, mbedtls_hash_size_for_ciphersuite(suite_info));
		ECDHE_len=mbedtls_hash_size_for_ciphersuite(suite_info); 
	} else 
#endif	
    {
		MBEDTLS_SSL_DEBUG_MSG(1, ("Unsupported key exchange -- mbedtls_ssl_derive_master_secret failed."));
		return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);
	}

	ret = mbedtls_hkdf_extract(md, intermediary_secret, mbedtls_hash_size_for_ciphersuite(suite_info),
		ECDHE, ECDHE_len, ssl->handshake->handshake_secret);

	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_hkdf_extract() with handshake_secret: Error", ret);
		return ret;
	}

	MBEDTLS_SSL_DEBUG_MSG(5, ("HKDF Extract -- handshake_secret"));
	MBEDTLS_SSL_DEBUG_BUF(5, "Salt", intermediary_secret, mbedtls_hash_size_for_ciphersuite(suite_info));
	MBEDTLS_SSL_DEBUG_BUF(5, "Input (ECDHE)", ECDHE, mbedtls_hash_size_for_ciphersuite(suite_info));
	MBEDTLS_SSL_DEBUG_BUF(5, "Output", ssl->handshake->handshake_secret, mbedtls_hash_size_for_ciphersuite(suite_info));

	/*
 	 * Derive-Secret(., "derived", "")
	 */

	ret = Derive_Secret(ssl->transform_in->ciphersuite_info->hash,
		ssl->handshake->handshake_secret, mbedtls_hash_size_for_ciphersuite(suite_info),
		(const unsigned char*)"derived", strlen("derived"),
		padbuf, mbedtls_hash_size_for_ciphersuite(suite_info),
		intermediary_secret, mbedtls_hash_size_for_ciphersuite(suite_info));

	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(1, "Derive-Secret(., 'derived', ''): Error", ret);
		return ret;
	}

	/*
	* Compute Master Secret with HKDF-Extract(Intermediary Secret, 0)
	*/

	memset(null_ikm, 0x0, mbedtls_hash_size_for_ciphersuite(suite_info));

	ret = mbedtls_hkdf_extract(md, intermediary_secret, mbedtls_hash_size_for_ciphersuite(suite_info),
		null_ikm, mbedtls_hash_size_for_ciphersuite(suite_info), ssl->handshake->master_secret);

	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_hkdf_extract() with master_secret: Error %d.", ret);
		return ret;
	}

	MBEDTLS_SSL_DEBUG_MSG(5, ("HKDF Extract -- master_secret"));
	MBEDTLS_SSL_DEBUG_BUF(5, "Salt", intermediary_secret, mbedtls_hash_size_for_ciphersuite(suite_info));
	MBEDTLS_SSL_DEBUG_BUF(5, "Input", null_ikm, mbedtls_hash_size_for_ciphersuite(suite_info));
	MBEDTLS_SSL_DEBUG_BUF(5, "Output", ssl->handshake->master_secret, mbedtls_hash_size_for_ciphersuite(suite_info));

	return(0);
}
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED && MBEDTLS_SSL_PROTO_TLS1_3 */


#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED) && !defined(MBEDTLS_SSL_PROTO_TLS1_3)
int mbedtls_ssl_psk_derive_premaster( mbedtls_ssl_context *ssl, mbedtls_key_exchange_type_t key_ex )
{
    unsigned char *p = ssl->handshake->premaster;
    unsigned char *end = p + sizeof( ssl->handshake->premaster );
    const unsigned char *psk = ssl->conf->psk;
    size_t psk_len = ssl->conf->psk_len;

    /* If the psk callback was called, use its result */
    if( ssl->handshake->psk != NULL )
    {
        psk = ssl->handshake->psk;
        psk_len = ssl->handshake->psk_len;
    }

    /*
     * PMS = struct {
     *     opaque other_secret<0..2^16-1>;
     *     opaque psk<0..2^16-1>;
     * };
     * with "other_secret" depending on the particular key exchange
     */
#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
    if( key_ex == MBEDTLS_KEY_EXCHANGE_PSK )
    {
        if( end - p < 2 )
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

        *(p++) = (unsigned char)( psk_len >> 8 );
        *(p++) = (unsigned char)( psk_len      );

        if( end < p || (size_t)( end - p ) < psk_len )
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

        memset( p, 0, psk_len );
        p += psk_len;
    }
    else
#endif /* MBEDTLS_KEY_EXCHANGE_PSK_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
    if( key_ex == MBEDTLS_KEY_EXCHANGE_RSA_PSK )
    {
        /*
         * other_secret already set by the ClientKeyExchange message,
         * and is 48 bytes long
         */
        *p++ = 0;
        *p++ = 48;
        p += 48;
    }
    else
#endif /* MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
    if( key_ex == MBEDTLS_KEY_EXCHANGE_DHE_PSK )
    {
        int ret;
        size_t len;

        /* Write length only when we know the actual value */
        if( ( ret = mbedtls_dhm_calc_secret( &ssl->handshake->dhm_ctx,
                                      p + 2, end - ( p + 2 ), &len,
                                      ssl->conf->f_rng, ssl->conf->p_rng ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_dhm_calc_secret", ret );
            return( ret );
        }
        *(p++) = (unsigned char)( len >> 8 );
        *(p++) = (unsigned char)( len );
        p += len;

        MBEDTLS_SSL_DEBUG_MPI( 3, "DHM: K ", &ssl->handshake->dhm_ctx.K  );
    }
    else
#endif /* MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
    if( key_ex == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK )
    {
        int ret;
        size_t zlen;

        if( ( ret = mbedtls_ecdh_calc_secret( &ssl->handshake->ecdh_ctx, &zlen,
                                       p + 2, end - ( p + 2 ),
                                       ssl->conf->f_rng, ssl->conf->p_rng ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ecdh_calc_secret", ret );
            return( ret );
        }

        *(p++) = (unsigned char)( zlen >> 8 );
        *(p++) = (unsigned char)( zlen      );
        p += zlen;
		
        MBEDTLS_SSL_DEBUG_MPI( 3, "ECDH: z", &ssl->handshake->ecdh_ctx.z );
    }
    else
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED */
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* opaque psk<0..2^16-1>; */
    if( end - p < 2 )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    *(p++) = (unsigned char)( psk_len >> 8 );
    *(p++) = (unsigned char)( psk_len      );

    if( end < p || (size_t)( end - p ) < psk_len )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    memcpy( p, psk, psk_len );
    p += psk_len;

    ssl->handshake->pmslen = p - ssl->handshake->premaster;

    return( 0 );
}
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

#if defined(MBEDTLS_SSL_PROTO_SSL3)
/*
 * SSLv3.0 MAC functions
 */
static void ssl_mac( mbedtls_md_context_t *md_ctx, unsigned char *secret,
                     unsigned char *buf, size_t len,
                     unsigned char *ctr, int type )
{
    unsigned char header[11];
    unsigned char padding[48];
    int padlen;
    int md_size = mbedtls_md_get_size( md_ctx->md_info );
    int md_type = mbedtls_md_get_type( md_ctx->md_info );

    /* Only MD5 and SHA-1 supported */
    if( md_type == MBEDTLS_MD_MD5 )
        padlen = 48;
    else
        padlen = 40;

    memcpy( header, ctr, 8 );
    header[ 8] = (unsigned char)  type;
    header[ 9] = (unsigned char)( len >> 8 );
    header[10] = (unsigned char)( len      );

    memset( padding, 0x36, padlen );
    mbedtls_md_starts( md_ctx );
    mbedtls_md_update( md_ctx, secret,  md_size );
    mbedtls_md_update( md_ctx, padding, padlen  );
    mbedtls_md_update( md_ctx, header,  11      );
    mbedtls_md_update( md_ctx, buf,     len     );
    mbedtls_md_finish( md_ctx, buf +    len     );

    memset( padding, 0x5C, padlen );
    mbedtls_md_starts( md_ctx );
    mbedtls_md_update( md_ctx, secret,    md_size );
    mbedtls_md_update( md_ctx, padding,   padlen  );
    mbedtls_md_update( md_ctx, buf + len, md_size );
    mbedtls_md_finish( md_ctx, buf + len          );
}
#endif /* MBEDTLS_SSL_PROTO_SSL3 */

#if defined(MBEDTLS_ARC4_C) || defined(MBEDTLS_CIPHER_NULL_CIPHER) ||     \
    ( defined(MBEDTLS_CIPHER_MODE_CBC) &&                                  \
      ( defined(MBEDTLS_AES_C) || defined(MBEDTLS_CAMELLIA_C) ) )
#define SSL_SOME_MODES_USE_MAC
#endif

/*
 * Encryption/decryption functions
 */
static int ssl_encrypt_buf( mbedtls_ssl_context *ssl )
{
    mbedtls_cipher_mode_t mode;
    int auth_done = 0;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "=> encrypt buf" ) );

    if( ssl->session_out == NULL || ssl->transform_out == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    mode = mbedtls_cipher_get_cipher_mode( &ssl->transform_out->cipher_ctx_enc );

    MBEDTLS_SSL_DEBUG_BUF( 4, "plaintext (before encryption)",
                      ssl->out_msg, ssl->out_msglen );

    /*
     * Add MAC before if needed
     */
#if defined(SSL_SOME_MODES_USE_MAC)
    if( mode == MBEDTLS_MODE_STREAM ||
        ( mode == MBEDTLS_MODE_CBC
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
          && ssl->session_out->encrypt_then_mac == MBEDTLS_SSL_ETM_DISABLED
#endif
        ) )
    {
#if defined(MBEDTLS_SSL_PROTO_SSL3)
        if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 )
        {
            ssl_mac( &ssl->transform_out->md_ctx_enc,
                      ssl->transform_out->mac_enc,
                      ssl->out_msg, ssl->out_msglen,
                      ssl->out_ctr, ssl->out_msgtype );
        }
        else
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1) || defined(MBEDTLS_SSL_PROTO_TLS1_1) || \
        defined(MBEDTLS_SSL_PROTO_TLS1_2) || defined(MBEDTLS_SSL_PROTO_TLS1_3)
        if( ssl->minor_ver >= MBEDTLS_SSL_MINOR_VERSION_1 )
        {
            mbedtls_md_hmac_update( &ssl->transform_out->md_ctx_enc, ssl->out_ctr, 8 );
            mbedtls_md_hmac_update( &ssl->transform_out->md_ctx_enc, ssl->out_hdr, 3 );
            mbedtls_md_hmac_update( &ssl->transform_out->md_ctx_enc, ssl->out_len, 2 );
            mbedtls_md_hmac_update( &ssl->transform_out->md_ctx_enc,
                             ssl->out_msg, ssl->out_msglen );
            mbedtls_md_hmac_finish( &ssl->transform_out->md_ctx_enc,
                             ssl->out_msg + ssl->out_msglen );
            mbedtls_md_hmac_reset( &ssl->transform_out->md_ctx_enc );
        }
        else
#endif
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        MBEDTLS_SSL_DEBUG_BUF( 4, "computed mac",
                       ssl->out_msg + ssl->out_msglen,
                       ssl->transform_out->maclen );

        ssl->out_msglen += ssl->transform_out->maclen;
        auth_done++;
    }
#endif /* AEAD not the only option */

    /*
     * Encrypt
     */
#if defined(MBEDTLS_ARC4_C) || defined(MBEDTLS_CIPHER_NULL_CIPHER)
    if( mode == MBEDTLS_MODE_STREAM )
    {
        int ret;
        size_t olen = 0;

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "before encrypt: msglen = %d, "
                            "including %d bytes of padding",
                       ssl->out_msglen, 0 ) );

        if( ( ret = mbedtls_cipher_crypt( &ssl->transform_out->cipher_ctx_enc,
                                   ssl->transform_out->iv_enc,
                                   ssl->transform_out->ivlen,
                                   ssl->out_msg, ssl->out_msglen,
                                   ssl->out_msg, &olen ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_crypt", ret );
            return( ret );
        }

        if( ssl->out_msglen != olen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
    }
    else
#endif /* MBEDTLS_ARC4_C || MBEDTLS_CIPHER_NULL_CIPHER */
#if defined(MBEDTLS_GCM_C) || defined(MBEDTLS_CCM_C)
    if( mode == MBEDTLS_MODE_GCM ||
        mode == MBEDTLS_MODE_CCM || mode == MBEDTLS_MODE_CCM_8)
    {
        int ret;
        size_t enc_msglen, olen;
        unsigned char *enc_msg;
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3) 
		unsigned char add_data[13];
#endif

		unsigned char taglen; 
		
		// Currently there is only one cipher with a short authentication tag defined
		if (ssl->transform_out->ciphersuite_info->cipher == MBEDTLS_CIPHER_AES_128_CCM_8)
			taglen = 8; 
		else taglen = 16; 

#if !defined(MBEDTLS_SSL_PROTO_TLS1_3) 
        memcpy( add_data, ssl->out_ctr, 8 );
        add_data[8]  = ssl->out_msgtype;
        mbedtls_ssl_write_version( ssl->major_ver, ssl->minor_ver,
                           ssl->conf->transport, add_data + 9 );
        add_data[11] = ( ssl->out_msglen >> 8 ) & 0xFF;
        add_data[12] = ssl->out_msglen & 0xFF;

        /*
         * Generate IV
         */
#if defined(MBEDTLS_SSL_AEAD_RANDOM_IV)
        ret = ssl->conf->f_rng( ssl->conf->p_rng,
                ssl->transform_out->iv_enc + ssl->transform_out->fixed_ivlen,
                ssl->transform_out->ivlen - ssl->transform_out->fixed_ivlen );
        if( ret != 0 )
            return( ret );

        memcpy( ssl->out_iv,
                ssl->transform_out->iv_enc + ssl->transform_out->fixed_ivlen,
                ssl->transform_out->ivlen - ssl->transform_out->fixed_ivlen );
#else
        if( ssl->transform_out->ivlen - ssl->transform_out->fixed_ivlen != 8 )
        {
            /* Reminder if we ever add an AEAD mode with a different size */
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        memcpy( ssl->transform_out->iv_enc + ssl->transform_out->fixed_ivlen,
                             ssl->out_ctr, 8 );
        memcpy( ssl->out_iv, ssl->out_ctr, 8 );
#endif /* MBEDTLS_SSL_AEAD_RANDOM_IV */

		
        /*
         * Fix pointer positions and message length with added IV
         */
        enc_msg = ssl->out_msg;
        enc_msglen = ssl->out_msglen;
        ssl->out_msglen += ssl->transform_out->ivlen -
                           ssl->transform_out->fixed_ivlen;

		MBEDTLS_SSL_DEBUG_BUF(4, "IV used",
			ssl->transform_out->iv_enc,
			ssl->transform_out->ivlen);

		MBEDTLS_SSL_DEBUG_BUF(4, "Additional data used", add_data, 13);

		MBEDTLS_SSL_DEBUG_BUF(4, "Unencrypted message: ", enc_msg, enc_msglen);

		/*
		MBEDTLS_SSL_DEBUG_MSG(3, ("before encrypt: msglen = %d, "
			"including %d bytes of padding",
			ssl->out_msglen, 0));
			*/

#else 

		enc_msg = ssl->out_msg;
		enc_msglen = ssl->out_msglen;
		// We adjust the message length since the authentication tag also consumes space.
		ssl->out_msglen += taglen;

		MBEDTLS_SSL_DEBUG_MSG(4, ("msglen (%d)", ssl->out_msglen));

		MBEDTLS_SSL_DEBUG_BUF(4, "Nonce (before)", ssl->transform_out->iv_enc, ssl->transform_out->ivlen);

		MBEDTLS_SSL_DEBUG_BUF(4, "Sequence Number (before):", ssl->transform_out->sequence_number_enc, 12);

		MBEDTLS_SSL_DEBUG_BUF(4, "Plaintext message:", enc_msg, enc_msglen);

#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)

        /*
         * Encrypt and authenticate
         */
        if( ( ret = mbedtls_cipher_auth_encrypt( &ssl->transform_out->cipher_ctx_enc,
                                         ssl->transform_out->iv_enc,
                                         ssl->transform_out->ivlen,
                                         add_data, 13,
                                         enc_msg, enc_msglen,
                                         enc_msg, &olen,
                                         enc_msg + enc_msglen, taglen ) ) != 0 )
#else 
		if ((ret = mbedtls_cipher_auth_encrypt(&ssl->transform_out->cipher_ctx_enc,
			ssl->transform_out->iv_enc,
			ssl->transform_out->ivlen,
			(const unsigned char*)"", 0, // no additional data is used in TLS 1.3
			enc_msg, enc_msglen,
			enc_msg, &olen,
			enc_msg + enc_msglen, taglen)) != 0)

#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
		{
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_auth_encrypt", ret );
            return( ret );
        }

        if( olen != enc_msglen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        //ssl->out_msglen += taglen;
        auth_done++;

		if ((ret = incrementSequenceNumber(&ssl->transform_out->sequence_number_enc[0], ssl->transform_out->iv_enc, ssl->transform_out->ivlen)) != 0) {

			MBEDTLS_SSL_DEBUG_RET(1, "Error in sequence number processing", ret);
			return(ret);
		}

		MBEDTLS_SSL_DEBUG_BUF(4, "Nonce (after)", ssl->transform_out->iv_enc, ssl->transform_out->ivlen);
		MBEDTLS_SSL_DEBUG_BUF(4, "Sequence Number (after):", ssl->transform_out->sequence_number_enc, 12);

		MBEDTLS_SSL_DEBUG_BUF(4, "Encrypted message (with tag): ", enc_msg, ssl->out_msglen);
		MBEDTLS_SSL_DEBUG_BUF(4, "Tag", enc_msg + enc_msglen, taglen);
		MBEDTLS_SSL_DEBUG_BUF(4, "Encrypted message (without tag): ", enc_msg, ssl->out_msglen-taglen);

    }
    else
#endif /* MBEDTLS_GCM_C || MBEDTLS_CCM_C */
#if defined(MBEDTLS_CIPHER_MODE_CBC) &&                                    \
    ( defined(MBEDTLS_AES_C) || defined(MBEDTLS_CAMELLIA_C) )
    if( mode == MBEDTLS_MODE_CBC )
    {
        int ret;
        unsigned char *enc_msg;
        size_t enc_msglen, padlen, olen = 0, i;

        padlen = ssl->transform_out->ivlen - ( ssl->out_msglen + 1 ) %
                 ssl->transform_out->ivlen;
        if( padlen == ssl->transform_out->ivlen )
            padlen = 0;

        for( i = 0; i <= padlen; i++ )
            ssl->out_msg[ssl->out_msglen + i] = (unsigned char) padlen;

        ssl->out_msglen += padlen + 1;

        enc_msglen = ssl->out_msglen;
        enc_msg = ssl->out_msg;

#if defined(MBEDTLS_SSL_PROTO_TLS1_1) || defined(MBEDTLS_SSL_PROTO_TLS1_2) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_3)
        /*
         * Prepend per-record IV for block cipher in TLS v1.1 and up as per
         * Method 1 (6.2.3.2. in RFC4346 and RFC5246)
         */
        if( ssl->minor_ver >= MBEDTLS_SSL_MINOR_VERSION_2 )
        {
            /*
             * Generate IV
             */
            ret = ssl->conf->f_rng( ssl->conf->p_rng, ssl->transform_out->iv_enc,
                                  ssl->transform_out->ivlen );
            if( ret != 0 )
                return( ret );

            memcpy( ssl->out_iv, ssl->transform_out->iv_enc,
                    ssl->transform_out->ivlen );

            /*
             * Fix pointer positions and message length with added IV
             */
            enc_msg = ssl->out_msg;
            enc_msglen = ssl->out_msglen;
            ssl->out_msglen += ssl->transform_out->ivlen;
        }
#endif /* MBEDTLS_SSL_PROTO_TLS1_1 || MBEDTLS_SSL_PROTO_TLS1_2 || MBEDTLS_SSL_PROTO_TLS1_3 */

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "before encrypt: msglen = %d, "
                            "including %d bytes of IV and %d bytes of padding",
                            ssl->out_msglen, ssl->transform_out->ivlen,
                            padlen + 1 ) );

        if( ( ret = mbedtls_cipher_crypt( &ssl->transform_out->cipher_ctx_enc,
                                   ssl->transform_out->iv_enc,
                                   ssl->transform_out->ivlen,
                                   enc_msg, enc_msglen,
                                   enc_msg, &olen ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_crypt", ret );
            return( ret );
        }

        if( enc_msglen != olen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

#if defined(MBEDTLS_SSL_PROTO_SSL3) || defined(MBEDTLS_SSL_PROTO_TLS1)
        if( ssl->minor_ver < MBEDTLS_SSL_MINOR_VERSION_2 )
        {
            /*
             * Save IV in SSL3 and TLS1
             */
            memcpy( ssl->transform_out->iv_enc,
                    ssl->transform_out->cipher_ctx_enc.iv,
                    ssl->transform_out->ivlen );
        }
#endif

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
        if( auth_done == 0 )
        {
            /*
             * MAC(MAC_write_key, seq_num +
             *     TLSCipherText.type +
             *     TLSCipherText.version +
             *     length_of( (IV +) ENC(...) ) +
             *     IV + // except for TLS 1.0
             *     ENC(content + padding + padding_length));
             */
            unsigned char pseudo_hdr[13];

            MBEDTLS_SSL_DEBUG_MSG( 3, ( "using encrypt then mac" ) );

            memcpy( pseudo_hdr +  0, ssl->out_ctr, 8 );
            memcpy( pseudo_hdr +  8, ssl->out_hdr, 3 );
            pseudo_hdr[11] = (unsigned char)( ( ssl->out_msglen >> 8 ) & 0xFF );
            pseudo_hdr[12] = (unsigned char)( ( ssl->out_msglen      ) & 0xFF );

            MBEDTLS_SSL_DEBUG_BUF( 4, "MAC'd meta-data", pseudo_hdr, 13 );

            mbedtls_md_hmac_update( &ssl->transform_out->md_ctx_enc, pseudo_hdr, 13 );
            mbedtls_md_hmac_update( &ssl->transform_out->md_ctx_enc,
                             ssl->out_iv, ssl->out_msglen );
            mbedtls_md_hmac_finish( &ssl->transform_out->md_ctx_enc,
                             ssl->out_iv + ssl->out_msglen );
            mbedtls_md_hmac_reset( &ssl->transform_out->md_ctx_enc );

            ssl->out_msglen += ssl->transform_out->maclen;
            auth_done++;
        }
#endif /* MBEDTLS_SSL_ENCRYPT_THEN_MAC */
    }
    else
#endif /* MBEDTLS_CIPHER_MODE_CBC &&
          ( MBEDTLS_AES_C || MBEDTLS_CAMELLIA_C ) */
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Make extra sure authentication was performed, exactly once */
    if( auth_done != 1 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "<= encrypt buf" ) );

    return( 0 );
}

#define SSL_MAX_MAC_SIZE   48

static int ssl_decrypt_buf( mbedtls_ssl_context *ssl )
{
    size_t i;
    mbedtls_cipher_mode_t mode;
    int auth_done = 0;
#if defined(SSL_SOME_MODES_USE_MAC)
    size_t padlen = 0, correct = 1;
#endif

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "=> decrypt buf" ) );

    if( ssl->session_in == NULL || ssl->transform_in == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    mode = mbedtls_cipher_get_cipher_mode( &ssl->transform_in->cipher_ctx_dec );

    if( ssl->in_msglen < ssl->transform_in->minlen )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "in_msglen (%d) < minlen (%d)",
                       ssl->in_msglen, ssl->transform_in->minlen ) );
        return( MBEDTLS_ERR_SSL_INVALID_MAC );
    }

#if defined(MBEDTLS_ARC4_C) || defined(MBEDTLS_CIPHER_NULL_CIPHER)
    if( mode == MBEDTLS_MODE_STREAM )
    {
        int ret;
        size_t olen = 0;

        padlen = 0;

        if( ( ret = mbedtls_cipher_crypt( &ssl->transform_in->cipher_ctx_dec,
                                   ssl->transform_in->iv_dec,
                                   ssl->transform_in->ivlen,
                                   ssl->in_msg, ssl->in_msglen,
                                   ssl->in_msg, &olen ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_crypt", ret );
            return( ret );
        }

        if( ssl->in_msglen != olen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
    }
    else
#endif /* MBEDTLS_ARC4_C || MBEDTLS_CIPHER_NULL_CIPHER */
#if defined(MBEDTLS_GCM_C) || defined(MBEDTLS_CCM_C)
    if( mode == MBEDTLS_MODE_GCM ||
        mode == MBEDTLS_MODE_CCM || 
		mode == MBEDTLS_MODE_CCM_8)
    {
        int ret;
        size_t dec_msglen, olen;
        unsigned char *dec_msg;
        unsigned char *dec_msg_result;
		unsigned char taglen; 
		

		// Currently there is only one cipher with a short authentication tag defined
		if (ssl->transform_in->ciphersuite_info->cipher == MBEDTLS_CIPHER_AES_128_CCM_8)
			taglen = 8;
		else taglen = 16;

#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
        unsigned char add_data[13];
        
        size_t explicit_iv_len = ssl->transform_in->ivlen -
                                 ssl->transform_in->fixed_ivlen;

		MBEDTLS_SSL_DEBUG_MSG(4, ("msglen (%d) + explicit_iv_len (%d) "
			"+ taglen (%d)", ssl->in_msglen,
			explicit_iv_len, taglen));

        if( ssl->in_msglen < explicit_iv_len + taglen )
        {
			MBEDTLS_SSL_DEBUG_MSG(1, ("ssl_decrypt_buf() - Message Length incorrect."));
            return( MBEDTLS_ERR_SSL_INVALID_MAC );
        }
        dec_msglen = ssl->in_msglen - explicit_iv_len - taglen;

        dec_msg = ssl->in_msg;
        dec_msg_result = ssl->in_msg;
        ssl->in_msglen = dec_msglen;

		// additional data is set to zero for TLS 1.3
        memcpy( add_data, ssl->in_ctr, 8 );
        add_data[8]  = ssl->in_msgtype;
        mbedtls_ssl_write_version( ssl->major_ver, ssl->minor_ver,
                           ssl->conf->transport, add_data + 9 );
        add_data[11] = ( ssl->in_msglen >> 8 ) & 0xFF;
        add_data[12] = ssl->in_msglen & 0xFF;
        memcpy( ssl->transform_in->iv_dec + ssl->transform_in->fixed_ivlen,
                ssl->in_iv,
                ssl->transform_in->ivlen - ssl->transform_in->fixed_ivlen );

        MBEDTLS_SSL_DEBUG_BUF( 4, "IV used", ssl->transform_in->iv_dec,
                                     ssl->transform_in->ivlen );

		MBEDTLS_SSL_DEBUG_BUF(4, "Additional data used", add_data, 13);

		MBEDTLS_SSL_DEBUG_BUF(4, "Encrypted message:", dec_msg, dec_msglen);

		MBEDTLS_SSL_DEBUG_BUF(4, "TAG used", dec_msg + dec_msglen, taglen);

#else 

		dec_msglen = ssl->in_msglen - taglen;
		dec_msg = ssl->in_msg;
		dec_msg_result = ssl->in_msg; // We write the result into the input buffer
		ssl->in_msglen = dec_msglen; // We adjust the message length since the authentication tag also consumes space.

		MBEDTLS_SSL_DEBUG_MSG(4, ("msglen (%d)", ssl->in_msglen));

		MBEDTLS_SSL_DEBUG_BUF(4, "Nonce (before)", ssl->transform_in->iv_dec, ssl->transform_in->ivlen);

		MBEDTLS_SSL_DEBUG_BUF(4, "Sequence Number (before):", ssl->transform_in->sequence_number_dec, 12);

		MBEDTLS_SSL_DEBUG_BUF(4, "Encrypted message (with tag):", dec_msg, dec_msglen+taglen);
		MBEDTLS_SSL_DEBUG_BUF(4, "Tag", dec_msg + dec_msglen, taglen);
		MBEDTLS_SSL_DEBUG_BUF(4, "Encrypted message (without tag):", dec_msg, dec_msglen);
#endif 

        /*
         * Decrypt and authenticate
         */
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
		if( ( ret = mbedtls_cipher_auth_decrypt( &ssl->transform_in->cipher_ctx_dec,
                                         ssl->transform_in->iv_dec,
                                         ssl->transform_in->ivlen,
                                         add_data, 13,
                                         dec_msg, dec_msglen,
                                         dec_msg_result, &olen,
                                         dec_msg + dec_msglen, taglen ) ) != 0 )
#else

		if ((ret = mbedtls_cipher_auth_decrypt(&ssl->transform_in->cipher_ctx_dec,
			ssl->transform_in->iv_dec,
			ssl->transform_in->ivlen,
			(const unsigned char*)"", 0, // no additional data is used in TLS 1.3
			dec_msg, dec_msglen,
			dec_msg_result, &olen,
			dec_msg + dec_msglen, taglen)) != 0)
#endif
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "Error in mbedtls_cipher_auth_decrypt()", ret );

            if( ret == MBEDTLS_ERR_CIPHER_AUTH_FAILED )
                return( MBEDTLS_ERR_SSL_INVALID_MAC );

            return( ret );
        }
        auth_done++;

		if ((ret = incrementSequenceNumber(&ssl->transform_in->sequence_number_dec[0], ssl->transform_in->iv_dec, ssl->transform_in->ivlen)) != 0) {
		
			MBEDTLS_SSL_DEBUG_RET(1, "Error in sequence number processing", ret);
			return(ret); 
		}

		MBEDTLS_SSL_DEBUG_BUF(4, "Nonce (after)", ssl->transform_in->iv_dec, ssl->transform_in->ivlen);
		MBEDTLS_SSL_DEBUG_BUF(4, "Sequence Number (after):", ssl->transform_in->sequence_number_dec, 12);

        if( olen != dec_msglen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
		/* This is now the structure of the resulting decrypted message: 
		 *    struct {
         *      opaque content[TLSPlaintext.length];
         *      ContentType type;
         *      uint8 zeros[length_of_padding];
         * } TLSInnerPlaintext;
         */
    }
    else
#endif /* MBEDTLS_GCM_C || MBEDTLS_CCM_C */
#if defined(MBEDTLS_CIPHER_MODE_CBC) &&                                    \
    ( defined(MBEDTLS_AES_C) || defined(MBEDTLS_CAMELLIA_C) )
    if( mode == MBEDTLS_MODE_CBC )
    {
        /*
         * Decrypt and check the padding
         */
        int ret;
        unsigned char *dec_msg;
        unsigned char *dec_msg_result;
        size_t dec_msglen;
        size_t minlen = 0;
        size_t olen = 0;

        /*
         * Check immediate ciphertext sanity
         */
#if defined(MBEDTLS_SSL_PROTO_TLS1_1) || defined(MBEDTLS_SSL_PROTO_TLS1_2) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_3)
        if( ssl->minor_ver >= MBEDTLS_SSL_MINOR_VERSION_2 )
            minlen += ssl->transform_in->ivlen;
#endif

        if( ssl->in_msglen < minlen + ssl->transform_in->ivlen ||
            ssl->in_msglen < minlen + ssl->transform_in->maclen + 1 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "msglen (%d) < max( ivlen(%d), maclen (%d) "
                                "+ 1 ) ( + expl IV )", ssl->in_msglen,
                                ssl->transform_in->ivlen,
                                ssl->transform_in->maclen ) );
            return( MBEDTLS_ERR_SSL_INVALID_MAC );
        }

        dec_msglen = ssl->in_msglen;
        dec_msg = ssl->in_msg;
        dec_msg_result = ssl->in_msg;

        /*
         * Authenticate before decrypt if enabled
         */
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
        if( ssl->session_in->encrypt_then_mac == MBEDTLS_SSL_ETM_ENABLED )
        {
            unsigned char computed_mac[SSL_MAX_MAC_SIZE];
            unsigned char pseudo_hdr[13];

            MBEDTLS_SSL_DEBUG_MSG( 3, ( "using encrypt then mac" ) );

            dec_msglen -= ssl->transform_in->maclen;
            ssl->in_msglen -= ssl->transform_in->maclen;

            memcpy( pseudo_hdr +  0, ssl->in_ctr, 8 );
            memcpy( pseudo_hdr +  8, ssl->in_hdr, 3 );
            pseudo_hdr[11] = (unsigned char)( ( ssl->in_msglen >> 8 ) & 0xFF );
            pseudo_hdr[12] = (unsigned char)( ( ssl->in_msglen      ) & 0xFF );

            MBEDTLS_SSL_DEBUG_BUF( 4, "MAC'd meta-data", pseudo_hdr, 13 );

            mbedtls_md_hmac_update( &ssl->transform_in->md_ctx_dec, pseudo_hdr, 13 );
            mbedtls_md_hmac_update( &ssl->transform_in->md_ctx_dec,
                             ssl->in_iv, ssl->in_msglen );
            mbedtls_md_hmac_finish( &ssl->transform_in->md_ctx_dec, computed_mac );
            mbedtls_md_hmac_reset( &ssl->transform_in->md_ctx_dec );

            MBEDTLS_SSL_DEBUG_BUF( 4, "message  mac", ssl->in_iv + ssl->in_msglen,
                                              ssl->transform_in->maclen );
            MBEDTLS_SSL_DEBUG_BUF( 4, "computed mac", computed_mac,
                                              ssl->transform_in->maclen );

            if( mbedtls_ssl_safer_memcmp( ssl->in_iv + ssl->in_msglen, computed_mac,
                              ssl->transform_in->maclen ) != 0 )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "message mac does not match" ) );

                return( MBEDTLS_ERR_SSL_INVALID_MAC );
            }
            auth_done++;
        }
#endif /* MBEDTLS_SSL_ENCRYPT_THEN_MAC */

        /*
         * Check length sanity
         */
        if( ssl->in_msglen % ssl->transform_in->ivlen != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "msglen (%d) %% ivlen (%d) != 0",
                           ssl->in_msglen, ssl->transform_in->ivlen ) );
            return( MBEDTLS_ERR_SSL_INVALID_MAC );
        }

#if defined(MBEDTLS_SSL_PROTO_TLS1_1) || defined(MBEDTLS_SSL_PROTO_TLS1_2) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_3)
        /*
         * Initialize for prepended IV for block cipher in TLS v1.1 and up
         */
        if( ssl->minor_ver >= MBEDTLS_SSL_MINOR_VERSION_2 )
        {
            dec_msglen -= ssl->transform_in->ivlen;
            ssl->in_msglen -= ssl->transform_in->ivlen;

            for( i = 0; i < ssl->transform_in->ivlen; i++ )
                ssl->transform_in->iv_dec[i] = ssl->in_iv[i];
        }
#endif /* MBEDTLS_SSL_PROTO_TLS1_1 || MBEDTLS_SSL_PROTO_TLS1_2 || MBEDTLS_SSL_PROTO_TLS1_3*/

        if( ( ret = mbedtls_cipher_crypt( &ssl->transform_in->cipher_ctx_dec,
                                   ssl->transform_in->iv_dec,
                                   ssl->transform_in->ivlen,
                                   dec_msg, dec_msglen,
                                   dec_msg_result, &olen ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_crypt", ret );
            return( ret );
        }

        if( dec_msglen != olen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

#if defined(MBEDTLS_SSL_PROTO_SSL3) || defined(MBEDTLS_SSL_PROTO_TLS1)
        if( ssl->minor_ver < MBEDTLS_SSL_MINOR_VERSION_2 )
        {
            /*
             * Save IV in SSL3 and TLS1
             */
            memcpy( ssl->transform_in->iv_dec,
                    ssl->transform_in->cipher_ctx_dec.iv,
                    ssl->transform_in->ivlen );
        }
#endif

        padlen = 1 + ssl->in_msg[ssl->in_msglen - 1];

        if( ssl->in_msglen < ssl->transform_in->maclen + padlen &&
            auth_done == 0 )
        {
#if defined(MBEDTLS_SSL_DEBUG_ALL)
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "msglen (%d) < maclen (%d) + padlen (%d)",
                        ssl->in_msglen, ssl->transform_in->maclen, padlen ) );
#endif
            padlen = 0;
            correct = 0;
        }

#if defined(MBEDTLS_SSL_PROTO_SSL3)
        if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 )
        {
            if( padlen > ssl->transform_in->ivlen )
            {
#if defined(MBEDTLS_SSL_DEBUG_ALL)
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad padding length: is %d, "
                                    "should be no more than %d",
                               padlen, ssl->transform_in->ivlen ) );
#endif
                correct = 0;
            }
        }
        else
#endif /* MBEDTLS_SSL_PROTO_SSL3 */
#if defined(MBEDTLS_SSL_PROTO_TLS1) || defined(MBEDTLS_SSL_PROTO_TLS1_1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_2)
        if( ssl->minor_ver > MBEDTLS_SSL_MINOR_VERSION_0 )
        {
            /*
             * TLSv1+: always check the padding up to the first failure
             * and fake check up to 256 bytes of padding
             */
            size_t pad_count = 0, real_count = 1;
            size_t padding_idx = ssl->in_msglen - padlen - 1;

            /*
             * Padding is guaranteed to be incorrect if:
             *   1. padlen >= ssl->in_msglen
             *
             *   2. padding_idx >= MBEDTLS_SSL_MAX_CONTENT_LEN +
             *                     ssl->transform_in->maclen
             *
             * In both cases we reset padding_idx to a safe value (0) to
             * prevent out-of-buffer reads.
             */
            correct &= ( ssl->in_msglen >= padlen + 1 );
            correct &= ( padding_idx < MBEDTLS_SSL_MAX_CONTENT_LEN +
                                       ssl->transform_in->maclen );

            padding_idx *= correct;

            for( i = 1; i <= 256; i++ )
            {
                real_count &= ( i <= padlen );
                pad_count += real_count *
                             ( ssl->in_msg[padding_idx + i] == padlen - 1 );
            }

            correct &= ( pad_count == padlen ); /* Only 1 on correct padding */

#if defined(MBEDTLS_SSL_DEBUG_ALL)
            if( padlen > 0 && correct == 0 )
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad padding byte detected" ) );
#endif
            padlen &= correct * 0x1FF;
        }
        else
#endif /* MBEDTLS_SSL_PROTO_TLS1 || MBEDTLS_SSL_PROTO_TLS1_1 || \
          MBEDTLS_SSL_PROTO_TLS1_2 */
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        ssl->in_msglen -= padlen;
    }
    else
#endif /* MBEDTLS_CIPHER_MODE_CBC &&
          ( MBEDTLS_AES_C || MBEDTLS_CAMELLIA_C ) */
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /*
     * Authenticate if not done yet.
     * Compute the MAC regardless of the padding result (RFC4346, CBCTIME).
     */
#if defined(SSL_SOME_MODES_USE_MAC)
    if( auth_done == 0 )
    {
        unsigned char tmp[SSL_MAX_MAC_SIZE];

        ssl->in_msglen -= ssl->transform_in->maclen;

        ssl->in_len[0] = (unsigned char)( ssl->in_msglen >> 8 );
        ssl->in_len[1] = (unsigned char)( ssl->in_msglen      );

        memcpy( tmp, ssl->in_msg + ssl->in_msglen, ssl->transform_in->maclen );

#if defined(MBEDTLS_SSL_PROTO_SSL3)
        if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 )
        {
            ssl_mac( &ssl->transform_in->md_ctx_dec,
                      ssl->transform_in->mac_dec,
                      ssl->in_msg, ssl->in_msglen,
                      ssl->in_ctr, ssl->in_msgtype );
        }
        else
#endif /* MBEDTLS_SSL_PROTO_SSL3 */
#if defined(MBEDTLS_SSL_PROTO_TLS1) || defined(MBEDTLS_SSL_PROTO_TLS1_1) || \
        defined(MBEDTLS_SSL_PROTO_TLS1_2) || defined(MBEDTLS_SSL_PROTO_TLS1_3)
        if( ssl->minor_ver > MBEDTLS_SSL_MINOR_VERSION_0 )
        {
            /*
             * Process MAC and always update for padlen afterwards to make
             * total time independent of padlen
             *
             * extra_run compensates MAC check for padlen
             *
             * Known timing attacks:
             *  - Lucky Thirteen (http://www.isg.rhul.ac.uk/tls/TLStiming.pdf)
             *
             * We use ( ( Lx + 8 ) / 64 ) to handle 'negative Lx' values
             * correctly. (We round down instead of up, so -56 is the correct
             * value for our calculations instead of -55)
             */
            size_t j, extra_run = 0;
            extra_run = ( 13 + ssl->in_msglen + padlen + 8 ) / 64 -
                        ( 13 + ssl->in_msglen          + 8 ) / 64;

            extra_run &= correct * 0xFF;

            mbedtls_md_hmac_update( &ssl->transform_in->md_ctx_dec, ssl->in_ctr, 8 );
            mbedtls_md_hmac_update( &ssl->transform_in->md_ctx_dec, ssl->in_hdr, 3 );
            mbedtls_md_hmac_update( &ssl->transform_in->md_ctx_dec, ssl->in_len, 2 );
            mbedtls_md_hmac_update( &ssl->transform_in->md_ctx_dec, ssl->in_msg,
                             ssl->in_msglen );
            mbedtls_md_hmac_finish( &ssl->transform_in->md_ctx_dec,
                             ssl->in_msg + ssl->in_msglen );
            /* Call mbedtls_md_process at least once due to cache attacks */
            for( j = 0; j < extra_run + 1; j++ )
                mbedtls_md_process( &ssl->transform_in->md_ctx_dec, ssl->in_msg );

            mbedtls_md_hmac_reset( &ssl->transform_in->md_ctx_dec );
        }
        else
#endif /* MBEDTLS_SSL_PROTO_TLS1 || MBEDTLS_SSL_PROTO_TLS1_1 || \
              MBEDTLS_SSL_PROTO_TLS1_2 || MBEDTLS_SSL_PROTO_TLS1_3*/
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        MBEDTLS_SSL_DEBUG_BUF( 4, "message  mac", tmp, ssl->transform_in->maclen );
        MBEDTLS_SSL_DEBUG_BUF( 4, "computed mac", ssl->in_msg + ssl->in_msglen,
                       ssl->transform_in->maclen );

        if( mbedtls_ssl_safer_memcmp( tmp, ssl->in_msg + ssl->in_msglen,
                         ssl->transform_in->maclen ) != 0 )
        {
#if defined(MBEDTLS_SSL_DEBUG_ALL)
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "message mac does not match" ) );
#endif
            correct = 0;
        }
        auth_done++;

        /*
         * Finally check the correct flag
         */
        if( correct == 0 )
            return( MBEDTLS_ERR_SSL_INVALID_MAC );
    }
#endif /* SSL_SOME_MODES_USE_MAC */

    /* Make extra sure authentication was performed, exactly once */
    if( auth_done != 1 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( ssl->in_msglen == 0 )
    {
        ssl->nb_zero++;

        /*
         * Three or more empty messages may be a DoS attack
         * (excessive CPU consumption).
         */
        if( ssl->nb_zero > 3 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "received four consecutive empty "
                                "messages, possible DoS attack" ) );
            return( MBEDTLS_ERR_SSL_INVALID_MAC );
        }
    }
    else
        ssl->nb_zero = 0;

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        ; /* in_ctr read from peer, not maintained internally */
    }
    else
#endif
    {
        for( i = 8; i > ssl_ep_len( ssl ); i-- )
            if( ++ssl->in_ctr[i - 1] != 0 )
                break;

        /* The loop goes to its end iff the counter is wrapping */
        if( i == ssl_ep_len( ssl ) )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "incoming message counter would wrap" ) );
            return( MBEDTLS_ERR_SSL_COUNTER_WRAPPING );
        }
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "<= decrypt buf" ) );

    return( 0 );
}

#undef MAC_NONE
#undef MAC_PLAINTEXT
#undef MAC_CIPHERTEXT

#if defined(MBEDTLS_ZLIB_SUPPORT)
/*
 * Compression/decompression functions
 */
static int ssl_compress_buf( mbedtls_ssl_context *ssl )
{
    int ret;
    unsigned char *msg_post = ssl->out_msg;
    size_t len_pre = ssl->out_msglen;
    unsigned char *msg_pre = ssl->compress_buf;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> compress buf" ) );

    if( len_pre == 0 )
        return( 0 );

    memcpy( msg_pre, ssl->out_msg, len_pre );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "before compression: msglen = %d, ",
                   ssl->out_msglen ) );

    MBEDTLS_SSL_DEBUG_BUF( 4, "before compression: output payload",
                   ssl->out_msg, ssl->out_msglen );

    ssl->transform_out->ctx_deflate.next_in = msg_pre;
    ssl->transform_out->ctx_deflate.avail_in = len_pre;
    ssl->transform_out->ctx_deflate.next_out = msg_post;
    ssl->transform_out->ctx_deflate.avail_out = MBEDTLS_SSL_BUFFER_LEN;

    ret = deflate( &ssl->transform_out->ctx_deflate, Z_SYNC_FLUSH );
    if( ret != Z_OK )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "failed to perform compression (%d)", ret ) );
        return( MBEDTLS_ERR_SSL_COMPRESSION_FAILED );
    }

    ssl->out_msglen = MBEDTLS_SSL_BUFFER_LEN -
                      ssl->transform_out->ctx_deflate.avail_out;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "after compression: msglen = %d, ",
                   ssl->out_msglen ) );

    MBEDTLS_SSL_DEBUG_BUF( 4, "after compression: output payload",
                   ssl->out_msg, ssl->out_msglen );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= compress buf" ) );

    return( 0 );
}

static int ssl_decompress_buf( mbedtls_ssl_context *ssl )
{
    int ret;
    unsigned char *msg_post = ssl->in_msg;
    size_t len_pre = ssl->in_msglen;
    unsigned char *msg_pre = ssl->compress_buf;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> decompress buf" ) );

    if( len_pre == 0 )
        return( 0 );

    memcpy( msg_pre, ssl->in_msg, len_pre );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "before decompression: msglen = %d, ",
                   ssl->in_msglen ) );

    MBEDTLS_SSL_DEBUG_BUF( 4, "before decompression: input payload",
                   ssl->in_msg, ssl->in_msglen );

    ssl->transform_in->ctx_inflate.next_in = msg_pre;
    ssl->transform_in->ctx_inflate.avail_in = len_pre;
    ssl->transform_in->ctx_inflate.next_out = msg_post;
    ssl->transform_in->ctx_inflate.avail_out = MBEDTLS_SSL_MAX_CONTENT_LEN;

    ret = inflate( &ssl->transform_in->ctx_inflate, Z_SYNC_FLUSH );
    if( ret != Z_OK )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "failed to perform decompression (%d)", ret ) );
        return( MBEDTLS_ERR_SSL_COMPRESSION_FAILED );
    }

    ssl->in_msglen = MBEDTLS_SSL_MAX_CONTENT_LEN -
                     ssl->transform_in->ctx_inflate.avail_out;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "after decompression: msglen = %d, ",
                   ssl->in_msglen ) );

    MBEDTLS_SSL_DEBUG_BUF( 4, "after decompression: input payload",
                   ssl->in_msg, ssl->in_msglen );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= decompress buf" ) );

    return( 0 );
}
#endif /* MBEDTLS_ZLIB_SUPPORT */

#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_RENEGOTIATION)
static int ssl_write_hello_request( mbedtls_ssl_context *ssl );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
static int ssl_resend_hello_request( mbedtls_ssl_context *ssl )
{
    /* If renegotiation is not enforced, retransmit until we would reach max
     * timeout if we were using the usual handshake doubling scheme */
    if( ssl->conf->renego_max_records < 0 )
    {
        uint32_t ratio = ssl->conf->hs_timeout_max / ssl->conf->hs_timeout_min + 1;
        unsigned char doublings = 1;

        while( ratio != 0 )
        {
            ++doublings;
            ratio >>= 1;
        }

        if( ++ssl->renego_records_seen > doublings )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "no longer retransmitting hello request" ) );
            return( 0 );
        }
    }

    return( ssl_write_hello_request( ssl ) );
}
#endif
#endif /* MBEDTLS_SSL_SRV_C && MBEDTLS_SSL_RENEGOTIATION */

/*
 * Fill the input message buffer by appending data to it.
 * The amount of data already fetched is in ssl->in_left.
 *
 * If we return 0, is it guaranteed that (at least) nb_want bytes are
 * available (from this read and/or a previous one). Otherwise, an error code
 * is returned (possibly EOF or WANT_READ).
 *
 * With stream transport (TLS) on success ssl->in_left == nb_want, but
 * with datagram transport (DTLS) on success ssl->in_left >= nb_want,
 * since we always read a whole datagram at once.
 *
 * For DTLS, it is up to the caller to set ssl->next_record_offset when
 * they're done reading a record.
 */
int mbedtls_ssl_fetch_input( mbedtls_ssl_context *ssl, size_t nb_want )
{
    int ret;
    size_t len;

    MBEDTLS_SSL_DEBUG_MSG( 5, ( "=> fetch input" ) );

    if( ssl->f_recv == NULL && ssl->f_recv_timeout == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Bad usage of mbedtls_ssl_set_bio() "
                            "or mbedtls_ssl_set_bio()" ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    if( nb_want > MBEDTLS_SSL_BUFFER_LEN - (size_t)( ssl->in_hdr - ssl->in_buf ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "requesting more data than fits" ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        uint32_t timeout;

        /* Just to be sure */
        if( ssl->f_set_timer == NULL || ssl->f_get_timer == NULL )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "You must use "
                        "mbedtls_ssl_set_timer_cb() for DTLS" ) );
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
        }

        /*
         * The point is, we need to always read a full datagram at once, so we
         * sometimes read more then requested, and handle the additional data.
         * It could be the rest of the current record (while fetching the
         * header) and/or some other records in the same datagram.
         */

        /*
         * Move to the next record in the already read datagram if applicable
         */
        if( ssl->next_record_offset != 0 )
        {
            if( ssl->in_left < ssl->next_record_offset )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
            }

            ssl->in_left -= ssl->next_record_offset;

            if( ssl->in_left != 0 )
            {
                MBEDTLS_SSL_DEBUG_MSG( 2, ( "next record in same datagram, offset: %d",
                                    ssl->next_record_offset ) );
                memmove( ssl->in_hdr,
                         ssl->in_hdr + ssl->next_record_offset,
                         ssl->in_left );
            }

            ssl->next_record_offset = 0;
        }

        MBEDTLS_SSL_DEBUG_MSG( 2, ( "in_left: %d, nb_want: %d",
                       ssl->in_left, nb_want ) );

        /*
         * Done if we already have enough data.
         */
        if( nb_want <= ssl->in_left)
        {
            MBEDTLS_SSL_DEBUG_MSG( 5, ( "<= fetch input" ) );
            return( 0 );
        }

        /*
         * A record can't be split accross datagrams. If we need to read but
         * are not at the beginning of a new record, the caller did something
         * wrong.
         */
        if( ssl->in_left != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        /*
         * Don't even try to read if time's out already.
         * This avoids by-passing the timer when repeatedly receiving messages
         * that will end up being dropped.
         */
        if( ssl_check_timer( ssl ) != 0 )
            ret = MBEDTLS_ERR_SSL_TIMEOUT;
        else
        {
            len = MBEDTLS_SSL_BUFFER_LEN - ( ssl->in_hdr - ssl->in_buf );

            if( ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER )
                timeout = ssl->handshake->retransmit_timeout;
            else
                timeout = ssl->conf->read_timeout;

            MBEDTLS_SSL_DEBUG_MSG( 3, ( "f_recv_timeout: %u ms", timeout ) );

            if( ssl->f_recv_timeout != NULL )
                ret = ssl->f_recv_timeout( ssl->p_bio, ssl->in_hdr, len,
                                                                    timeout );
            else
                ret = ssl->f_recv( ssl->p_bio, ssl->in_hdr, len );

            MBEDTLS_SSL_DEBUG_RET( 2, "ssl->f_recv(_timeout)", ret );

            if( ret == 0 )
                return( MBEDTLS_ERR_SSL_CONN_EOF );
        }

        if( ret == MBEDTLS_ERR_SSL_TIMEOUT )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "timeout" ) );
            ssl_set_timer( ssl, 0 );

            if( ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER )
            {
                if( ssl_double_retransmit_timeout( ssl ) != 0 )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "handshake timeout" ) );
                    return( MBEDTLS_ERR_SSL_TIMEOUT );
                }

                if( ( ret = mbedtls_ssl_resend( ssl ) ) != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_resend", ret );
                    return( ret );
                }

                return( MBEDTLS_ERR_SSL_WANT_READ );
            }
#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_RENEGOTIATION)
            else if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER &&
                     ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_PENDING )
            {
                if( ( ret = ssl_resend_hello_request( ssl ) ) != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "ssl_resend_hello_request", ret );
                    return( ret );
                }

                return( MBEDTLS_ERR_SSL_WANT_READ );
            }
#endif /* MBEDTLS_SSL_SRV_C && MBEDTLS_SSL_RENEGOTIATION */
        }

        if( ret < 0 )
            return( ret );

        ssl->in_left = ret;
    }
    else
#endif
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "in_left: %d, nb_want: %d",
                       ssl->in_left, nb_want ) );

        while( ssl->in_left < nb_want )
        {
            len = nb_want - ssl->in_left;

            if( ssl_check_timer( ssl ) != 0 )
                ret = MBEDTLS_ERR_SSL_TIMEOUT;
            else
            {
                if( ssl->f_recv_timeout != NULL )
                {
                    ret = ssl->f_recv_timeout( ssl->p_bio,
                                               ssl->in_hdr + ssl->in_left, len,
                                               ssl->conf->read_timeout );
                }
                else
                {
                    ret = ssl->f_recv( ssl->p_bio,
                                       ssl->in_hdr + ssl->in_left, len );
                }
            }

            MBEDTLS_SSL_DEBUG_MSG( 2, ( "in_left: %d, nb_want: %d",
                                        ssl->in_left, nb_want ) );
            MBEDTLS_SSL_DEBUG_RET( 2, "ssl->f_recv(_timeout)", ret );

            if( ret == 0 )
                return( MBEDTLS_ERR_SSL_CONN_EOF );

            if( ret < 0 )
                return( ret );

            ssl->in_left += ret;
        }
    }

    MBEDTLS_SSL_DEBUG_MSG( 5, ( "<= fetch input" ) );

    return( 0 );
}

/*
 * Flush any data not yet written
 */
int mbedtls_ssl_flush_output( mbedtls_ssl_context *ssl )
{
    int ret;
    unsigned char *buf, i;

    MBEDTLS_SSL_DEBUG_MSG( 5, ( "=> flush output" ) );

    if( ssl->f_send == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Bad usage of mbedtls_ssl_set_bio() "
                            "or mbedtls_ssl_set_bio()" ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    /* Avoid incrementing counter if data is flushed */
    if( ssl->out_left == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 5, ( "<= flush output" ) );
        return( 0 );
    }

    while( ssl->out_left > 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "message length: %d, out_left: %d",
                       mbedtls_ssl_hdr_len( ssl ) + ssl->out_msglen, ssl->out_left ) );

        buf = ssl->out_hdr + mbedtls_ssl_hdr_len( ssl ) +
              ssl->out_msglen - ssl->out_left;
        ret = ssl->f_send( ssl->p_bio, buf, ssl->out_left );

        MBEDTLS_SSL_DEBUG_RET( 2, "ssl->f_send", ret );

        if( ret <= 0 )
            return( ret );

        ssl->out_left -= ret;
    }

    for( i = 8; i > ssl_ep_len( ssl ); i-- )
        if( ++ssl->out_ctr[i - 1] != 0 )
            break;

    /* The loop goes to its end iff the counter is wrapping */
    if( i == ssl_ep_len( ssl ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "outgoing message counter would wrap" ) );
        return( MBEDTLS_ERR_SSL_COUNTER_WRAPPING );
    }

    MBEDTLS_SSL_DEBUG_MSG( 5, ( "<= flush output" ) );

    return( 0 );
}

/*
 * Functions to handle the DTLS retransmission state machine
 */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
/*
 * Append current handshake message to current outgoing flight
 */
static int ssl_flight_append( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_flight_item *msg;

    /* Allocate space for current message */
    if( ( msg = mbedtls_calloc( 1, sizeof(  mbedtls_ssl_flight_item ) ) ) == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "alloc %d bytes failed",
                            sizeof( mbedtls_ssl_flight_item ) ) );
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    if( ( msg->p = mbedtls_calloc( 1, ssl->out_msglen ) ) == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "alloc %d bytes failed", ssl->out_msglen ) );
        mbedtls_free( msg );
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    /* Copy current handshake message with headers */
    memcpy( msg->p, ssl->out_msg, ssl->out_msglen );
    msg->len = ssl->out_msglen;
    msg->type = ssl->out_msgtype;
    msg->next = NULL;

    /* Append to the current flight */
    if( ssl->handshake->flight == NULL )
        ssl->handshake->flight = msg;
    else
    {
        mbedtls_ssl_flight_item *cur = ssl->handshake->flight;
        while( cur->next != NULL )
            cur = cur->next;
        cur->next = msg;
    }

    return( 0 );
}

/*
 * Free the current flight of handshake messages
 */
static void ssl_flight_free( mbedtls_ssl_flight_item *flight )
{
    mbedtls_ssl_flight_item *cur = flight;
    mbedtls_ssl_flight_item *next;

    while( cur != NULL )
    {
        next = cur->next;

        mbedtls_free( cur->p );
        mbedtls_free( cur );

        cur = next;
    }
}

#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
static void ssl_dtls_replay_reset( mbedtls_ssl_context *ssl );
#endif

/*
 * Swap transform_out and out_ctr with the alternative ones
 */
static void ssl_swap_epochs( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_transform *tmp_transform;
    unsigned char tmp_out_ctr[8];

    if( ssl->transform_out == ssl->handshake->alt_transform_out )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "skip swap epochs" ) );
        return;
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "swap epochs" ) );

    /* Swap transforms */
    tmp_transform                     = ssl->transform_out;
    ssl->transform_out                = ssl->handshake->alt_transform_out;
    ssl->handshake->alt_transform_out = tmp_transform;

    /* Swap epoch + sequence_number */
    memcpy( tmp_out_ctr,                 ssl->out_ctr,                8 );
    memcpy( ssl->out_ctr,                ssl->handshake->alt_out_ctr, 8 );
    memcpy( ssl->handshake->alt_out_ctr, tmp_out_ctr,                 8 );

    /* Adjust to the newly activated transform */
    if( ssl->transform_out != NULL &&
        ssl->minor_ver >= MBEDTLS_SSL_MINOR_VERSION_2 )
    {
        ssl->out_msg = ssl->out_iv + ssl->transform_out->ivlen -
                                     ssl->transform_out->fixed_ivlen;
    }
    else
        ssl->out_msg = ssl->out_iv;

#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
    if( mbedtls_ssl_hw_record_activate != NULL )
    {
        if( ( ret = mbedtls_ssl_hw_record_activate( ssl, MBEDTLS_SSL_CHANNEL_OUTBOUND ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_hw_record_activate", ret );
            return( MBEDTLS_ERR_SSL_HW_ACCEL_FAILED );
        }
    }
#endif
}

/*
 * Retransmit the current flight of messages.
 *
 * Need to remember the current message in case flush_output returns
 * WANT_WRITE, causing us to exit this function and come back later.
 * This function must be called until state is no longer SENDING.
 */
int mbedtls_ssl_resend( mbedtls_ssl_context *ssl )
{
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> mbedtls_ssl_resend" ) );

    if( ssl->handshake->retransmit_state != MBEDTLS_SSL_RETRANS_SENDING )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "initialise resending" ) );

        ssl->handshake->cur_msg = ssl->handshake->flight;
        ssl_swap_epochs( ssl );

        ssl->handshake->retransmit_state = MBEDTLS_SSL_RETRANS_SENDING;
    }

    while( ssl->handshake->cur_msg != NULL )
    {
        int ret;
        mbedtls_ssl_flight_item *cur = ssl->handshake->cur_msg;

        /* Swap epochs before sending Finished: we can't do it after
         * sending ChangeCipherSpec, in case write returns WANT_READ.
         * Must be done before copying, may change out_msg pointer */
        if( cur->type == MBEDTLS_SSL_MSG_HANDSHAKE &&
            cur->p[0] == MBEDTLS_SSL_HS_FINISHED )
        {
            ssl_swap_epochs( ssl );
        }

        memcpy( ssl->out_msg, cur->p, cur->len );
        ssl->out_msglen = cur->len;
        ssl->out_msgtype = cur->type;

        ssl->handshake->cur_msg = cur->next;

        MBEDTLS_SSL_DEBUG_BUF( 3, "resent handshake message header", ssl->out_msg, 12 );

        if( ( ret = mbedtls_ssl_write_record( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_record", ret );
            return( ret );
        }
    }

    if( ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER )
        ssl->handshake->retransmit_state = MBEDTLS_SSL_RETRANS_FINISHED;
    else
    {
        ssl->handshake->retransmit_state = MBEDTLS_SSL_RETRANS_WAITING;
        ssl_set_timer( ssl, ssl->handshake->retransmit_timeout );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= mbedtls_ssl_resend" ) );

    return( 0 );
}

/*
 * To be called when the last message of an incoming flight is received.
 */
void mbedtls_ssl_recv_flight_completed( mbedtls_ssl_context *ssl )
{
    /* We won't need to resend that one any more */
    ssl_flight_free( ssl->handshake->flight );
    ssl->handshake->flight = NULL;
    ssl->handshake->cur_msg = NULL;

    /* The next incoming flight will start with this msg_seq */
    ssl->handshake->in_flight_start_seq = ssl->handshake->in_msg_seq;

    /* Cancel timer */
    ssl_set_timer( ssl, 0 );

    if( ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE &&
        ssl->in_msg[0] == MBEDTLS_SSL_HS_FINISHED )
    {
        ssl->handshake->retransmit_state = MBEDTLS_SSL_RETRANS_FINISHED;
    }
    else
        ssl->handshake->retransmit_state = MBEDTLS_SSL_RETRANS_PREPARING;
}

/*
 * To be called when the last message of an outgoing flight is send.
 */
void mbedtls_ssl_send_flight_completed( mbedtls_ssl_context *ssl )
{
    ssl_reset_retransmit_timeout( ssl );
    ssl_set_timer( ssl, ssl->handshake->retransmit_timeout );

    if( ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE &&
        ssl->in_msg[0] == MBEDTLS_SSL_HS_FINISHED )
    {
        ssl->handshake->retransmit_state = MBEDTLS_SSL_RETRANS_FINISHED;
    }
    else
        ssl->handshake->retransmit_state = MBEDTLS_SSL_RETRANS_WAITING;
}
#endif /* MBEDTLS_SSL_PROTO_DTLS */

/*
 * Record layer functions
 */

/*
 * Write current record.
 * Uses ssl->out_msgtype, ssl->out_msglen and bytes at ssl->out_msg.
 */
int mbedtls_ssl_write_record( mbedtls_ssl_context *ssl )
{
    int ret, done = 0;
	size_t dummy_length;
    size_t len = ssl->out_msglen;

    MBEDTLS_SSL_DEBUG_MSG( 5, ( "=> write record" ) );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
	if ((ssl->out_buf != NULL) && (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM)) {
		ssl->out_buf[3] = (char)(ssl->in_epoch >> 8) & 0xFF;
		ssl->out_buf[4] = (char)(ssl->in_epoch) & 0xFF;
	}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

	if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake != NULL &&
        ssl->handshake->retransmit_state == MBEDTLS_SSL_RETRANS_SENDING )
    {
        ; /* Skip special handshake treatment when resending */
    }
    else
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
	if ((ssl->out_msg != NULL) && (ssl->out_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE)) { 
#else 
    if( ssl->out_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE ) { 
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
       if( ssl->out_msg[0] != MBEDTLS_SSL_HS_HELLO_REQUEST &&
            ssl->handshake == NULL && ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER)
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }


#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
	    /*
		 * Adding the length info from the Handshake header. 
		 *  The msg_type was already added earlier.
		 *
		 *  struct {
		 *    HandshakeType msg_type;
		 *    uint24 length;
		 *    select(HandshakeType) {
		 *       case hello_request:       HelloRequest;
		 *       case client_hello:        ClientHello;
		 *       case server_hello:        ServerHello;
		 *       case certificate:         Certificate;
		 *       case server_key_exchange: ServerKeyExchange;
		 *       case certificate_request: CertificateRequest;
		 *       case server_hello_done:   ServerHelloDone;
		 *       case certificate_verify:  CertificateVerify;
		 *       case client_key_exchange: ClientKeyExchange;
		 *       case finished:            Finished;
		 *    } body;
		 *  } Handshake;
         *
		 */

	   ssl->out_msg[1] = (unsigned char)((len - 4) >> 16);
	   ssl->out_msg[2] = (unsigned char)((len - 4) >> 8);
	   ssl->out_msg[3] = (unsigned char)((len - 4));

	   if (ssl->transform_out != NULL) {
		   // We add the ContentType to the end of the payload
		   // and fake the one visible from the outside. 
		   ssl->out_msg[len] = MBEDTLS_SSL_MSG_HANDSHAKE;
		   len += 1; 
		   ssl->out_msglen += 1; 
	   }
	  
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */


#if defined(MBEDTLS_SSL_PROTO_DTLS)
	   /*
	   * DTLS has additional fields in the Handshake layer,
	   * between the length field and the actual payload:
	   *      uint16 message_seq;
	   *      uint24 fragment_offset;
	   *      uint24 fragment_length;
	   */
	   if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        {
            /* Make room for the additional DTLS fields */
            memmove( ssl->out_msg + mbedtls_ssl_hs_hdr_len(ssl), ssl->out_msg + 4, len - 4 );
            ssl->out_msglen += 8;
#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
			// Advancing also the pointer to the pre_shared_key extension (if used)
			if ((ssl->handshake!=NULL) && (ssl->handshake->pre_shared_key_pointer!=NULL)) {
				ssl->handshake->pre_shared_key_pointer += 8;
			}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 && MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */
			len += 8;

            /* Write message_seq and update it */
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
			if (ssl->out_msg[0] == MBEDTLS_SSL_HS_HELLO_REQUEST)
            {
				ssl->out_msg[4] = 0;
				ssl->out_msg[5] = 0;
            } else 
#else 
			if (ssl->out_msg[0] == MBEDTLS_SSL_HS_NEW_SESSION_TICKET) {
				/* Here we just fake the sequence number field.
				 * In the future we need to store the sequence number in the 
				 * session state (instead of the handshake state).
				 */
				ssl->out_msg[4] = 5;
				ssl->out_msg[5] = 0;
			} else 
#endif /* !MBEDTLS_SSL_PROTO_TLS1_3 */
			{
				ssl->out_msg[4] = (ssl->handshake->out_msg_seq >> 8) & 0xFF;
				ssl->out_msg[5] = (ssl->handshake->out_msg_seq) & 0xFF;
				++(ssl->handshake->out_msg_seq);
			}

            /* We don't fragment, so frag_offset = 0 and frag_len = len */
            memset( ssl->out_msg + 6, 0x00, 3 );
            memcpy( ssl->out_msg + 9, ssl->out_msg + 1, 3 );
        }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
		/* We need to patch the psk binder by 
		 * re-running the function to get the correct length information for the extension. 
		 * But: we only do that when in ClientHello state and when using a PSK mode
		 */ 
		if ((ssl->conf->endpoint== MBEDTLS_SSL_IS_CLIENT)
			&& 
			(ssl->state == MBEDTLS_SSL_CLIENT_HELLO)
			&& 
			(ssl->handshake->extensions_present & PRE_SHARED_KEY_EXTENSION)
			&&
			(ssl->conf->key_exchange_modes == KEY_EXCHANGE_MODE_PSK_ALL ||
				ssl->conf->key_exchange_modes == KEY_EXCHANGE_MODE_PSK_KE ||
				ssl->conf->key_exchange_modes == KEY_EXCHANGE_MODE_PSK_DHE_KE)) {

			ssl_write_pre_shared_key_ext(ssl, ssl->handshake->pre_shared_key_pointer, &dummy_length, 1);
		}
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

		// For post-handshake messages we do not need to update the hash anymore
		if (ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER) {

//			if (ssl->transform_out != NULL && ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER) {
			if (ssl->transform_out != NULL) {
				/* If we append the handshake type to the message then we
				* don't include it in the handshake hash. */

				MBEDTLS_SSL_DEBUG_MSG(5, ("--- Update Checksum (mbedtls_ssl_write_record-1)"));

				ssl->handshake->update_checksum(ssl, ssl->out_msg, len - 1);
			}
			else
			{
				MBEDTLS_SSL_DEBUG_MSG(5, ("--- Update Checksum (mbedtls_ssl_write_record)"));
				ssl->handshake->update_checksum(ssl, ssl->out_msg, len);
			}
		}
#else   
		if (ssl->out_msg[0] != MBEDTLS_SSL_HS_HELLO_REQUEST) {
			MBEDTLS_SSL_DEBUG_MSG(5, ("--- Update Checksum (mbedtls_ssl_write_record)"));
			ssl->handshake->update_checksum(ssl, ssl->out_msg, len);
		}
#endif
	}

    /* Save handshake and CCS messages for resending */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake != NULL &&
        ssl->handshake->retransmit_state != MBEDTLS_SSL_RETRANS_SENDING &&
        ( ssl->out_msgtype == MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC ||
          ssl->out_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE ) )
    {
        if( ( ret = ssl_flight_append( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "ssl_flight_append", ret );
            return( ret );
        }
    }
#endif

#if defined(MBEDTLS_ZLIB_SUPPORT)
    if( ssl->transform_out != NULL &&
        ssl->session_out->compression == MBEDTLS_SSL_COMPRESS_DEFLATE )
    {
        if( ( ret = ssl_compress_buf( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "ssl_compress_buf", ret );
            return( ret );
        }

        len = ssl->out_msglen;
    }
#endif /*MBEDTLS_ZLIB_SUPPORT */

#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
    if( mbedtls_ssl_hw_record_write != NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "going for mbedtls_ssl_hw_record_write()" ) );

        ret = mbedtls_ssl_hw_record_write( ssl );
        if( ret != 0 && ret != MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_hw_record_write", ret );
            return( MBEDTLS_ERR_SSL_HW_ACCEL_FAILED );
        }

        if( ret == 0 )
            done = 1;
    }
#endif /* MBEDTLS_SSL_HW_RECORD_ACCEL */

/* 

 --- TLS Record Layer Header --- 

struct {
    uint8 major;
    uint8 minor;
} ProtocolVersion;

enum {
    alert(21),
    handshake(22),
    application_data(23)
    (255)
} ContentType;

struct {
    ContentType type;
    ProtocolVersion record_version = { 3, 1 };   
	uint16 length;
	opaque fragment[TLSPlaintext.length];
} TLSPlaintext;

For TLS 1.3 we use the same version number.  

*/
	if( !done )
    {

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
		// Set ContentType in Record Layer header
		if (ssl->transform_out != NULL) {
			/* In case of TLS 1.3 for encrypted payloads we claim that we are 
			 * sending application data but in reality we are using  
			 * an encrypted handshake message. 
			 */
			ssl->out_hdr[0] = MBEDTLS_SSL_MSG_APPLICATION_DATA;
		}
		else 
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
		{
			ssl->out_hdr[0] = (unsigned char)ssl->out_msgtype;
		}

		// Protocol Version 
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
		/* TLS 1.3 re-uses the version {3, 4} in the ClientHello, Serverhello, 
		 * etc. but the record layer still uses {3, 1} and hence we need to patch it.
		 */

		mbedtls_ssl_write_version(3, 1,
			ssl->conf->transport, ssl->out_hdr + 1);

#else
		mbedtls_ssl_write_version(ssl->major_ver, ssl->minor_ver,
			ssl->conf->transport, ssl->out_hdr + 1 );
#endif

		// Length
        ssl->out_len[0] = (unsigned char)( len >> 8 );
        ssl->out_len[1] = (unsigned char)( len      );

        if( ssl->transform_out != NULL )
        {
            if( ( ret = ssl_encrypt_buf( ssl ) ) != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_encrypt_buf", ret );
                return( ret );
            }

            len = ssl->out_msglen;
            ssl->out_len[0] = (unsigned char)( len >> 8 );
            ssl->out_len[1] = (unsigned char)( len      );
        }

        ssl->out_left = mbedtls_ssl_hdr_len( ssl ) + ssl->out_msglen;

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "output record: msgtype = %d, "
                            "version = [%d:%d], msglen = %d",
                       ssl->out_hdr[0], ssl->out_hdr[1], ssl->out_hdr[2],
                     ( ssl->out_len[0] << 8 ) | ssl->out_len[1] ) );

        MBEDTLS_SSL_DEBUG_BUF( 4, "SENT TO THE NETWORK",
                       ssl->out_hdr, mbedtls_ssl_hdr_len( ssl ) + ssl->out_msglen );
    }

    if( ( ret = mbedtls_ssl_flush_output( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_flush_output", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_MSG( 5, ( "<= write record" ) );

    return( 0 );
}

#if defined(MBEDTLS_SSL_PROTO_DTLS)
/*
 * Mark bits in bitmask (used for DTLS HS reassembly)
 */
static void ssl_bitmask_set( unsigned char *mask, size_t offset, size_t len )
{
    unsigned int start_bits, end_bits;

    start_bits = 8 - ( offset % 8 );
    if( start_bits != 8 )
    {
        size_t first_byte_idx = offset / 8;

        /* Special case */
        if( len <= start_bits )
        {
            for( ; len != 0; len-- )
                mask[first_byte_idx] |= 1 << ( start_bits - len );

            /* Avoid potential issues with offset or len becoming invalid */
            return;
        }

        offset += start_bits; /* Now offset % 8 == 0 */
        len -= start_bits;

        for( ; start_bits != 0; start_bits-- )
            mask[first_byte_idx] |= 1 << ( start_bits - 1 );
    }

    end_bits = len % 8;
    if( end_bits != 0 )
    {
        size_t last_byte_idx = ( offset + len ) / 8;

        len -= end_bits; /* Now len % 8 == 0 */

        for( ; end_bits != 0; end_bits-- )
            mask[last_byte_idx] |= 1 << ( 8 - end_bits );
    }

    memset( mask + offset / 8, 0xFF, len / 8 );
}

/*
 * Check that bitmask is full
 */
static int ssl_bitmask_check( unsigned char *mask, size_t len )
{
    size_t i;

    for( i = 0; i < len / 8; i++ )
        if( mask[i] != 0xFF )
            return( -1 );

    for( i = 0; i < len % 8; i++ )
        if( ( mask[len / 8] & ( 1 << ( 7 - i ) ) ) == 0 )
            return( -1 );

    return( 0 );
}

/*
 * Reassemble fragmented DTLS handshake messages.
 *
 * Use a temporary buffer for reassembly, divided in two parts:
 * - the first holds the reassembled message (including handshake header),
 * - the second holds a bitmask indicating which parts of the message
 *   (excluding headers) have been received so far.
 */
static int ssl_reassemble_dtls_handshake( mbedtls_ssl_context *ssl )
{
    unsigned char *msg, *bitmask;
    size_t frag_len, frag_off;
    size_t msg_len = ssl->in_hslen - 12; /* Without headers */

    if( ssl->handshake == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "not supported outside handshake (for now)" ) );
        return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    /*
     * For first fragment, check size and allocate buffer
     */
    if( ssl->handshake->hs_msg == NULL )
    {
        size_t alloc_len;

        MBEDTLS_SSL_DEBUG_MSG( 2, ( "initialize reassembly, total length = %d",
                            msg_len ) );

        if( ssl->in_hslen > MBEDTLS_SSL_MAX_CONTENT_LEN )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "handshake message too large" ) );
            return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
        }

        /* The bitmask needs one bit per byte of message excluding header */
        alloc_len = 12 + msg_len + msg_len / 8 + ( msg_len % 8 != 0 );

        ssl->handshake->hs_msg = mbedtls_calloc( 1, alloc_len );
        if( ssl->handshake->hs_msg == NULL )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "alloc failed (%d bytes)", alloc_len ) );
            return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
        }

        /* Prepare final header: copy msg_type, length and message_seq,
         * then add standardised fragment_offset and fragment_length */
        memcpy( ssl->handshake->hs_msg, ssl->in_msg, 6 );
        memset( ssl->handshake->hs_msg + 6, 0, 3 );
        memcpy( ssl->handshake->hs_msg + 9,
                ssl->handshake->hs_msg + 1, 3 );
    }
    else
    {
        /* Make sure msg_type and length are consistent */
        if( memcmp( ssl->handshake->hs_msg, ssl->in_msg, 4 ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "fragment header mismatch" ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }
    }

    msg = ssl->handshake->hs_msg + 12;
    bitmask = msg + msg_len;

    /*
     * Check and copy current fragment
     */
    frag_off = ( ssl->in_msg[6]  << 16 ) |
               ( ssl->in_msg[7]  << 8  ) |
                 ssl->in_msg[8];
    frag_len = ( ssl->in_msg[9]  << 16 ) |
               ( ssl->in_msg[10] << 8  ) |
                 ssl->in_msg[11];

    if( frag_off + frag_len > msg_len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid fragment offset/len: %d + %d > %d",
                          frag_off, frag_len, msg_len ) );
        return( MBEDTLS_ERR_SSL_INVALID_RECORD );
    }

    if( frag_len + 12 > ssl->in_msglen )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid fragment length: %d + 12 > %d",
                          frag_len, ssl->in_msglen ) );
        return( MBEDTLS_ERR_SSL_INVALID_RECORD );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "adding fragment, offset = %d, length = %d",
                        frag_off, frag_len ) );

    memcpy( msg + frag_off, ssl->in_msg + 12, frag_len );
    ssl_bitmask_set( bitmask, frag_off, frag_len );

    /*
     * Do we have the complete message by now?
     * If yes, finalize it, else ask to read the next record.
     */
    if( ssl_bitmask_check( bitmask, msg_len ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "message is not complete yet" ) );
        return( MBEDTLS_ERR_SSL_WANT_READ );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "handshake message completed" ) );

    if( frag_len + 12 < ssl->in_msglen )
    {
        /*
         * We'got more handshake messages in the same record.
         * This case is not handled now because no know implementation does
         * that and it's hard to test, so we prefer to fail cleanly for now.
         */
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "last fragment not alone in its record" ) );
        return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    if( ssl->in_left > ssl->next_record_offset )
    {
        /*
         * We've got more data in the buffer after the current record,
         * that we don't want to overwrite. Move it before writing the
         * reassembled message, and adjust in_left and next_record_offset.
         */
        unsigned char *cur_remain = ssl->in_hdr + ssl->next_record_offset;
        unsigned char *new_remain = ssl->in_msg + ssl->in_hslen;
        size_t remain_len = ssl->in_left - ssl->next_record_offset;

        /* First compute and check new lengths */
        ssl->next_record_offset = new_remain - ssl->in_hdr;
        ssl->in_left = ssl->next_record_offset + remain_len;

        if( ssl->in_left > MBEDTLS_SSL_BUFFER_LEN -
                           (size_t)( ssl->in_hdr - ssl->in_buf ) )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "reassembled message too large for buffer" ) );
            return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
        }

        memmove( new_remain, cur_remain, remain_len );
    }

    memcpy( ssl->in_msg, ssl->handshake->hs_msg, ssl->in_hslen );

    mbedtls_free( ssl->handshake->hs_msg );
    ssl->handshake->hs_msg = NULL;

    MBEDTLS_SSL_DEBUG_BUF( 3, "reassembled handshake message",
                   ssl->in_msg, ssl->in_hslen );

    return( 0 );
}
#endif /* MBEDTLS_SSL_PROTO_DTLS */

static int ssl_prepare_handshake_record( mbedtls_ssl_context *ssl )
{
    if( ssl->in_msglen < mbedtls_ssl_hs_hdr_len( ssl ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "handshake message too short: %d",
                            ssl->in_msglen ) );
        return( MBEDTLS_ERR_SSL_INVALID_RECORD );
    }

    ssl->in_hslen = mbedtls_ssl_hs_hdr_len( ssl ) + (
                    ( ssl->in_msg[1] << 16 ) |
                    ( ssl->in_msg[2] << 8  ) |
                      ssl->in_msg[3] );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "handshake message: msglen ="
                        " %d, type = %d, hslen = %d",
                        ssl->in_msglen, ssl->in_msg[0], ssl->in_hslen ) );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        int ret;
        unsigned int recv_msg_seq = ( ssl->in_msg[4] << 8 ) | ssl->in_msg[5];

        /* ssl->handshake is NULL when receiving ClientHello for renego */
        if( ssl->handshake != NULL &&
            recv_msg_seq != ssl->handshake->in_msg_seq )
        {
            /* Retransmit only on last message from previous flight, to avoid
             * too many retransmissions.
             * Besides, No sane server ever retransmits HelloVerifyRequest */
            if( recv_msg_seq == ssl->handshake->in_flight_start_seq - 1 &&
                ssl->in_msg[0] != MBEDTLS_SSL_HS_HELLO_VERIFY_REQUEST )
            {
                MBEDTLS_SSL_DEBUG_MSG( 2, ( "received message from last flight, "
                                    "message_seq = %d, start_of_flight = %d",
                                    recv_msg_seq,
                                    ssl->handshake->in_flight_start_seq ) );

                if( ( ret = mbedtls_ssl_resend( ssl ) ) != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_resend", ret );
                    return( ret );
                }
            }
            else
            {
                MBEDTLS_SSL_DEBUG_MSG( 2, ( "dropping out-of-sequence message: "
                                    "message_seq = %d, expected = %d",
                                    recv_msg_seq,
                                    ssl->handshake->in_msg_seq ) );
            }

            return( MBEDTLS_ERR_SSL_WANT_READ );
        }
        /* Wait until message completion to increment in_msg_seq */

        /* Reassemble if current message is fragmented or reassembly is
         * already in progress */
        if( ssl->in_msglen < ssl->in_hslen ||
            memcmp( ssl->in_msg + 6, "\0\0\0",        3 ) != 0 ||
            memcmp( ssl->in_msg + 9, ssl->in_msg + 1, 3 ) != 0 ||
            ( ssl->handshake != NULL && ssl->handshake->hs_msg != NULL ) )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "found fragmented DTLS handshake message" ) );

            if( ( ret = ssl_reassemble_dtls_handshake( ssl ) ) != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_reassemble_dtls_handshake", ret );
                return( ret );
            }
        }
    }
    else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    /* With TLS we don't handle fragmentation (for now) */
    if( ssl->in_msglen < ssl->in_hslen )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "TLS handshake fragmentation not supported" ) );
        return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    if( ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER &&
        ssl->handshake != NULL )
    {
		/*
		 * If the server responds with the HRR message then a special handling  
		 * with the modified transcript hash is necessary. We compute this hash later.
		 */
		if (ssl->in_msg[0] != MBEDTLS_SSL_HS_HELLO_RETRY_REQUEST) {
			MBEDTLS_SSL_DEBUG_MSG(5, ("--- Update Checksum (ssl_prepare_handshake_record)")); 
			ssl->handshake->update_checksum(ssl, ssl->in_msg, ssl->in_hslen);
		}
    }

    /* Handshake message is complete, increment counter */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake != NULL )
    {
        ssl->handshake->in_msg_seq++;
    }
#endif

    return( 0 );
}

/*
 * DTLS anti-replay: RFC 6347 4.1.2.6
 *
 * in_window is a field of bits numbered from 0 (lsb) to 63 (msb).
 * Bit n is set iff record number in_window_top - n has been seen.
 *
 * Usually, in_window_top is the last record number seen and the lsb of
 * in_window is set. The only exception is the initial state (record number 0
 * not seen yet).
 */
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
static void ssl_dtls_replay_reset( mbedtls_ssl_context *ssl )
{
    ssl->in_window_top = 0;
    ssl->in_window = 0;
}

static inline uint64_t ssl_load_six_bytes( unsigned char *buf )
{
    return( ( (uint64_t) buf[0] << 40 ) |
            ( (uint64_t) buf[1] << 32 ) |
            ( (uint64_t) buf[2] << 24 ) |
            ( (uint64_t) buf[3] << 16 ) |
            ( (uint64_t) buf[4] <<  8 ) |
            ( (uint64_t) buf[5]       ) );
}

/*
 * Return 0 if sequence number is acceptable, -1 otherwise
 */
int mbedtls_ssl_dtls_replay_check( mbedtls_ssl_context *ssl )
{
    uint64_t rec_seqnum = ssl_load_six_bytes( ssl->in_ctr + 2 );
    uint64_t bit;

    if( ssl->conf->anti_replay == MBEDTLS_SSL_ANTI_REPLAY_DISABLED )
        return( 0 );

    if( rec_seqnum > ssl->in_window_top )
        return( 0 );

    bit = ssl->in_window_top - rec_seqnum;

    if( bit >= 64 )
        return( -1 );

    if( ( ssl->in_window & ( (uint64_t) 1 << bit ) ) != 0 )
        return( -1 );

    return( 0 );
}

/*
 * Update replay window on new validated record
 */
void mbedtls_ssl_dtls_replay_update( mbedtls_ssl_context *ssl )
{
    uint64_t rec_seqnum = ssl_load_six_bytes( ssl->in_ctr + 2 );

    if( ssl->conf->anti_replay == MBEDTLS_SSL_ANTI_REPLAY_DISABLED )
        return;

    if( rec_seqnum > ssl->in_window_top )
    {
        /* Update window_top and the contents of the window */
        uint64_t shift = rec_seqnum - ssl->in_window_top;

        if( shift >= 64 )
            ssl->in_window = 1;
        else
        {
            ssl->in_window <<= shift;
            ssl->in_window |= 1;
        }

        ssl->in_window_top = rec_seqnum;
    }
    else
    {
        /* Mark that number as seen in the current window */
        uint64_t bit = ssl->in_window_top - rec_seqnum;

        if( bit < 64 ) /* Always true, but be extra sure */
            ssl->in_window |= (uint64_t) 1 << bit;
    }
}
#endif /* MBEDTLS_SSL_DTLS_ANTI_REPLAY */

#if defined(MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE) && defined(MBEDTLS_SSL_SRV_C)
/* Forward declaration */
static int ssl_session_reset_int( mbedtls_ssl_context *ssl, int partial );

/*
 * Without any SSL context, check if a datagram looks like a ClientHello with
 * a valid cookie, and if it doesn't, generate a HelloVerifyRequest message.
 * Both input and output include full DTLS headers.
 *
 * - if cookie is valid, return 0
 * - if ClientHello looks superficially valid but cookie is not,
 *   fill obuf and set olen, then
 *   return MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED
 * - otherwise return a specific error code
 */
static int ssl_check_dtls_clihlo_cookie(
                           mbedtls_ssl_cookie_write_t *f_cookie_write,
                           mbedtls_ssl_cookie_check_t *f_cookie_check,
                           void *p_cookie,
                           const unsigned char *cli_id, size_t cli_id_len,
                           const unsigned char *in, size_t in_len,
                           unsigned char *obuf, size_t buf_len, size_t *olen )
{
    size_t sid_len, cookie_len;
    unsigned char *p;

    if( f_cookie_write == NULL || f_cookie_check == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    /*
     * Structure of ClientHello with record and handshake headers,
     * and expected values. We don't need to check a lot, more checks will be
     * done when actually parsing the ClientHello - skipping those checks
     * avoids code duplication and does not make cookie forging any easier.
     *
     *  0-0  ContentType type;                  copied, must be handshake
     *  1-2  ProtocolVersion version;           copied
     *  3-4  uint16 epoch;                      copied, must be 0
     *  5-10 uint48 sequence_number;            copied
     * 11-12 uint16 length;                     (ignored)
     *
     * 13-13 HandshakeType msg_type;            (ignored)
     * 14-16 uint24 length;                     (ignored)
     * 17-18 uint16 message_seq;                copied
     * 19-21 uint24 fragment_offset;            copied, must be 0
     * 22-24 uint24 fragment_length;            (ignored)
     *
     * 25-26 ProtocolVersion client_version;    (ignored)
     * 27-58 Random random;                     (ignored)
     * 59-xx SessionID session_id;              1 byte len + sid_len content
     * 60+   opaque cookie<0..2^8-1>;           1 byte len + content
     *       ...
     *
     * Minimum length is 61 bytes.
     */
    if( in_len < 61 ||
        in[0] != MBEDTLS_SSL_MSG_HANDSHAKE ||
        in[3] != 0 || in[4] != 0 ||
        in[19] != 0 || in[20] != 0 || in[21] != 0 )
    {
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    sid_len = in[59];
    if( sid_len > in_len - 61 )
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );

    cookie_len = in[60 + sid_len];
    if( cookie_len > in_len - 60 )
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );

    if( f_cookie_check( p_cookie, in + sid_len + 61, cookie_len,
                        cli_id, cli_id_len ) == 0 )
    {
        /* Valid cookie */
        return( 0 );
    }

    /*
     * If we get here, we've got an invalid cookie, let's prepare HVR.
     *
     *  0-0  ContentType type;                  copied
     *  1-2  ProtocolVersion version;           copied
     *  3-4  uint16 epoch;                      copied
     *  5-10 uint48 sequence_number;            copied
     * 11-12 uint16 length;                     olen - 13
     *
     * 13-13 HandshakeType msg_type;            hello_verify_request
     * 14-16 uint24 length;                     olen - 25
     * 17-18 uint16 message_seq;                copied
     * 19-21 uint24 fragment_offset;            copied
     * 22-24 uint24 fragment_length;            olen - 25
     *
     * 25-26 ProtocolVersion server_version;    0xfe 0xff
     * 27-27 opaque cookie<0..2^8-1>;           cookie_len = olen - 27, cookie
     *
     * Minimum length is 28.
     */
    if( buf_len < 28 )
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );

    /* Copy most fields and adapt others */
    memcpy( obuf, in, 25 );
    obuf[13] = MBEDTLS_SSL_HS_HELLO_VERIFY_REQUEST;
    obuf[25] = 0xfe;
    obuf[26] = 0xff;

    /* Generate and write actual cookie */
    p = obuf + 28;
    if( f_cookie_write( p_cookie,
                        &p, obuf + buf_len, cli_id, cli_id_len ) != 0 )
    {
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    *olen = p - obuf;

    /* Go back and fill length fields */
    obuf[27] = (unsigned char)( *olen - 28 );

    obuf[14] = obuf[22] = (unsigned char)( ( *olen - 25 ) >> 16 );
    obuf[15] = obuf[23] = (unsigned char)( ( *olen - 25 ) >>  8 );
    obuf[16] = obuf[24] = (unsigned char)( ( *olen - 25 )       );

    obuf[11] = (unsigned char)( ( *olen - 13 ) >>  8 );
    obuf[12] = (unsigned char)( ( *olen - 13 )       );

    return( MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED );
}

/*
 * Handle possible client reconnect with the same UDP quadruplet
 * (RFC 6347 Section 4.2.8).
 *
 * Called by ssl_parse_record_header() in case we receive an epoch 0 record
 * that looks like a ClientHello.
 *
 * - if the input looks like a ClientHello without cookies,
 *   send back HelloVerifyRequest, then
 *   return MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED
 * - if the input looks like a ClientHello with a valid cookie,
 *   reset the session of the current context, and
 *   return MBEDTLS_ERR_SSL_CLIENT_RECONNECT
 * - if anything goes wrong, return a specific error code
 *
 * mbedtls_ssl_read_record() will ignore the record if anything else than
 * MBEDTLS_ERR_SSL_CLIENT_RECONNECT or 0 is returned, although this function
 * cannot not return 0.
 */
static int ssl_handle_possible_reconnect( mbedtls_ssl_context *ssl )
{
    int ret;
    size_t len;

    ret = ssl_check_dtls_clihlo_cookie(
            ssl->conf->f_cookie_write,
            ssl->conf->f_cookie_check,
            ssl->conf->p_cookie,
            ssl->cli_id, ssl->cli_id_len,
            ssl->in_buf, ssl->in_left,
            ssl->out_buf, MBEDTLS_SSL_MAX_CONTENT_LEN, &len );

    MBEDTLS_SSL_DEBUG_RET( 2, "ssl_check_dtls_clihlo_cookie", ret );

    if( ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED )
    {
        /* Dont check write errors as we can't do anything here.
         * If the error is permanent we'll catch it later,
         * if it's not, then hopefully it'll work next time. */
        (void) ssl->f_send( ssl->p_bio, ssl->out_buf, len );

        return( MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED );
    }

    if( ret == 0 )
    {
        /* Got a valid cookie, partially reset context */
        if( ( ret = ssl_session_reset_int( ssl, 1 ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "reset", ret );
            return( ret );
        }

        return( MBEDTLS_ERR_SSL_CLIENT_RECONNECT );
    }

    return( ret );
}
#endif /* MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE && MBEDTLS_SSL_SRV_C */

/*
 * ContentType type;
 * ProtocolVersion version;
 * uint16 epoch;            // DTLS only
 * uint48 sequence_number;  // DTLS only
 * uint16 length;
 */
static int ssl_parse_record_header( mbedtls_ssl_context *ssl )
{
    int ret;
    int major_ver, minor_ver;

    MBEDTLS_SSL_DEBUG_BUF( 4, "input record header", ssl->in_hdr, mbedtls_ssl_hdr_len( ssl ) );

    ssl->in_msgtype =  ssl->in_hdr[0];
    ssl->in_msglen = ( ssl->in_len[0] << 8 ) | ssl->in_len[1];
    mbedtls_ssl_read_version( &major_ver, &minor_ver, ssl->conf->transport, ssl->in_hdr + 1 );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "input record: msgtype = %d, "
                        "version = [%d:%d], msglen = %d",
                        ssl->in_msgtype,
                        major_ver, minor_ver, ssl->in_msglen ) );

    /* Check record type */
    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE &&
        ssl->in_msgtype != MBEDTLS_SSL_MSG_ALERT &&
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
		ssl->in_msgtype != MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC &&
#endif
        ssl->in_msgtype != MBEDTLS_SSL_MSG_APPLICATION_DATA )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "unknown record type" ) );

        if( ( ret = mbedtls_ssl_send_alert_message( ssl,
                        MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                        MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE ) ) != 0 )
        {
            return( ret );
        }

        return( MBEDTLS_ERR_SSL_INVALID_RECORD );
    }

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        /* Drop unexpected ChangeCipherSpec messages */
        /* Change Cipherspec messages do not exist in TLS 1.3
		
		if( ssl->in_msgtype == MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC &&
            ssl->state != MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC &&
            ssl->state != MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "dropping unexpected ChangeCipherSpec" ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }
		*/ 
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
		/* Drop unexpected ApplicationData records,
         * except at the beginning of renegotiations */
        if( ssl->in_msgtype == MBEDTLS_SSL_MSG_APPLICATION_DATA &&
            ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER
#if defined(MBEDTLS_SSL_RENEGOTIATION)
            && ! ( ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS &&
                   ssl->state == MBEDTLS_SSL_SERVER_HELLO )
#endif /* MBEDTLS_SSL_RENEGOTIATION */
            )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "dropping unexpected ApplicationData" ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
	}
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    /* Check version */
    if( major_ver != ssl->major_ver )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "major version mismatch" ) );
        return( MBEDTLS_ERR_SSL_INVALID_RECORD );
    }

    if( minor_ver > ssl->conf->max_minor_ver )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "minor version mismatch" ) );
        return( MBEDTLS_ERR_SSL_INVALID_RECORD );
    }

    /* Check epoch (and sequence number) with DTLS */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        unsigned int rec_epoch = ( ssl->in_ctr[0] << 8 ) | ssl->in_ctr[1];

        if( rec_epoch != ssl->in_epoch )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "record from another epoch: "
                                        "expected %d, received %d",
                                        ssl->in_epoch, rec_epoch ) );

#if defined(MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE) && defined(MBEDTLS_SSL_SRV_C)
            /*
             * Check for an epoch 0 ClientHello. We can't use in_msg here to
             * access the first byte of record content (handshake type), as we
             * have an active transform (possibly iv_len != 0), so use the
             * fact that the record header len is 13 instead.
             */
            if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER &&
                ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER &&
                rec_epoch == 0 &&
                ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE &&
                ssl->in_left > 13 &&
                ssl->in_buf[13] == MBEDTLS_SSL_HS_CLIENT_HELLO )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "possible client reconnect "
                                            "from the same port" ) );
                return( ssl_handle_possible_reconnect( ssl ) );
            }
            else
#endif /* MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE && MBEDTLS_SSL_SRV_C */
                return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }

#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
        /* Replay detection only works for the current epoch */
        if( rec_epoch == ssl->in_epoch &&
            mbedtls_ssl_dtls_replay_check( ssl ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "replayed record" ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }
#endif
    }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    /* Check length against the size of our buffer */
    if( ssl->in_msglen > MBEDTLS_SSL_BUFFER_LEN
                         - (size_t)( ssl->in_msg - ssl->in_buf ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad message length" ) );
        return( MBEDTLS_ERR_SSL_INVALID_RECORD );
    }

    /* Check length against bounds of the current transform and version */
    if( ssl->transform_in == NULL )
    {
        if( ssl->in_msglen < 1 ||
            ssl->in_msglen > MBEDTLS_SSL_MAX_CONTENT_LEN )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad message length" ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }
    }
    else
    {
        if( ssl->in_msglen < ssl->transform_in->minlen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad message length" ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }
 
#if defined(MBEDTLS_SSL_PROTO_SSL3)
        if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 &&
            ssl->in_msglen > ssl->transform_in->minlen + MBEDTLS_SSL_MAX_CONTENT_LEN )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad message length" ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1) || defined(MBEDTLS_SSL_PROTO_TLS1_1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_2) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_3)
        /*
         * TLS encrypted messages can have up to 256 bytes of padding
         */
        if( ssl->minor_ver >= MBEDTLS_SSL_MINOR_VERSION_1 &&
            ssl->in_msglen > ssl->transform_in->minlen +
                             MBEDTLS_SSL_MAX_CONTENT_LEN + 256 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad message length" ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }
#endif
    }

    return( 0 );
}

/*
 * If applicable, decrypt (and decompress) record content
 */
static int ssl_prepare_record_content( mbedtls_ssl_context *ssl )
{
    int ret, done = 0;

    MBEDTLS_SSL_DEBUG_BUF( 4, "RECEIVED FROM NETWORK",
                   ssl->in_hdr, mbedtls_ssl_hdr_len( ssl ) + ssl->in_msglen );

#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
    if( mbedtls_ssl_hw_record_read != NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "going for mbedtls_ssl_hw_record_read()" ) );

        ret = mbedtls_ssl_hw_record_read( ssl );
        if( ret != 0 && ret != MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_hw_record_read", ret );
            return( MBEDTLS_ERR_SSL_HW_ACCEL_FAILED );
        }

        if( ret == 0 )
            done = 1;
    }
#endif /* MBEDTLS_SSL_HW_RECORD_ACCEL */
    if( !done && ssl->transform_in != NULL )
    {
        if( ( ret = ssl_decrypt_buf( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "ssl_decrypt_buf", ret );
            return( ret );
        }

        MBEDTLS_SSL_DEBUG_BUF( 4, "input payload after decrypt",
                       ssl->in_msg, ssl->in_msglen );

        if( ssl->in_msglen > MBEDTLS_SSL_MAX_CONTENT_LEN )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad message length" ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }
    }

#if defined(MBEDTLS_ZLIB_SUPPORT)
    if( ssl->transform_in != NULL &&
        ssl->session_in->compression == MBEDTLS_SSL_COMPRESS_DEFLATE )
    {
        if( ( ret = ssl_decompress_buf( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "ssl_decompress_buf", ret );
            return( ret );
        }

        // TODO: what's the purpose of these lines? is in_len used?
        ssl->in_len[0] = (unsigned char)( ssl->in_msglen >> 8 );
        ssl->in_len[1] = (unsigned char)( ssl->in_msglen      );
    }
#endif /* MBEDTLS_ZLIB_SUPPORT */

#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        mbedtls_ssl_dtls_replay_update( ssl );
    }
#endif

    return( 0 );
}

static void ssl_handshake_wrapup_free_hs_transform( mbedtls_ssl_context *ssl );

/*
 * Read a record.
 *
 * Silently ignore non-fatal alert (and for DTLS, invalid records as well,
 * RFC 6347 4.1.2.7) and continue reading until a valid record is found.
 *
 */
// TBD: This code requires refactoring. 

int mbedtls_ssl_read_record( mbedtls_ssl_context *ssl )
{
    int ret;

    MBEDTLS_SSL_DEBUG_MSG( 5, ( "=> read record" ) );

    if( ssl->in_hslen != 0 && ssl->in_hslen < ssl->in_msglen )
    {
        /*
         * Get next Handshake message in the current record
         */
        ssl->in_msglen -= ssl->in_hslen;

        memmove( ssl->in_msg, ssl->in_msg + ssl->in_hslen,
                 ssl->in_msglen );

        MBEDTLS_SSL_DEBUG_BUF( 4, "remaining content in record",
                           ssl->in_msg, ssl->in_msglen );

        if( ( ret = ssl_prepare_handshake_record( ssl ) ) != 0 )
            return( ret );

        return( 0 );
    }

    ssl->in_hslen = 0;

    /*
     * Read the record header and parse it
     */
read_record_header:
    if( ( ret = mbedtls_ssl_fetch_input( ssl, mbedtls_ssl_hdr_len( ssl ) ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_fetch_input", ret );
        return( ret );
    }

    if( ( ret = ssl_parse_record_header( ssl ) ) != 0 )
    {
#if defined(MBEDTLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
            ret != MBEDTLS_ERR_SSL_CLIENT_RECONNECT )
        {
            /* Ignore bad record and get next one; drop the whole datagram
             * since current header cannot be trusted to find the next record
             * in current datagram */
            ssl->next_record_offset = 0;
            ssl->in_left = 0;

            MBEDTLS_SSL_DEBUG_MSG( 1, ( "discarding invalid record (header)" ) );
            goto read_record_header;
        }
#endif
        return( ret );
    }

    /*
     * Read message contents
     */
    if( ( ret = mbedtls_ssl_fetch_input( ssl,
                                 mbedtls_ssl_hdr_len( ssl ) + ssl->in_msglen ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_fetch_input", ret );
        return( ret );
    }

    /* Done reading this record, get ready for the next one */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        ssl->next_record_offset = ssl->in_msglen + mbedtls_ssl_hdr_len( ssl );
    else
#endif
        ssl->in_left = 0;

	/*
	* optionally decrypt message
	*/
	
    if( ( ret = ssl_prepare_record_content( ssl ) ) != 0 )
    {
#if defined(MBEDTLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        {
            /* Silently discard invalid records */
            if( ret == MBEDTLS_ERR_SSL_INVALID_RECORD ||
                ret == MBEDTLS_ERR_SSL_INVALID_MAC )
            {
                /* Except when waiting for Finished as a bad mac here
                 * probably means something went wrong in the handshake
                 * (eg wrong psk used, mitm downgrade attempt, etc.) */
                if( ssl->state == MBEDTLS_SSL_CLIENT_FINISHED ||
                    ssl->state == MBEDTLS_SSL_SERVER_FINISHED )
                {
#if defined(MBEDTLS_SSL_ALL_ALERT_MESSAGES)
                    if( ret == MBEDTLS_ERR_SSL_INVALID_MAC )
                    {
                        mbedtls_ssl_send_alert_message( ssl,
                                MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                MBEDTLS_SSL_ALERT_MSG_BAD_RECORD_MAC );
                    }
#endif
                    return( ret );
                }

#if defined(MBEDTLS_SSL_DTLS_BADMAC_LIMIT)
                if( ssl->conf->badmac_limit != 0 &&
                    ++ssl->badmac_seen >= ssl->conf->badmac_limit )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "too many records with bad MAC" ) );
                    return( MBEDTLS_ERR_SSL_INVALID_MAC );
                }
#endif

                MBEDTLS_SSL_DEBUG_MSG( 1, ( "discarding invalid record (mac)" ) );
                goto read_record_header;
            }

            return( ret );
        }
        else
#endif
        {
            /* Error out (and send alert) on invalid records */
#if defined(MBEDTLS_SSL_ALL_ALERT_MESSAGES)
            if( ret == MBEDTLS_ERR_SSL_INVALID_MAC )
            {
                mbedtls_ssl_send_alert_message( ssl,
                        MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                        MBEDTLS_SSL_ALERT_MSG_BAD_RECORD_MAC );
            }
#endif
            return( ret );
        }
    }

    /*
     * When we sent the last flight of the handshake, we MUST respond to a
     * retransmit of the peer's previous flight with a retransmit. (In
     * practice, only the Finished message will make it, other messages
     * including CCS use the old transform so they're dropped as invalid.)
     *
     * If the record we received is not a handshake message, however, it
     * means the peer received our last flight so we can clean up
     * handshake info.
     *
     * This check needs to be done before prepare_handshake() due to an edge
     * case: if the client immediately requests renegotiation, this
     * finishes the current handshake first, avoiding the new ClientHello
     * being mistaken for an ancient message in the current handshake.
     */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake != NULL &&
        ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER )
    {
        if( ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE &&
                ssl->in_msg[0] == MBEDTLS_SSL_HS_FINISHED )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "received retransmit of last flight" ) );

            if( ( ret = mbedtls_ssl_resend( ssl ) ) != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_resend", ret );
                return( ret );
            }

            return( MBEDTLS_ERR_SSL_WANT_READ );
        }
        else
        {
            ssl_handshake_wrapup_free_hs_transform( ssl );
        }
    }
#endif

    /*
     * Handshake message processing for unencrypted handshake messages
     */
    if( ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE )
    {
        if( ( ret = ssl_prepare_handshake_record( ssl ) ) != 0 )
            return( ret );
    }

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
	/* This case happens with encrypted handshake messages, 
	 * such as the EncryptedExtension or the Finished messages. */
	if ((ssl->in_msgtype == MBEDTLS_SSL_MSG_APPLICATION_DATA) && (ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER))
	{
		/* The structure of the payload should be as follows:
		 *    struct {
		 *       opaque content[TLSPlaintext.length];
		 *       ContentType type;
		 *       uint8 zeros[length_of_padding];
		 *    } TLSInnerPlaintext;
		 *
		 * We will check whether the ContentType is indeed a
		 * handshake message.
		 *
		 * We will walk backwards in the decrypted message
		 * to scan over eventually available padding bytes.
		 */

		for (int i = ssl->in_msglen; i > 0; i--) {
			if (ssl->in_msg[i-1] != 0) {
				if (ssl->in_msg[i-1] == MBEDTLS_SSL_MSG_HANDSHAKE) {
					// everything is OK
					ssl->in_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
					// we skip the ContentType and padding from the length
					ssl->in_msglen = i - 1;
					break;
				} else if (ssl->in_msg[i - 1] == MBEDTLS_SSL_MSG_APPLICATION_DATA) {
					// We received application data
					ssl->in_msgtype = MBEDTLS_SSL_MSG_APPLICATION_DATA;
					// we skip the ContentType and padding from the length
					ssl->in_msglen = i - 1;
					break;
				}
				else if (ssl->in_msg[i - 1] == MBEDTLS_SSL_MSG_ALERT) {
					// We received an alert
					ssl->in_msgtype = MBEDTLS_SSL_MSG_ALERT;
					// we skip the ContentType and padding from the length
					ssl->in_msglen = i - 1;
					//					ssl->in_msglen = 0; 
					break;
				}
				else {
					MBEDTLS_SSL_DEBUG_MSG(1, ("unknown message"));
					return(MBEDTLS_ERR_SSL_BAD_HS_UNKNOWN_MSG);
				}

			}
		}

		if (ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE) {
			/*
#if defined(MBEDTLS_SSL_PROTO_DTLS)
			if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM)
			{
				ssl->in_hslen = ((ssl->in_msg[1] << 16) | (ssl->in_msg[2] << 8) | (ssl->in_msg[3])) + mbedtls_ssl_hs_hdr_len(ssl);
			}
			else
#endif // MBEDTLS_SSL_PROTO_DTLS 
			{
				ssl->in_hslen = ((ssl->in_msg[1] << 16) | (ssl->in_msg[2] << 8) | (ssl->in_msg[3])) + mbedtls_ssl_hs_hdr_len(ssl);
			}
			*/
			ssl->in_hslen = ((ssl->in_msg[1] << 16) | (ssl->in_msg[2] << 8) | (ssl->in_msg[3])) + mbedtls_ssl_hs_hdr_len(ssl);

			if ((ret = ssl_prepare_handshake_record(ssl)) != 0)
				return(ret);

		}
	}
	if ((ssl->in_msgtype == MBEDTLS_SSL_MSG_APPLICATION_DATA) && (ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER)) {
		/* In case of an application data payload received after the handshake is over. */
		for (int i = ssl->in_msglen; i > 0; i--) {
			if (ssl->in_msg[i - 1] != 0) {
				if (ssl->in_msg[i - 1] == MBEDTLS_SSL_MSG_APPLICATION_DATA) {
					// We received application data
					ssl->in_msgtype = MBEDTLS_SSL_MSG_APPLICATION_DATA;
					// we skip the ContentType and padding from the length
					ssl->in_msglen = i - 1;
					break;
				}
				else if (ssl->in_msg[i - 1] == MBEDTLS_SSL_MSG_ALERT) { 
					// We received an alert
					ssl->in_msgtype = MBEDTLS_SSL_MSG_ALERT;
					// we skip the ContentType and padding from the length
					ssl->in_msglen = i - 1;
//					ssl->in_msglen = 0; 
					break;
				}
				else if (ssl->in_msg[i - 1] == MBEDTLS_SSL_MSG_HANDSHAKE) {
					// We received a post-handshake message
					ssl->in_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
					// we skip the ContentType and padding from the length
					ssl->in_msglen = i - 1;
					break; 
				}
				else {
					MBEDTLS_SSL_DEBUG_MSG(1, ("unknown message"));
					return(MBEDTLS_ERR_SSL_BAD_HS_UNKNOWN_MSG);
				}

			}
		}
	}

#endif
    if( ssl->in_msgtype == MBEDTLS_SSL_MSG_ALERT )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "got an alert message, type: [%d:%d]",
                       ssl->in_msg[0], ssl->in_msg[1] ) );

        /*
         * Ignore non-fatal alerts, except close_notify and no_renegotiation
         */
        if( ssl->in_msg[0] == MBEDTLS_SSL_ALERT_LEVEL_FATAL )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "is a fatal alert message (msg %d)",
                           ssl->in_msg[1] ) );
            return( MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE );
        }

        if( ssl->in_msg[0] == MBEDTLS_SSL_ALERT_LEVEL_WARNING &&
            ssl->in_msg[1] == MBEDTLS_SSL_ALERT_MSG_CLOSE_NOTIFY )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "is a close notify message" ) );
            return( MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY );
        }

#if defined(MBEDTLS_SSL_RENEGOTIATION)
        if( ssl->in_msg[0] == MBEDTLS_SSL_ALERT_LEVEL_WARNING &&
            ssl->in_msg[1] == MBEDTLS_SSL_ALERT_MSG_NO_RENEGOTIATION )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "is a SSLv3 no_cert" ) );
            /* Will be handled when trying to parse ServerHello */
            return( 0 );
        }
#endif

#if defined(MBEDTLS_SSL_PROTO_SSL3) && defined(MBEDTLS_SSL_SRV_C)
        if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 &&
            ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER &&
            ssl->in_msg[0] == MBEDTLS_SSL_ALERT_LEVEL_WARNING &&
            ssl->in_msg[1] == MBEDTLS_SSL_ALERT_MSG_NO_CERT )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "is a SSLv3 no_cert" ) );
            /* Will be handled in mbedtls_ssl_parse_certificate() */
            return( 0 );
        }
#endif /* MBEDTLS_SSL_PROTO_SSL3 && MBEDTLS_SSL_SRV_C */

        /* Silently ignore: fetch new message */
        goto read_record_header;
    }

    MBEDTLS_SSL_DEBUG_MSG( 5, ( "<= read record" ) );

    return( 0 );
}

int mbedtls_ssl_send_fatal_handshake_failure( mbedtls_ssl_context *ssl )
{
    int ret;

    if( ( ret = mbedtls_ssl_send_alert_message( ssl,
                    MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                    MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

int mbedtls_ssl_send_alert_message( mbedtls_ssl_context *ssl,
                            unsigned char level,
                            unsigned char message )
{
    int ret;

    if( ssl == NULL || ssl->conf == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> send alert message" ) );

    ssl->out_msgtype = MBEDTLS_SSL_MSG_ALERT;
	ssl->out_msg[0] = level;
	ssl->out_msg[1] = message;

	if (ssl->transform != NULL) {
		// If we encrypt then we add the content type and optionally padding
		ssl->out_msglen = 3; // 3 includes the content type as well
		// we use no padding
		ssl->out_msg[2] = MBEDTLS_SSL_MSG_ALERT;
	} else {
		ssl->out_msglen = 2;
	}

    if( ( ret = mbedtls_ssl_write_record( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_record", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= send alert message" ) );

    return( 0 );
}

/*
 * Handshake functions
 */
#if !defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) && \
    defined(MBEDTLS_SSL_PROTO_TLS1_3)
int mbedtls_ssl_write_certificate( mbedtls_ssl_context *ssl)
{
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info = ssl->session_negotiate->ciphersuite_info;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write certificate" ) );

    if( ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK  ||
        ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate" ) );
        ssl->state++;
        return( 0 );
    }

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
}

int mbedtls_ssl_parse_certificate( mbedtls_ssl_context *ssl )
{
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info = ssl->session_negotiate->ciphersuite_info;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse certificate" ) );

    if( ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK ||
        ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK)
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip parse certificate" ) );
        ssl->state++;
        return( 0 );
    }

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
}

int mbedtls_ssl_parse_certificate_verify(mbedtls_ssl_context *ssl, int from)
{
	const mbedtls_ssl_ciphersuite_t *ciphersuite_info = ssl->session_negotiate->ciphersuite_info;

	MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse certificate verify"));

	if (ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK ||
		ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK )
	{
		MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip parse certificate verify"));
		ssl->state++;
		return(0);
	}

	MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
	return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
}
int mbedtls_ssl_write_certificate_verify(mbedtls_ssl_context *ssl, int from)
{
	const mbedtls_ssl_ciphersuite_t *ciphersuite_info = ssl->session_negotiate->ciphersuite_info;

	MBEDTLS_SSL_DEBUG_MSG(2, ("=> write certificate verify"));

	if (ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK  ||
		ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK)
	{
		MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip write certificate verify"));
		ssl->state++;
		return(0);
	}

	MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
	return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
}
#endif /* !MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED && MBEDTLS_SSL_PROTO_TLS1_3 */

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) && \
    defined(MBEDTLS_SSL_PROTO_TLS1_3)
int mbedtls_ssl_write_certificate_verify(mbedtls_ssl_context *ssl, int from)
{
	int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
	const mbedtls_ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;
	size_t n = 0, offset = 0;

	unsigned char hash[MBEDTLS_MD_MAX_SIZE];
	unsigned char *hash_start = hash;
	unsigned int hashlen;
	int have_own_cert = 1;


	MBEDTLS_SSL_DEBUG_MSG(2, ("=> write certificate verify"));

	if (ssl->session_negotiate->key_exchange != MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA)
	{
		MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip write certificate verify"));
		return(0);
	}

	if (mbedtls_ssl_own_cert(ssl) == NULL) have_own_cert = 0; 

	if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT)
	{
		if (ssl->client_auth == 0 || have_own_cert == 0 || ssl->conf->authmode == MBEDTLS_SSL_VERIFY_NONE)
		{
			MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip write certificate verify"));
			return(0);
		}
	}

	if (have_own_cert == 0 && ssl->client_auth == 1 && ssl->conf->authmode != MBEDTLS_SSL_VERIFY_NONE)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("got no certificate"));
		return(MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED);
	}

	/*
	* Check whether the signature scheme corresponds to the key we are using
	*/
	if (mbedtls_ssl_sig_from_pk(mbedtls_ssl_own_key(ssl)) != MBEDTLS_SSL_SIG_ECDSA) {
		MBEDTLS_SSL_DEBUG_MSG(1, ("Certificate Verify: Only ECDSA signature algorithm is currently supported."));
		return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
	}

	/*
	* Check whether the signature scheme corresponds to the hash algorithm of the negotiated ciphersuite
	* TBD: Double-check whether this is really a good approach.

	if ((ssl->handshake->signature_scheme == SIGNATURE_ECDSA_SECP256r1_SHA256) && (ciphersuite_info->hash != MBEDTLS_MD_SHA256)) {
		MBEDTLS_SSL_DEBUG_MSG(1, ("Certificate Verify: SIGNATURE_ECDSA_SECP256r1_SHA256 only matches with MBEDTLS_MD_SHA256."));
		return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
	}
	else if ((ssl->handshake->signature_scheme == SIGNATURE_ECDSA_SECP384r1_SHA384) && (ciphersuite_info->hash != MBEDTLS_MD_SHA384)) {
		MBEDTLS_SSL_DEBUG_MSG(1, ("Certificate Verify: SIGNATURE_ECDSA_SECP384r1_SHA384 only matches with MBEDTLS_MD_SHA384."));
		return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
	}
	else if ((ssl->handshake->signature_scheme == SIGNATURE_ECDSA_SECP521r1_SHA512) && (ciphersuite_info->hash != MBEDTLS_MD_SHA512)) {
		MBEDTLS_SSL_DEBUG_MSG(1, ("Certificate Verify: SIGNATURE_ECDSA_SECP521r1_SHA512 only matches with MBEDTLS_MD_SHA512."));
		return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
	}
	*/


	/*
	* Make an signature of the handshake digests
	*/
	ret = ssl->handshake->calc_verify(ssl, hash, from);

	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(1, "calc_verify", ret);
		return(ret);
	}

	/*
	*  struct {
	*    SignatureScheme algorithm;
	*    opaque signature<0..2^16-1>;
	*  } CertificateVerify;
	*/

	/* The algorithm used for computing the hash above must 
	 * correspond to the algorithm indicated in the signature_scheme below.
	 * 
	 * TBD: ssl->handshake->signature_scheme should already contain the correct value
	 *      based on the parsing of the ClientHello / transmission of the ServerHello 
	 *      message. 
	 */

	switch (ciphersuite_info->hash) {
	case MBEDTLS_MD_SHA256: ssl->handshake->signature_scheme = SIGNATURE_ECDSA_SECP256r1_SHA256; break;
	case MBEDTLS_MD_SHA384: ssl->handshake->signature_scheme = SIGNATURE_ECDSA_SECP384r1_SHA384;  break;
	case MBEDTLS_MD_SHA512: ssl->handshake->signature_scheme = SIGNATURE_ECDSA_SECP521r1_SHA512;  break;
	default: MBEDTLS_SSL_DEBUG_MSG(1, ("Certificate Verify: Unknown hash algorithm."));
		return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
	}

	ssl->out_msg[4] = (unsigned char)((ssl->handshake->signature_scheme >> 8) & 0xFF);
	ssl->out_msg[5] = (unsigned char)((ssl->handshake->signature_scheme) & 0xFF);

	/* Info from ssl->transform_negotiate->ciphersuite_info->mac will be used instead */
	hashlen = 0;
	offset = 2;

	if ((ret = mbedtls_pk_sign(mbedtls_ssl_own_key(ssl), ciphersuite_info->hash, hash_start, hashlen,
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

	ssl->state++;

	if ((ret = mbedtls_ssl_write_record(ssl)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_write_record", ret);
		return(ret);
	}

	MBEDTLS_SSL_DEBUG_MSG(2, ("<= write certificate verify"));

	return(ret);
}

int mbedtls_ssl_parse_certificate_verify(mbedtls_ssl_context *ssl, int from)
{
	int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
	size_t i, sig_len;
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];
	unsigned char *hash_start = hash;
	size_t hashlen;
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
	mbedtls_pk_type_t pk_alg;
#endif
	mbedtls_md_type_t md_alg;
	//const mbedtls_ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;

	MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse certificate verify"));

	if (ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK ||
		ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK ||
		ssl->session_negotiate->peer_cert == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip parse certificate verify"));
		ssl->state++;
		return(0);
	}

	/* Needs to be done before read_record() to exclude current message */
	ret = ssl->handshake->calc_verify(ssl, hash, from);

	if (ret != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "calc_verify", ret);
		return(ret);
	}

	if ((ret = mbedtls_ssl_read_record(ssl)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_read_record", ret);
		return(ret);
	}

	ssl->state++;

	if (ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE ||
		ssl->in_msg[0] != MBEDTLS_SSL_HS_CERTIFICATE_VERIFY)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate verify message"));
		return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
	}

	i = mbedtls_ssl_hs_hdr_len(ssl);

	/*
	*  struct {
	*     SignatureAndHashAlgorithm algorithm; -- TLS 1.2 only
	*     opaque signature<0..2^16-1>;
	*  } DigitallySigned;
	*/
#if defined(MBEDTLS_SSL_PROTO_SSL3) || defined(MBEDTLS_SSL_PROTO_TLS1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_1)
	if (ssl->minor_ver != MBEDTLS_SSL_MINOR_VERSION_3)
	{
		md_alg = MBEDTLS_MD_NONE;
		hashlen = 36;

		/* For ECDSA, use SHA-1, not MD-5 + SHA-1 */
		if (mbedtls_pk_can_do(&ssl->session_negotiate->peer_cert->pk,
			MBEDTLS_PK_ECDSA))
		{
			hash_start += 16;
			hashlen -= 16;
			md_alg = MBEDTLS_MD_SHA1;
		}
	}
	else
#endif /* MBEDTLS_SSL_PROTO_SSL3 || MBEDTLS_SSL_PROTO_TLS1 ||
		MBEDTLS_SSL_PROTO_TLS1_1 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && !defined(MBEDTLS_SSL_PROTO_TLS1_3)
		if (ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_3)
		{
			if (i + 2 > ssl->in_hslen)
			{
				MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate verify message"));
				return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
			}

			/*
			* Hash
			*/
			if (ssl->in_msg[i] != ssl->handshake->verify_sig_alg)
			{
				MBEDTLS_SSL_DEBUG_MSG(1, ("peer not adhering to requested sig_alg"
					" for verify message"));
				return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
			}

			md_alg = mbedtls_ssl_md_alg_from_hash(ssl->handshake->verify_sig_alg);

			/* Info from md_alg will be used instead */
			hashlen = 0;

			i++;

			/*
			* Signature
			*/
			if ((pk_alg = mbedtls_ssl_pk_alg_from_sig(ssl->in_msg[i]))
				== MBEDTLS_PK_NONE)
			{
				MBEDTLS_SSL_DEBUG_MSG(1, ("peer not adhering to requested sig_alg"
					" for verify message"));
				return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
			}

			/*
			* Check the certificate's key type matches the signature alg
			*/
			if (!mbedtls_pk_can_do(&ssl->session_negotiate->peer_cert->pk, pk_alg))
			{
				MBEDTLS_SSL_DEBUG_MSG(1, ("sig_alg doesn't match cert key"));
				return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
			}

			i++;
		}
		else
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
			if (ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_4)
			{
				if (i + 2 > ssl->in_hslen)
				{
					MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate verify message"));
					return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
				}

/*
				// TBD: a hack for the moment. 
				ssl->handshake->verify_sig_alg = MBEDTLS_SSL_HASH_SHA256;


				// Hash 
				if (ssl->in_msg[i] != ssl->handshake->verify_sig_alg)
				{
					MBEDTLS_SSL_DEBUG_MSG(1, ("peer not adhering to requested sig_alg"
						" for verify message"));
					return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
				}
*/

				// We input the signature scheme without checking against supported signature_schemes 
				md_alg = mbedtls_ssl_md_alg_from_hash(ssl->in_msg[i]);

				/* Info from md_alg will be used instead */
				hashlen = 0;

				i++;

				/*
				* Signature
				*/
				if ((pk_alg = mbedtls_ssl_pk_alg_from_sig(ssl->in_msg[i]))
					== MBEDTLS_PK_NONE)
				{
					MBEDTLS_SSL_DEBUG_MSG(1, ("peer not adhering to requested sig_alg"
						" for verify message"));
					return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
				}

				/*
				* Check the certificate's key type matches the signature alg
				*/
				if (!mbedtls_pk_can_do(&ssl->session_negotiate->peer_cert->pk, pk_alg))
				{
					MBEDTLS_SSL_DEBUG_MSG(1, ("sig_alg doesn't match cert key"));
					return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
				}

				i++;
			}

			else
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
		{
			MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
			return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
		}

	if (i + 2 > ssl->in_hslen)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate verify message"));
		return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
	}

	sig_len = (ssl->in_msg[i] << 8) | ssl->in_msg[i + 1];
	i += 2;

	if (i + sig_len != ssl->in_hslen)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate verify message"));
		return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
	}

	if ((ret = mbedtls_pk_verify(&ssl->session_negotiate->peer_cert->pk,
		md_alg, hash_start, hashlen,
		ssl->in_msg + i, sig_len)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_pk_verify", ret);
		return(ret);
	}

	MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse certificate verify"));

	return(ret);
}

int mbedtls_ssl_write_certificate( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    size_t i, n, total_len; // , hdr_len;
    const mbedtls_x509_crt *crt;
//    const mbedtls_ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;
	unsigned char *start;
	int have_own_cert=1; 

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write certificate" ) );

    if(ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK ||
		ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate" ) );
        return( 0 );
    }

	/* There may be other reasons why no certificate is sent. 
	 * Currently, we just consider the lack of a cert as the only condition.
	 */
	if (mbedtls_ssl_own_cert(ssl) == NULL) have_own_cert = 0; 

#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
		/* The client MUST send a Certificate message if and only 
		 * if the server has requested client authentication via a 
		 * CertificateRequest message. 
		 *
		 * client_auth indicates whether the server had requested 
		 * client authentication. 
		 */
        if( ssl->client_auth == 0)
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate" ) );
            return( 0 );
        }
    }
#endif /* MBEDTLS_SSL_CLI_C */
#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        if(have_own_cert == 0) {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "got no certificate to send" ) );
            return( MBEDTLS_ERR_SSL_CERTIFICATE_REQUIRED );
        }
    }
#endif /* MBEDTLS_SSL_SRV_C */

    /*
     *  Handshake Header is 4 (before adding DTLS-specific fields, which is done later)
	 *  Certificate Request Context: 1 byte
     *  Length of CertificateEntry: 3 bytes
     *     Length of cert. 1: 2 bytes
	 *     cert_data: n bytes 
	 *	   Extension: 2 bytes
	 *     Extension value: m bytes
     */
    i = 4;

	// empty certificate_request_context with length 0
	ssl->out_msg[i] = 0; 
    /* Skip length of certificate_request_context and 
	 * the length of CertificateEntry
	 */
	i += 1; 

#if defined(MBEDTLS_SSL_CLI_C)
   /* If the server requests client authentication but no suitable
	* certificate is available, the client MUST send a
	* Certificate message containing no certificates
	* (i.e., with the "certificate_list" field having length 0).
	*
	* authmode indicates whether the client configuration required authentication.
	*/
	if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT && (have_own_cert == 0 || ssl->conf->authmode == MBEDTLS_SSL_VERIFY_NONE)) {
		MBEDTLS_SSL_DEBUG_MSG(2, ("<= write empty client certificate"));
		ssl->out_msg[i] = 0;
		ssl->out_msg[i + 1] = 0;
		ssl->out_msg[i + 2] = 0;
		i += 3;

		goto empty_cert; 
	} 
#endif /* MBEDTLS_SSL_CLI_C */

	start = &ssl->out_msg[i];
	crt = mbedtls_ssl_own_cert(ssl);
	MBEDTLS_SSL_DEBUG_CRT(3, "own certificate", mbedtls_ssl_own_cert(ssl));

	i += 3;

	while( crt != NULL )
    {
        n = crt->raw.len;
        if( n > MBEDTLS_SSL_MAX_CONTENT_LEN - 3 - i )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "certificate too large, %d > %d",
                           i + 3 + n, MBEDTLS_SSL_MAX_CONTENT_LEN ) );
            return( MBEDTLS_ERR_SSL_CERTIFICATE_TOO_LARGE );
        }

        ssl->out_msg[i    ] = (unsigned char)( n >> 16 );
        ssl->out_msg[i + 1] = (unsigned char)( n >>  8 );
        ssl->out_msg[i + 2] = (unsigned char)( n       );

        i += 3; memcpy( ssl->out_msg + i, crt->raw.p, n );
        i += n; crt = crt->next;

		/* Currently, we don't have any certificate extensions defined. 
		 * Hence, we are sending an empty extension with length zero.
		 */
		ssl->out_msg[i] = 0;
		ssl->out_msg[i+1] = 0;
		i += 2; 
    }
	total_len = &ssl->out_msg[i] - start - 3; 
    *start++  = (unsigned char)( (total_len) >> 16 );
    *start++  = (unsigned char)( (total_len) >>  8 );
    *start++  = (unsigned char)( (total_len)       );

#if defined(MBEDTLS_SSL_CLI_C)
empty_cert: 
#endif /* MBEDTLS_SSL_CLI_C */
    ssl->out_msglen  = i;
    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = MBEDTLS_SSL_HS_CERTIFICATE;

    if( ( ret = mbedtls_ssl_write_record( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_record", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write certificate" ) );

    return( ret );
}

int mbedtls_ssl_parse_certificate( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    size_t i, n, certificate_request_context_len;
//    const mbedtls_ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;
    int authmode = ssl->conf->authmode;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse certificate" ) );

    if(ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK ||
		ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK)
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip parse certificate" ) );
        return( 0 );
    }

#if defined(MBEDTLS_SSL_SRV_C)
   
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    if( ssl->handshake->sni_authmode != MBEDTLS_SSL_VERIFY_UNSET )
        authmode = ssl->handshake->sni_authmode;
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER &&
        authmode == MBEDTLS_SSL_VERIFY_NONE )
    {
        ssl->session_negotiate->verify_result = MBEDTLS_X509_BADCERT_SKIP_VERIFY;
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip parse certificate" ) );
        return( 0 );
    }
#endif /* MBEDTLS_SSL_SRV_C */

	// If we have already read the record previously then we should not do it again. 
	if (ssl->record_read == 0)
	{
		if ((ret = mbedtls_ssl_read_record(ssl)) != 0)
		{
			MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_read_record", ret);
			return(ret);
		}
		ssl->record_read = 1;
	}

#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint  == MBEDTLS_SSL_IS_SERVER)
    {
        if( ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE &&
            ssl->in_msg[0]  == MBEDTLS_SSL_HS_CERTIFICATE)
        {
			// read certificate request context length
			certificate_request_context_len = (size_t) *(ssl->in_msg + mbedtls_ssl_hs_hdr_len(ssl));
	
			// verify message length
			if (ssl->in_hslen < 3 + certificate_request_context_len + 1 + mbedtls_ssl_hs_hdr_len(ssl)) {
				MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate message"));
				return(MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE);
			} 

			// check whether we got an empty certificate message
			if (memcmp(ssl->in_msg + 1 + certificate_request_context_len + mbedtls_ssl_hs_hdr_len(ssl), "\0\0\0", 3) == 0) {
				MBEDTLS_SSL_DEBUG_MSG(1, ("client has no certificate"));

				ssl->session_negotiate->verify_result = MBEDTLS_X509_BADCERT_MISSING;
				if (authmode == MBEDTLS_SSL_VERIFY_OPTIONAL)
					return(0);
				else
					return(MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE);
			}
        }
    }
#endif /* MBEDTLS_SSL_SRV_C */

    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    if( ssl->in_msg[0] != MBEDTLS_SSL_HS_CERTIFICATE ||
        ssl->in_hslen < mbedtls_ssl_hs_hdr_len( ssl ) + 3 + 3 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
    }

    i = mbedtls_ssl_hs_hdr_len( ssl );

	// length information of certificate_request_context 
	certificate_request_context_len = ssl->in_msg[i+1];

	// skip certificate_request_context
	i += certificate_request_context_len+1;

    n = ( ssl->in_msg[i+1] << 8 ) | ssl->in_msg[i+2];

    if( ssl->in_msg[i] != 0 ||
        ssl->in_hslen != (n + 3 + certificate_request_context_len + 1 + mbedtls_ssl_hs_hdr_len( ssl )) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
    }

    /* In case we tried to reuse a session but it failed */
    if( ssl->session_negotiate->peer_cert != NULL )
    {
        mbedtls_x509_crt_free( ssl->session_negotiate->peer_cert );
        mbedtls_free( ssl->session_negotiate->peer_cert );
    }

    if( ( ssl->session_negotiate->peer_cert = mbedtls_calloc( 1,
                    sizeof( mbedtls_x509_crt ) ) ) == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "alloc(%d bytes) failed",
                       sizeof( mbedtls_x509_crt ) ) );
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    mbedtls_x509_crt_init( ssl->session_negotiate->peer_cert );

    i += 3;

    while( i < ssl->in_hslen )
    {
        if( ssl->in_msg[i] != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
            return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
        }

        n = ( (unsigned int) ssl->in_msg[i + 1] << 8 )
            | (unsigned int) ssl->in_msg[i + 2];
        i += 3;

        if( n < 128 || i + n > ssl->in_hslen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
            return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
        }

        ret = mbedtls_x509_crt_parse_der( ssl->session_negotiate->peer_cert,
                                  ssl->in_msg + i, n );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, " mbedtls_x509_crt_parse_der", ret );
            return( ret );
        }

        i += n;

		// length information of certificate extensions 
		n = (ssl->in_msg[i] << 8) | ssl->in_msg[i + 1];

		// we ignore the certificate extension right now		
		i += 2+n; 
    }

    MBEDTLS_SSL_DEBUG_CRT( 3, "peer certificate", ssl->session_negotiate->peer_cert );

    /*
     * On client, make sure the server cert doesn't change during renego to
     * avoid "triple handshake" attack: https://secure-resumption.com/
     */
#if defined(MBEDTLS_SSL_RENEGOTIATION) && defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT &&
        ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS )
    {
        if( ssl->session->peer_cert == NULL )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "new server cert during renegotiation" ) );
            return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
        }

        if( ssl->session->peer_cert->raw.len !=
            ssl->session_negotiate->peer_cert->raw.len ||
            memcmp( ssl->session->peer_cert->raw.p,
                    ssl->session_negotiate->peer_cert->raw.p,
                    ssl->session->peer_cert->raw.len ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "server cert changed during renegotiation" ) );
            return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
        }
    }
#endif /* MBEDTLS_SSL_RENEGOTIATION && MBEDTLS_SSL_CLI_C */

    if( authmode != MBEDTLS_SSL_VERIFY_NONE )
    {
        mbedtls_x509_crt *ca_chain;
        mbedtls_x509_crl *ca_crl;

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
        if( ssl->handshake->sni_ca_chain != NULL )
        {
            ca_chain = ssl->handshake->sni_ca_chain;
            ca_crl   = ssl->handshake->sni_ca_crl;
        }
        else
#endif
        {
            ca_chain = ssl->conf->ca_chain;
            ca_crl   = ssl->conf->ca_crl;
        }

        if( ca_chain == NULL )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "got no CA chain" ) );
            return( MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED );
        }

        /*
         * Main check: verify certificate
         */
        ret = mbedtls_x509_crt_verify_with_profile(
                                ssl->session_negotiate->peer_cert,
                                ca_chain, ca_crl,
                                ssl->conf->cert_profile,
                                ssl->hostname,
                               &ssl->session_negotiate->verify_result,
                                ssl->conf->f_vrfy, ssl->conf->p_vrfy );

        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "x509_verify_cert", ret );
        }

        /*
         * Secondary checks: always done, but change 'ret' only if it was 0
         */

#if defined(MBEDTLS_ECP_C)
        {
            const mbedtls_pk_context *pk = &ssl->session_negotiate->peer_cert->pk;

            /* If certificate uses an EC key, make sure the curve is OK */
            if( mbedtls_pk_can_do( pk, MBEDTLS_PK_ECKEY ) &&
                mbedtls_ssl_check_curve( ssl, mbedtls_pk_ec( *pk )->grp.id ) != 0 )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate (EC key curve)" ) );
                if( ret == 0 )
                    ret = MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE;
            }
        }
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
		if (mbedtls_ssl_check_cert_usage(ssl->session_negotiate->peer_cert,
			ssl->session_negotiate->key_exchange,
			!ssl->conf->endpoint,
			&ssl->session_negotiate->verify_result ) != 0 )
#else 
        if( mbedtls_ssl_check_cert_usage( ssl->session_negotiate->peer_cert,
                                  ciphersuite_info,
                                  ! ssl->conf->endpoint,
                                 &ssl->session_negotiate->verify_result ) != 0 )
#endif

        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate (usage extensions)" ) );
            if( ret == 0 )
                ret = MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE;
        }

        if( authmode == MBEDTLS_SSL_VERIFY_OPTIONAL )
            ret = 0;
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse certificate" ) );

    return( ret );
}
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED && MBEDTLS_SSL_PROTO_TLS1_3 */ 

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

/* Generate application traffic keys since any records following a 1-RTT Finished message
 * MUST be encrypted under the application traffic key.
 */
int mbedtls_ssl_generate_application_traffic_keys(mbedtls_ssl_context *ssl) {
	int ret;
	const mbedtls_md_info_t *md_info;
	const mbedtls_ssl_ciphersuite_t *suite_info;
	const mbedtls_cipher_info_t *cipher_info;
	mbedtls_ssl_transform *transform = ssl->transform_negotiate;
	KeySet *traffic_keys = &ssl->transform_negotiate->traffic_keys;

	unsigned char padbuf[MBEDTLS_MD_MAX_SIZE];

#if defined(MBEDTLS_SHA256_C) 
	mbedtls_sha256_context sha256;
#endif

#if defined(MBEDTLS_SHA512_C)
	mbedtls_sha512_context sha512;
#endif

	MBEDTLS_SSL_DEBUG_MSG(2, ("=> derive application traffic keys"));

	cipher_info = mbedtls_cipher_info_from_type(transform->ciphersuite_info->cipher);
	if (cipher_info == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("cipher info for %d not found",
			transform->ciphersuite_info->cipher));
		return(MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
	}

	md_info = mbedtls_md_info_from_type(transform->ciphersuite_info->hash);
	if (md_info == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_md info for %d not found",
			transform->ciphersuite_info->hash));
		return(MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
	}

	suite_info = mbedtls_ssl_ciphersuite_from_id(ssl->session_negotiate->ciphersuite);
	if (suite_info == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_ssl_ciphersuite_from_id in mbedtls_ssl_derive_traffic_keys failed"));
		return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);
	}

	/*
	* Determine the appropriate key, IV and MAC length.
	*/

	/* Settings for GCM, CCM, and CCM_8 */
	transform->maclen = 0;
	transform->fixed_ivlen = 4;
	transform->ivlen = cipher_info->iv_size;
	transform->keylen = cipher_info->key_bitlen / 8;

	/* Minimum length for an encrypted handshake message is 
	 *  - Handshake header 
	 *  - 1 byte for handshake type appended to the end of the message 
	 *  - Authentication tag (which depends on the mode of operation)
	 */
	if (transform->ciphersuite_info->cipher == MBEDTLS_CIPHER_AES_128_CCM_8) transform->minlen = 8; 
	else transform->minlen = 16; 

	transform->minlen += mbedtls_ssl_hs_hdr_len(ssl);

	transform->minlen += 1; 

	if (mbedtls_hash_size_for_ciphersuite(suite_info) == 32) {
#if defined(MBEDTLS_SHA256_C)
		mbedtls_sha256_init(&sha256);
		mbedtls_sha256_clone(&sha256, &ssl->handshake->fin_sha256);
		mbedtls_sha256_finish(&sha256, padbuf);
#else 
		MBEDTLS_SSL_DEBUG_MSG(1, ("MBEDTLS_SHA256_C not set but ciphersuite with SHA256 negotiated"));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
#endif 
	}

	if (mbedtls_hash_size_for_ciphersuite(suite_info) == 48) {
#if defined(MBEDTLS_SHA512_C)
		mbedtls_sha512_init(&sha512);
		mbedtls_sha512_starts(&sha512, 1 /* = use SHA384 */);
		mbedtls_sha512_clone(&sha512, &ssl->handshake->fin_sha512);
		mbedtls_sha512_finish(&sha512, padbuf);
#else 
		MBEDTLS_SSL_DEBUG_MSG(1, ("MBEDTLS_SHA512_C not set but ciphersuite with SHA384 negotiated"));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
#endif
	}

	/* Generate client_application_traffic_secret_0
	 * 
	 * Master Secret
	 * |
	 * +-----> Derive-Secret(., "c ap traffic",
	 * |                     ClientHello...server Finished)
	 * |                     = client_application_traffic_secret_0
	 */ 

	ret = Derive_Secret(mbedtls_md_get_type(md_info),
		ssl->handshake->master_secret, mbedtls_hash_size_for_ciphersuite(suite_info),
		(const unsigned char*)"c ap traffic", strlen("c ap traffic"),
		padbuf, mbedtls_hash_size_for_ciphersuite(suite_info),
		ssl->handshake->client_traffic_secret, mbedtls_hash_size_for_ciphersuite(suite_info));

	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(1, "Derive_Secret() with client_traffic_secret_0: Error", ret);
		return ret;
	}

	/* Generate server_application_traffic_secret_0
	*
	* Master Secret
	* |
	* +---------> Derive-Secret(., "s ap traffic",
	* |                         ClientHello...Server Finished)
	* |                         = server_application_traffic_secret_0
	*/

	ret = Derive_Secret(mbedtls_md_get_type(md_info),
		ssl->handshake->master_secret, mbedtls_hash_size_for_ciphersuite(suite_info),
		(const unsigned char*)"s ap traffic", strlen("s ap traffic"),
		padbuf, mbedtls_hash_size_for_ciphersuite(suite_info),
		ssl->handshake->server_traffic_secret, mbedtls_hash_size_for_ciphersuite(suite_info));

	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(1, "Derive_Secret() with server_traffic_secret_0: Error", ret);
		return ret;
	}

	/* Generate application traffic keys since any records following a 1-RTT Finished message
	* MUST be encrypted under the application traffic key.
	*/

	MBEDTLS_SSL_DEBUG_MSG(3, ("-->>Calling makeTrafficKeys() with the following parameters:"));
	MBEDTLS_SSL_DEBUG_MSG(3, ("-- Hash Algorithm: %s", mbedtls_md_get_name(md_info)));
	MBEDTLS_SSL_DEBUG_MSG(3, ("-- Handshake Traffic Secret Length: %d bytes", mbedtls_hash_size_for_ciphersuite(suite_info)));
	MBEDTLS_SSL_DEBUG_MSG(3, ("-- Phase: 'application data key expansion'"));
	MBEDTLS_SSL_DEBUG_MSG(3, ("-- Phase Length: %d bytes", strlen("handshake key expansion")));
	MBEDTLS_SSL_DEBUG_MSG(3, ("-- Key Length: %d bytes", transform->keylen));
	MBEDTLS_SSL_DEBUG_MSG(3, ("-- IV Length: %d bytes", transform->ivlen));

	if ((ret = makeTrafficKeys(mbedtls_md_get_type(md_info), 
		ssl->handshake->client_traffic_secret,
		ssl->handshake->server_traffic_secret,
		mbedtls_hash_size_for_ciphersuite(suite_info), transform->keylen, transform->ivlen, traffic_keys)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "makeTrafficKeys failed", ret);
		return(ret);
	}

	MBEDTLS_SSL_DEBUG_BUF(3, "Record Type = Application Data, clientWriteKey:", traffic_keys->clientWriteKey, transform->keylen);
	MBEDTLS_SSL_DEBUG_BUF(3, "Record Type = Application Data, serverWriteKey:", traffic_keys->serverWriteKey, transform->keylen);
	MBEDTLS_SSL_DEBUG_BUF(3, "Record Type = Application Data, clientWriteIV:", traffic_keys->clientWriteIV, transform->ivlen);
	MBEDTLS_SSL_DEBUG_BUF(3, "Record Type = Application Data, serverWriteIV:", traffic_keys->serverWriteIV, transform->ivlen);

	MBEDTLS_SSL_DEBUG_MSG(2, ("<= derive application traffic keys"));

	return(0);
}


/* mbedtls_set_traffic_key() activates keys and IVs for 
 * the negotiated ciphersuite for use with encryption/decryption. 
 * The sequence numbers are also set to zero.
 */
int mbedtls_set_traffic_key(mbedtls_ssl_context *ssl) {
	const mbedtls_cipher_info_t *cipher_info;
	int ret; 
	unsigned char *key1, *key2;
	mbedtls_ssl_transform *transform = ssl->transform_negotiate;
	KeySet *traffic_keys = &ssl->transform_negotiate->traffic_keys; 

	cipher_info = mbedtls_cipher_info_from_type(transform->ciphersuite_info->cipher);
	if (cipher_info == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("cipher info for %d not found",
			transform->ciphersuite_info->cipher));
		return(MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
	}

	if ((ret = mbedtls_cipher_setup(&transform->cipher_ctx_enc,
		cipher_info)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_setup", ret);
		return(ret);
	}

	if ((ret = mbedtls_cipher_setup(&transform->cipher_ctx_dec,
		cipher_info)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_setup", ret);
		return(ret);
	}

#if defined(MBEDTLS_SSL_SRV_C)
	if (ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER)
	{

		key1 = traffic_keys->serverWriteKey; // encryption key for the server
		key2 = traffic_keys->clientWriteKey; // decryption key for the server

		transform->iv_enc = traffic_keys->serverWriteIV;
		transform->iv_dec = traffic_keys->clientWriteIV;
	}
#endif
#if defined(MBEDTLS_SSL_CLI_C)
	if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT)
	{
		key1 = traffic_keys->clientWriteKey; // encryption key for the client
		key2 = traffic_keys->serverWriteKey; // decryption key for the client

		transform->iv_enc = traffic_keys->clientWriteIV;
		transform->iv_dec = traffic_keys->serverWriteIV;
	}
#endif

	if ((ret = mbedtls_cipher_setkey(&transform->cipher_ctx_enc, key1,
		cipher_info->key_bitlen,
		MBEDTLS_ENCRYPT)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_setkey", ret);
		return(ret);
	}

	if ((ret = mbedtls_cipher_setkey(&transform->cipher_ctx_dec, key2,
		cipher_info->key_bitlen,
		MBEDTLS_DECRYPT)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_setkey", ret);
		return(ret);
	}

	memset(ssl->transform_in->sequence_number_dec, 0x0, 12);
	memset(ssl->transform_out->sequence_number_enc, 0x0, 12);
	return (0);
}

#if defined(MBEDTLS_ZERO_RTT)
/* Early Data Key Derivation for TLS 1.3
*
* Three tasks:
*   - Switch transform
*   - Generate client_early_traffic_secret
*   - Generate traffic key material
*/
int mbedtls_ssl_early_data_key_derivation(mbedtls_ssl_context *ssl)
{
	int ret;
	int hash_length; 
	const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
	const mbedtls_cipher_info_t *cipher_info;

/*	unsigned char *psk;
	size_t psk_len;
*/	const mbedtls_md_info_t *md;
	KeySet traffic_keys;
	unsigned char *key1, *key2;
	unsigned char padbuf[MBEDTLS_MD_MAX_SIZE];
	mbedtls_ssl_transform *transform;

#if defined(MBEDTLS_SHA256_C)
	mbedtls_sha256_context sha256;
#endif

#if defined(MBEDTLS_SHA512_C)
	mbedtls_sha512_context sha512;
#endif


	MBEDTLS_SSL_DEBUG_MSG(2, ("=> mbedtls_ssl_early_data_key_derivation"));

	// sanity checks 
	if (ssl->transform_negotiate == NULL) {
		MBEDTLS_SSL_DEBUG_MSG(1, ("transform_negotiate == NULL, mbedtls_ssl_early_data_key_derivation failed"));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
	}

	if (ssl->transform_negotiate->ciphersuite_info == NULL) {
		MBEDTLS_SSL_DEBUG_MSG(1, ("transform_negotiate->ciphersuite_info == NULL, mbedtls_ssl_early_data_key_derivation failed"));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
	}

	if (ssl->session_negotiate == NULL) {
		MBEDTLS_SSL_DEBUG_MSG(1, ("session_negotiate == NULL, mbedtls_ssl_early_data_key_derivation failed"));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
	}

#if defined(MBEDTLS_SSL_SRV_C)
	if (ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER)
	{
		MBEDTLS_SSL_DEBUG_MSG(3, ("switching to new transform spec for inbound data"));
		ssl->transform_in = ssl->transform_negotiate;
		ssl->session_in = ssl->session_negotiate;
		transform = ssl->transform_negotiate;
	}
#endif
#if defined(MBEDTLS_SSL_CLI_C)
	if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT)
	{
		MBEDTLS_SSL_DEBUG_MSG(3, ("switching to new transform spec for outbound data"));
		ssl->transform_out = ssl->transform_negotiate;
		ssl->session_out = ssl->session_negotiate;
		transform = ssl->transform_negotiate;
	}
#endif

	ciphersuite_info = transform->ciphersuite_info;
	if (ciphersuite_info == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("ciphersuite_info == NULL"));
		return(MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
	}

	cipher_info = mbedtls_cipher_info_from_type(ciphersuite_info->cipher);
	if (cipher_info == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("cipher info for %d not found",
			ciphersuite_info->cipher));
		return(MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
	}

	md = mbedtls_md_info_from_type(transform->ciphersuite_info->hash);
	if (md == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("md == NULL, mbedtls_ssl_early_data_key_derivation failed"));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
	}

	hash_length = mbedtls_hash_size_for_ciphersuite(ciphersuite_info);

	if (hash_length == -1) {
		MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_hash_size_for_ciphersuite == -1, mbedtls_ssl_early_data_key_derivation failed"));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
	}

#if defined(MBEDTLS_SSL_SRV_C)
	if (ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER)
	{
		memset(transform->sequence_number_dec, 0x0, 12); /* Set sequence number to zero */
	}
#endif
#if defined(MBEDTLS_SSL_CLI_C)
	if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT)
	{
		memset(transform->sequence_number_enc, 0x0, 12); /* Set sequence number to zero */
	}
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)
	if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM)
	{
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
		ssl_dtls_replay_reset(ssl);
#endif

		/* Increment epoch */
		if (++ssl->in_epoch == 0)
		{
			MBEDTLS_SSL_DEBUG_MSG(1, ("DTLS epoch would wrap"));
			return(MBEDTLS_ERR_SSL_COUNTER_WRAPPING);
		}
	}
	else
#endif /* MBEDTLS_SSL_PROTO_DTLS */

		// memset(ssl->in_ctr, 0, 8);

		if (ciphersuite_info->hash == MBEDTLS_MD_SHA256) {
#if defined(MBEDTLS_SHA256_C) 
			mbedtls_sha256_init(&sha256);
			mbedtls_sha256_starts(&sha256, 0 /* = use SHA256 */);
			mbedtls_sha256_clone(&sha256, &ssl->handshake->fin_sha256);
			MBEDTLS_SSL_DEBUG_BUF(5, "finished sha256 state", (unsigned char *)sha256.state, sizeof(sha256.state));
			mbedtls_sha256_finish(&sha256, padbuf);
			MBEDTLS_SSL_DEBUG_BUF(5, "handshake hash", padbuf, 32);
#else 
			MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_ssl_derive_master_secret: Unknow hash function."));
			return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
#endif 
		}
		else if (ciphersuite_info->hash == MBEDTLS_MD_SHA384) {
#if defined(MBEDTLS_SHA512_C)
			mbedtls_sha512_init(&sha512);
			mbedtls_sha512_starts(&sha512, 1 /* = use SHA384 */);
			mbedtls_sha512_clone(&sha512, &ssl->handshake->fin_sha512);
			MBEDTLS_SSL_DEBUG_BUF(4, "finished sha384 state", (unsigned char *)sha512.state, 48);
			mbedtls_sha512_finish(&sha512, padbuf);
			MBEDTLS_SSL_DEBUG_BUF(5, "handshake hash", padbuf, 48);
#else 
			MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_ssl_derive_master_secret: Unknow hash function."));
			return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
#endif 
		}
		else if (ciphersuite_info->hash == MBEDTLS_MD_SHA512) {
#if defined(MBEDTLS_SHA512_C)
			mbedtls_sha512_init(&sha512);
			mbedtls_sha512_starts(&sha512, 0 /* = use SHA512 */);
			mbedtls_sha512_clone(&sha512, &ssl->handshake->fin_sha512);
			MBEDTLS_SSL_DEBUG_BUF(4, "finished sha512 state", (unsigned char *)sha512.state, 64);
			mbedtls_sha512_finish(&sha512, padbuf);
			MBEDTLS_SSL_DEBUG_BUF(5, "handshake hash for psk binder", padbuf, 64);
		}
		else {
#else 
			MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_ssl_derive_master_secret: Unknow hash function."));
			return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
#endif 
		}

		/* Create client_early_traffic_secret */
		ret = Derive_Secret(mbedtls_md_get_type(md),
			ssl->handshake->early_secret, hash_length,
			(const unsigned char*)"c e traffic", strlen("c e traffic"),
			padbuf, hash_length, ssl->handshake->client_early_traffic_secret, hash_length);

	MBEDTLS_SSL_DEBUG_BUF(5, "early_secret", ssl->handshake->early_secret, hash_length);
	MBEDTLS_SSL_DEBUG_BUF(5, "client_early_traffic_secret", ssl->handshake->client_early_traffic_secret, hash_length);

	MBEDTLS_SSL_DEBUG_MSG(5, ("Derive_Secret with 'c e traffic'"));

	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(1, "Derive_Secret", ret);
		return(ret);
	}

	/* Creating the Traffic Keys */

	/* Settings for GCM, CCM, and CCM_8 */
	transform->maclen = 0;
	transform->fixed_ivlen = 4;
	transform->ivlen = cipher_info->iv_size;
	transform->keylen = cipher_info->key_bitlen / 8;

	/* Minimum length for an encrypted handshake message is
	*  - Handshake header
	*  - 1 byte for handshake type appended to the end of the message
	*  - Authentication tag (which depends on the mode of operation)
	*/
	if (transform->ciphersuite_info->cipher == MBEDTLS_CIPHER_AES_128_CCM_8) transform->minlen = 8;
	else transform->minlen = 16;

	transform->minlen += mbedtls_ssl_hs_hdr_len(ssl);

	transform->minlen += 1;

	MBEDTLS_SSL_DEBUG_MSG(3, ("-->>Calling makeTrafficKeys() with the following parameters:"));
	MBEDTLS_SSL_DEBUG_MSG(3, ("-- Hash Algorithm: %s", mbedtls_md_get_name(md)));
	MBEDTLS_SSL_DEBUG_MSG(3, ("-- Early Traffic Secret Length: %d bytes", mbedtls_hash_size_for_ciphersuite(ciphersuite_info)));
	MBEDTLS_SSL_DEBUG_MSG(3, ("-- Key Length: %d bytes", transform->keylen));
	MBEDTLS_SSL_DEBUG_MSG(3, ("-- IV Length: %d bytes", transform->ivlen));

	if ((ret = makeTrafficKeys(mbedtls_md_get_type(md),
		ssl->handshake->client_early_traffic_secret,
		ssl->handshake->client_early_traffic_secret,
		mbedtls_hash_size_for_ciphersuite(ciphersuite_info),
		transform->keylen, transform->ivlen, &traffic_keys)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "makeTrafficKeys failed", ret);
		return(ret);
	}

	MBEDTLS_SSL_DEBUG_BUF(3, "[TLS 1.3, ] + handshake key expansion, clientWriteKey:", traffic_keys.clientWriteKey, transform->keylen);
	MBEDTLS_SSL_DEBUG_BUF(3, "[TLS 1.3, ] + handshake key expansion, serverWriteKey:", traffic_keys.serverWriteKey, transform->keylen);
	MBEDTLS_SSL_DEBUG_BUF(3, "[TLS 1.3, ] + handshake key expansion, clientWriteIV:", traffic_keys.clientWriteIV, transform->ivlen);
	MBEDTLS_SSL_DEBUG_BUF(3, "[TLS 1.3, ] + handshake key expansion, serverWriteIV:", traffic_keys.serverWriteIV, transform->ivlen);

	if ((ret = mbedtls_cipher_setup(&transform->cipher_ctx_enc,
		cipher_info)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_setup", ret);
		return(ret);
	}

	if ((ret = mbedtls_cipher_setup(&transform->cipher_ctx_dec,
		cipher_info)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_setup", ret);
		return(ret);
	}

#if defined(MBEDTLS_SSL_SRV_C)
	if (ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER)
	{

		key1 = traffic_keys.serverWriteKey; // encryption key for the server
		key2 = traffic_keys.clientWriteKey; // decryption key for the server

		transform->iv_enc = traffic_keys.serverWriteIV;
		transform->iv_dec = traffic_keys.clientWriteIV;
	}
#endif
#if defined(MBEDTLS_SSL_CLI_C)
	if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT)
	{
		key1 = traffic_keys.clientWriteKey; // encryption key for the client
		key2 = traffic_keys.serverWriteKey; // decryption key for the client

		transform->iv_enc = traffic_keys.clientWriteIV;
		transform->iv_dec = traffic_keys.serverWriteIV;
	}
#endif

	if ((ret = mbedtls_cipher_setkey(&transform->cipher_ctx_enc, key1,
		cipher_info->key_bitlen,
		MBEDTLS_ENCRYPT)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_setkey", ret);
		return(ret);
	}

	if ((ret = mbedtls_cipher_setkey(&transform->cipher_ctx_dec, key2,
		cipher_info->key_bitlen,
		MBEDTLS_DECRYPT)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_setkey", ret);
		return(ret);
	}

	/*
	* Set the in_msg pointer to the correct location based on IV length
	* For TLS 1.3 the record layer header has changed and hence we need to accomodate for it.
	*/
#if defined(MBEDTLS_SSL_SRV_C)
	if (ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER)
	{
		ssl->in_msg = ssl->in_iv;
	}
#endif
#if defined(MBEDTLS_SSL_CLI_C)
	if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT)
	{
		ssl->out_msg = ssl->out_iv;
	}
#endif

#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
	if (mbedtls_ssl_hw_record_activate != NULL)
	{
		if ((ret = mbedtls_ssl_hw_record_activate(ssl, MBEDTLS_SSL_CHANNEL_INBOUND)) != 0)
		{
			MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_hw_record_activate", ret);
			return(MBEDTLS_ERR_SSL_HW_ACCEL_FAILED);
		}
	}
#endif

	MBEDTLS_SSL_DEBUG_MSG(2, ("<= mbedtls_ssl_early_data_key_derivation"));

	return(0);
}
#endif /* MBEDTLS_ZERO_RTT */

/* Key Derivation for TLS 1.3 
 * 
 * Three tasks: 
 *   - Switch transform for inbound data 
 *   - Generate master key
 *   - Generate handshake traffic keys
 */
int mbedtls_ssl_key_derivation(mbedtls_ssl_context *ssl)
{
	int ret;
//	const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
	
//	ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;

	MBEDTLS_SSL_DEBUG_MSG(2, ("=> mbedtls_ssl_key_derivation"));

	MBEDTLS_SSL_DEBUG_MSG(3, ("switching to new transform spec for inbound data"));
	ssl->transform_in = ssl->transform_negotiate;
	ssl->session_in = ssl->session_negotiate;
	memset(ssl->transform_in->sequence_number_dec, 0x0, 12); /* Set sequence number to zero */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
	if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM)
	{
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
		ssl_dtls_replay_reset(ssl);
#endif

		/* Increment epoch */
		if (++ssl->in_epoch == 0)
		{
			MBEDTLS_SSL_DEBUG_MSG(1, ("DTLS epoch would wrap"));
			return(MBEDTLS_ERR_SSL_COUNTER_WRAPPING);
		}
	}
	else
#endif /* MBEDTLS_SSL_PROTO_DTLS */

	memset(ssl->in_ctr, 0, 8);

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)


	/* Creating the Master Secret (TLS 1.3) */
	if ((ret = mbedtls_ssl_derive_master_secret(ssl)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_derive_master_secret", ret);
		return(ret);
	}

	/* Creating the Traffic Keys (TLS 1.3) */

	if ((ret = mbedtls_ssl_derive_traffic_keys(ssl)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_derive_traffic_keys", ret);
		return(ret);
	}
#else 
	if ((ret = mbedtls_ssl_psk_derive_premaster(ssl,
		ssl->transform_negotiate->key_exchange)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_psk_derive_premaster", ret);
		return(ret);
	}

    /* TLS Key Derivation Procedure is executed here. */

	if ((ret = mbedtls_ssl_derive_keys(ssl)) != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_derive_keys", ret);
		return(ret);
	}
#endif
	/*
	* Set the in_msg pointer to the correct location based on IV length
	* For TLS 1.3 the record layer header has changed and hence we need to accomodate for it. 
	*/
	if ((ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_2) || (ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_3))
	{
		ssl->in_msg = ssl->in_iv + ssl->transform_negotiate->ivlen -
			ssl->transform_negotiate->fixed_ivlen;
	}
	else if (ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_4) {
		ssl->in_msg = ssl->in_iv;
	}
	else
		ssl->in_msg = ssl->in_iv;

#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
	if (mbedtls_ssl_hw_record_activate != NULL)
	{
		if ((ret = mbedtls_ssl_hw_record_activate(ssl, MBEDTLS_SSL_CHANNEL_INBOUND)) != 0)
		{
			MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_hw_record_activate", ret);
			return(MBEDTLS_ERR_SSL_HW_ACCEL_FAILED);
		}
	}
#endif

	MBEDTLS_SSL_DEBUG_MSG(2, ("<= mbedtls_ssl_key_derivation"));

	return(0);
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */



void mbedtls_ssl_optimize_checksum( mbedtls_ssl_context *ssl,
                            const mbedtls_ssl_ciphersuite_t *ciphersuite_info )
{
    ((void) ciphersuite_info);

#if defined(MBEDTLS_SSL_PROTO_SSL3) || defined(MBEDTLS_SSL_PROTO_TLS1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_1)
    if( ssl->minor_ver < MBEDTLS_SSL_MINOR_VERSION_3 )
        ssl->handshake->update_checksum = ssl_update_checksum_md5sha1;
    else
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_2) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if defined(MBEDTLS_SHA512_C)
    if( ciphersuite_info->hash == MBEDTLS_MD_SHA384 )
        ssl->handshake->update_checksum = ssl_update_checksum_sha384;
    else
#endif
#if defined(MBEDTLS_SHA256_C)
    if( ciphersuite_info->hash == MBEDTLS_MD_SHA256 )
        ssl->handshake->update_checksum = ssl_update_checksum_sha256;
    else
#endif
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 || defined(MBEDTLS_SSL_PROTO_TLS1_3)*/
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return;
    }
}

void mbedtls_ssl_reset_checksum( mbedtls_ssl_context *ssl )
{
#if defined(MBEDTLS_SSL_PROTO_SSL3) || defined(MBEDTLS_SSL_PROTO_TLS1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_1)
     mbedtls_md5_starts( &ssl->handshake->fin_md5  );
    mbedtls_sha1_starts( &ssl->handshake->fin_sha1 );
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_2) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if defined(MBEDTLS_SHA256_C)
    mbedtls_sha256_starts( &ssl->handshake->fin_sha256, 0 /* 0 for SHA-256 */ );
	MBEDTLS_SSL_DEBUG_MSG(4, ("mbedtls_ssl_reset_checksum"));
#endif
#if defined(MBEDTLS_SHA512_C)
    mbedtls_sha512_starts( &ssl->handshake->fin_sha512, 1 /* 1 for SHA-384 */);
#endif
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 || defined(MBEDTLS_SSL_PROTO_TLS1_3)*/
}

static void ssl_update_checksum_start( mbedtls_ssl_context *ssl,
                                       const unsigned char *buf, size_t len )
{

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if defined(MBEDTLS_SHA256_C)
#if defined(MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES)
    mbedtls_sha256_context sha256_debug;
#endif // MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES
#endif // MBEDTLS_SHA256_C 

#if defined(MBEDTLS_SHA512_C)
#if defined(MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES)
    mbedtls_sha512_context sha512_debug;
#endif // MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES
#endif // MBEDTLS_SHA512_C
#endif // MBEDTLS_SSL_PROTO_TLS1_3

#if defined(MBEDTLS_SSL_PROTO_SSL3) || defined(MBEDTLS_SSL_PROTO_TLS1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_1)
    mbedtls_md5_update( &ssl->handshake->fin_md5 , buf, len );
    mbedtls_sha1_update( &ssl->handshake->fin_sha1, buf, len );
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_2) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_3)

#if defined(MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES)
	unsigned char padbuf[MBEDTLS_MD_MAX_SIZE];
#endif /* MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES */
	const mbedtls_ssl_ciphersuite_t *suite_info;

	suite_info = mbedtls_ssl_ciphersuite_from_id(ssl->session_negotiate->ciphersuite);

	/* Check whether cipher has already been set. If it hasn't 
	 * then we have to compute a hash with all available algorithms.
	 */
	if (suite_info != NULL) {

		if (suite_info->hash == MBEDTLS_MD_SHA256) {
#if defined(MBEDTLS_SHA256_C)
			MBEDTLS_SSL_DEBUG_BUF(4, "Transcript state (before)", (unsigned char *)
				ssl->handshake->fin_sha256.state, 32);
			mbedtls_sha256_update(&ssl->handshake->fin_sha256, buf, len);
			MBEDTLS_SSL_DEBUG_BUF(4, "Input to handshake hash", buf, len);
			MBEDTLS_SSL_DEBUG_BUF(4, "Transcript state (after)", (unsigned char *)
				ssl->handshake->fin_sha256.state, 32);
#if defined(MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES) 
			mbedtls_sha256_init(&sha256_debug);
			mbedtls_sha256_clone(&sha256_debug, &ssl->handshake->fin_sha256);
			mbedtls_sha256_finish(&sha256_debug, padbuf);
			MBEDTLS_SSL_DEBUG_BUF(4, "Handshake hash", (unsigned char *)
				padbuf, 32);
#endif // MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES
#else 
			MBEDTLS_SSL_DEBUG_MSG(1, ("ssl_update_checksum_start: Unknow hash function."));
			return;
#endif /* MBEDTLS_SHA256_C */
		}
		else if (suite_info->hash == MBEDTLS_MD_SHA384) {
#if defined(MBEDTLS_SHA512_C)
			MBEDTLS_SSL_DEBUG_BUF(4, "Transcript state (before)", (unsigned char *)
				ssl->handshake->fin_sha512.state, 48);
			mbedtls_sha512_update(&ssl->handshake->fin_sha512, buf, len);
			MBEDTLS_SSL_DEBUG_BUF(4, "Input to handshake hash", buf, len);
			MBEDTLS_SSL_DEBUG_BUF(4, "Transcript state (after)", (unsigned char *)
				ssl->handshake->fin_sha512.state, 48);

#if defined(MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES) 
			mbedtls_sha512_init(&sha512_debug);
			mbedtls_sha512_starts(&sha512_debug, 1 /* = use SHA384 */);
			mbedtls_sha512_clone(&sha512_debug, &ssl->handshake->fin_sha512);
			mbedtls_sha512_finish(&sha512_debug, padbuf);
			MBEDTLS_SSL_DEBUG_BUF(4, "Handshake hash", (unsigned char *)
				padbuf, 48);
#endif // MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES
#else 
			MBEDTLS_SSL_DEBUG_MSG(1, ("ssl_update_checksum_start: Unknow hash function."));
			return;
#endif /* MBEDTLS_SHA512_C */
		}
		else {
			MBEDTLS_SSL_DEBUG_MSG(1, ("ssl_update_checksum_start: Unknow hash function."));
			return;
		} 
	} // suite_info != NULL
	else {

#if defined(MBEDTLS_SHA256_C)
		MBEDTLS_SSL_DEBUG_BUF(4, "Transcript state (before)", (unsigned char *)
			ssl->handshake->fin_sha256.state, 32);
		mbedtls_sha256_update(&ssl->handshake->fin_sha256, buf, len);
		MBEDTLS_SSL_DEBUG_BUF(4, "Input to handshake hash", buf, len);
		MBEDTLS_SSL_DEBUG_BUF(4, "Transcript state (after)", (unsigned char *)
			ssl->handshake->fin_sha256.state, 32);

#if defined(MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES) 
		mbedtls_sha256_init(&sha256_debug);
		mbedtls_sha256_clone(&sha256_debug, &ssl->handshake->fin_sha256);
		mbedtls_sha256_finish(&sha256_debug, padbuf);
		MBEDTLS_SSL_DEBUG_BUF(4, "Handshake hash", (unsigned char *)
			padbuf, 32);
#endif // MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES
#endif /* MBEDTLS_SHA256_C */

#if defined(MBEDTLS_SHA512_C)
		MBEDTLS_SSL_DEBUG_BUF(4, "Transcript state (before)", (unsigned char *)
			ssl->handshake->fin_sha512.state, 48);
		mbedtls_sha512_update(&ssl->handshake->fin_sha512, buf, len);
		MBEDTLS_SSL_DEBUG_BUF(4, "Input to handshake hash", buf, len);
		MBEDTLS_SSL_DEBUG_BUF(4, "Transcript state (after)", (unsigned char *)
			ssl->handshake->fin_sha512.state, 48);

#if defined(MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES) 
		mbedtls_sha512_init(&sha512_debug);
		mbedtls_sha512_starts(&sha512_debug, 1 /* = use SHA384 */);
		mbedtls_sha512_clone(&sha512_debug, &ssl->handshake->fin_sha512);
		mbedtls_sha512_finish(&sha512_debug, padbuf);
		MBEDTLS_SSL_DEBUG_BUF(4, "Handshake hash", (unsigned char *)
			padbuf, 48);
#endif // MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES
#endif /* MBEDTLS_SHA512_C */
	}
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 || defined(MBEDTLS_SSL_PROTO_TLS1_3) */
}

#if defined(MBEDTLS_SSL_PROTO_SSL3) || defined(MBEDTLS_SSL_PROTO_TLS1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_1)
static void ssl_update_checksum_md5sha1( mbedtls_ssl_context *ssl,
                                         const unsigned char *buf, size_t len )
{
     mbedtls_md5_update( &ssl->handshake->fin_md5 , buf, len );
    mbedtls_sha1_update( &ssl->handshake->fin_sha1, buf, len );
}
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if defined(MBEDTLS_SHA256_C)
static void ssl_update_checksum_sha256( mbedtls_ssl_context *ssl,
                                        const unsigned char *buf, size_t len )
{
#if defined(MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES)
	mbedtls_sha256_context sha256;
	unsigned char padbuf[32];

#endif // MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES

    mbedtls_sha256_update( &ssl->handshake->fin_sha256, buf, len );
	MBEDTLS_SSL_DEBUG_BUF(4, "Input to handshake hash", buf, len);
	MBEDTLS_SSL_DEBUG_BUF(4, "Transcript state", (unsigned char *)
		ssl->handshake->fin_sha256.state, 32);

#if defined(MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES)
	mbedtls_sha256_init(&sha256);
	mbedtls_sha256_clone(&sha256, &ssl->handshake->fin_sha256);
	mbedtls_sha256_finish(&sha256, padbuf);

	MBEDTLS_SSL_DEBUG_BUF(4, "Handshake hash", (unsigned char *)
		padbuf, 32);
#endif // MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES

}
#endif

#if defined(MBEDTLS_SHA512_C)
static void ssl_update_checksum_sha384( mbedtls_ssl_context *ssl,
                                        const unsigned char *buf, size_t len )
{

#if defined(MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES)
	mbedtls_sha512_context sha512;
	unsigned char padbuf[48];
#endif /* MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES */

    mbedtls_sha512_update( &ssl->handshake->fin_sha512, buf, len );
	MBEDTLS_SSL_DEBUG_BUF(4, "Input to handshake hash", buf, len);
	MBEDTLS_SSL_DEBUG_BUF(4, "Transcript hash", (unsigned char *)
		ssl->handshake->fin_sha512.state, 48);

#if defined(MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES)
	mbedtls_sha512_init(&sha512);
	mbedtls_sha512_starts(&sha512, 1 /* = use SHA384 */);
	mbedtls_sha512_clone(&sha512, &ssl->handshake->fin_sha512);
	mbedtls_sha512_finish(&sha512, padbuf);

	MBEDTLS_SSL_DEBUG_BUF(4, "Handshake hash", (unsigned char *) padbuf, 48);
#endif /* MBEDTLS_SSL_DEBUG_HANDSHAKE_HASHES */

}
#endif /* MBEDTLS_SHA512_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 || defined(MBEDTLS_SSL_PROTO_TLS1_3)*/

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if defined(MBEDTLS_SHA256_C)
static int ssl_calc_finished_tls_sha256(
	mbedtls_ssl_context *ssl, unsigned char *buf, int from)
{
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
	const char *sender;
	int len = 12; 
#endif /* ! MBEDTLS_SSL_PROTO_TLS1_3 */
	int ret; 
	mbedtls_sha256_context sha256;
	unsigned char padbuf[32];
	unsigned char *finished_key;
	mbedtls_ssl_session *session; 
	const mbedtls_md_info_t *md;

	md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

	if (md == NULL) {
		MBEDTLS_SSL_DEBUG_MSG(2, ("mbedtls_md_info_from_type failed"));
		return (MBEDTLS_ERR_SSL_INTERNAL_ERROR);
	}

    session = ssl->session_negotiate;
    if( !session )
        session = ssl->session;

    mbedtls_sha256_init( &sha256 );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> calc finished tls sha256" ) );

    mbedtls_sha256_clone( &sha256, &ssl->handshake->fin_sha256 );

	/* TLS 1.3 Finished message
	*
	* struct {
	*     opaque verify_data[Hash.length];
	* } Finished;
    *
	* verify_data =
	*     HMAC(finished_key, Hash(
	*         Handshake Context +
	*         Certificate* +
	*         CertificateVerify*)
	*    )
	*
	*   * Only included if present.
	*/
/*
#if !defined(MBEDTLS_SHA256_ALT)
    MBEDTLS_SSL_DEBUG_BUF( 4, "finished sha2 state", (unsigned char *)
                   sha256.state, sizeof( sha256.state ) );
#endif // !MBEDTLS_SHA256_ALT
*/
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
    sender = ( from == MBEDTLS_SSL_IS_CLIENT )
             ? "client finished"
             : "server finished";
#endif /* ! MBEDTLS_SSL_PROTO_TLS1_3 */

    mbedtls_sha256_finish( &sha256, padbuf );

	MBEDTLS_SSL_DEBUG_BUF(5, "handshake hash", padbuf, 32);

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

	/* 
	 * finished_key =
     *    HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
     * 
	 * The binding_value is computed in the same way as the Finished message 
	 * but with the BaseKey being the binder_key.
	 */

	// create client finished_key
	ret = hkdfExpandLabel(MBEDTLS_MD_SHA256, ssl->handshake->client_handshake_traffic_secret, 32, (const unsigned char*)"finished", strlen("finished"), (const unsigned char*) "", 0, 32, ssl->handshake->client_finished_key, 32);
	
	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(2, "Creating the client_finished_key failed", ret);
		return (ret);
	} 

	MBEDTLS_SSL_DEBUG_BUF(3, "client_finished_key", ssl->handshake->client_finished_key, 32);

	// create server finished_key
	ret = hkdfExpandLabel(MBEDTLS_MD_SHA256, ssl->handshake->server_handshake_traffic_secret, 32, (const unsigned char*)"finished", strlen("finished"), (const unsigned char*)"", 0, 32, ssl->handshake->server_finished_key, 32);
	
	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(2, "Creating the server_finished_key failed", ret);
		return (ret);
	}

	MBEDTLS_SSL_DEBUG_BUF(3, "server_finished_key", ssl->handshake->server_finished_key, 32);

	if (from == MBEDTLS_SSL_IS_CLIENT) {
		/* In this case the server is receiving a finished message
		* sent by the client. It therefore needs to use the client_finished_key.
		*/
		MBEDTLS_SSL_DEBUG_MSG(3, ("Using client_finished_key to compute mac (for creating finished message)"));
		finished_key = ssl->handshake->client_finished_key;
	}
	else {
		/* If the server is sending a finished message then it needs to use
		* the server_finished_key.
		*/
		MBEDTLS_SSL_DEBUG_MSG(3, ("Using server_finished_key to compute mac (for verification procedure)"));
		finished_key = ssl->handshake->server_finished_key;
	}

	// compute mac and write it into the buffer
	ret = mbedtls_md_hmac(md, finished_key, 32, padbuf, 32, buf);

	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_md_hmac", ret);
		return (ret);
	}

	MBEDTLS_SSL_DEBUG_MSG(3, ("verify_data of Finished message"));
	MBEDTLS_SSL_DEBUG_BUF(3, "Input", padbuf, 32);
	MBEDTLS_SSL_DEBUG_BUF(3, "Key", finished_key, 32);
	MBEDTLS_SSL_DEBUG_BUF(3, "Output", buf, 32);

#else /* !MBEDTLS_SSL_PROTO_TLS1_3 */
    ssl->handshake->tls_prf( session->master, 48, sender,
                             padbuf, 32, buf, len );

	MBEDTLS_SSL_DEBUG_BUF(3, "session->master", session->master, 48);
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

    mbedtls_sha256_free( &sha256 );
    mbedtls_zeroize(  padbuf, sizeof(  padbuf ) );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= calc  finished" ) );
	return (0);
}
#endif /* MBEDTLS_SHA256_C */

#if defined(MBEDTLS_SHA512_C)
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
static int ssl_calc_finished_tls_sha384(
	mbedtls_ssl_context *ssl, unsigned char *buf, int from)
#else 
static int ssl_calc_finished_tls_sha384(
	mbedtls_ssl_context *ssl, unsigned char *buf, int from)
#endif 
{
	mbedtls_sha512_context sha512;
	int ret; 
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
	int len = 12;
	const char *sender;
#endif
	unsigned char padbuf[48];
	unsigned char *finished_key;
	mbedtls_ssl_session *session; 
	const mbedtls_md_info_t *md;

	md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);

	if (md == NULL) {
		MBEDTLS_SSL_DEBUG_MSG(2, ("mbedtls_md_info_from_type failed"));
		return (MBEDTLS_ERR_SSL_INTERNAL_ERROR);
	}

	session = ssl->session_negotiate;
	if (!session)
		session = ssl->session;

	mbedtls_sha512_init(&sha512);
	mbedtls_sha512_starts(&sha512, 1 /* = use SHA384 */);

	MBEDTLS_SSL_DEBUG_MSG(2, ("=> calc finished tls sha384"));

	mbedtls_sha512_clone(&sha512, &ssl->handshake->fin_sha512);

	/* TLS 1.3 Finished message
	*
	* struct {
	*     opaque verify_data[Hash.length];
	* } Finished;
	*
	* verify_data =
	*     HMAC(finished_key, Hash(
	*         Handshake Context +
	*         Certificate* +
	*         CertificateVerify*
	*         )
	*    )
	*
	*   * Only included if present.
	*/

/*#if !defined(MBEDTLS_SHA512_ALT)
	MBEDTLS_SSL_DEBUG_BUF(4, "finished sha512 state", (unsigned char *)
		sha512.state, sizeof(sha512.state));
#endif
*/
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
	sender = (from == MBEDTLS_SSL_IS_CLIENT)
		? "client finished"
		: "server finished";
#endif

	mbedtls_sha512_finish(&sha512, padbuf);

	MBEDTLS_SSL_DEBUG_BUF(5, "handshake hash", padbuf, 48);

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

	// create client finished_key
	ret = hkdfExpandLabel(MBEDTLS_MD_SHA384, ssl->handshake->client_handshake_traffic_secret, 48, (const unsigned char*)"finished", strlen("finished"), (const unsigned char*)"", 0, 48, ssl->handshake->client_finished_key, 48);

	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(2, "Creating the client_finished_key failed", ret);
		return (ret);
	}

	MBEDTLS_SSL_DEBUG_BUF(3, "client_finished_key", ssl->handshake->client_finished_key, 48);

	// create server finished_key
	ret = hkdfExpandLabel(MBEDTLS_MD_SHA384, ssl->handshake->server_handshake_traffic_secret, 48, (const unsigned char*)"finished", strlen("finished"), (const unsigned char*)"", 0, 48, ssl->handshake->server_finished_key, 48);

	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(2, "Creating the server_finished_key failed", ret);
		return (ret);
	}

	MBEDTLS_SSL_DEBUG_BUF(3, "server_finished_key", ssl->handshake->server_finished_key, 48);


	if (from == MBEDTLS_SSL_IS_CLIENT) {
		/* In this case the server is receiving a finished message
		* sent by the client. It therefore needs to use the client_finished_key.
		*/
		MBEDTLS_SSL_DEBUG_MSG(2, ("Using client_finished_key to compute mac (for creating finished message)"));
		finished_key = ssl->handshake->client_finished_key;
	}
	else {
		/* If the server is sending a finished message then it needs to use
		* the server_finished_key.
		*/
		MBEDTLS_SSL_DEBUG_MSG(2, ("Using server_finished_key to compute mac (for verification procedure)"));
		finished_key = ssl->handshake->server_finished_key;
	}

	// compute mac and write it into the buffer
	ret = mbedtls_md_hmac(md, finished_key, 48, padbuf, 48, buf);

	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(2, "mbedtls_md_hmac", ret);
		return (ret);
	}

	MBEDTLS_SSL_DEBUG_MSG(2, ("verify_data of Finished message"));
	MBEDTLS_SSL_DEBUG_BUF(3, "Input", padbuf, 48);
	MBEDTLS_SSL_DEBUG_BUF(3, "Key", finished_key, 48);
	MBEDTLS_SSL_DEBUG_BUF(3, "Output", buf, 48);

#else /* !MBEDTLS_SSL_PROTO_TLS1_3 */ 
	ssl->handshake->tls_prf(session->master, 48, sender,
		padbuf, 32, buf, len);

	MBEDTLS_SSL_DEBUG_BUF(3, "session->master", session->master, 48);
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

	mbedtls_sha512_free(&sha512);

	mbedtls_zeroize(padbuf, sizeof(padbuf));

	MBEDTLS_SSL_DEBUG_MSG(2, ("<= calc  finished"));
	return(0);
}
#endif /* MBEDTLS_SHA512_C */

#endif /* MBEDTLS_SSL_PROTO_TLS1_2 || defined(MBEDTLS_SSL_PROTO_TLS1_3)*/

static void ssl_handshake_wrapup_free_hs_transform( mbedtls_ssl_context *ssl )
{
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "=> handshake wrapup: final free" ) );

    /*
     * Free our handshake params
     */
    mbedtls_ssl_handshake_free( ssl->handshake );
    mbedtls_free( ssl->handshake );
    ssl->handshake = NULL;

    /*
     * Free the previous transform and swith in the current one
     */
    if( ssl->transform )
    {
        mbedtls_ssl_transform_free( ssl->transform );
        mbedtls_free( ssl->transform );
    }
    ssl->transform = ssl->transform_negotiate;
    ssl->transform_negotiate = NULL;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "<= handshake wrapup: final free" ) );
}

void mbedtls_ssl_handshake_wrapup( mbedtls_ssl_context *ssl )
{
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
    int resume = ssl->handshake->resume;
#endif 

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "=> handshake wrapup" ) );

#if defined(MBEDTLS_SSL_RENEGOTIATION)
    if( ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS )
    {
        ssl->renego_status =  MBEDTLS_SSL_RENEGOTIATION_DONE;
        ssl->renego_records_seen = 0;
    }
#endif

    /*
     * Free the previous session and switch in the current one
     */
    if( ssl->session )
    {
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
        /* RFC 7366 3.1: keep the EtM state */
        ssl->session_negotiate->encrypt_then_mac =
                  ssl->session->encrypt_then_mac;
#endif

        mbedtls_ssl_session_free( ssl->session );
        mbedtls_free( ssl->session );
    }
    ssl->session = ssl->session_negotiate;
    ssl->session_negotiate = NULL;

#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
    /*
     * Add cache entry
     */
    if( ssl->conf->f_set_cache != NULL &&
        ssl->session->id_len != 0 &&
        resume == 0 )
    {
        if( ssl->conf->f_set_cache( ssl->conf->p_cache, ssl->session ) != 0 )
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "cache did not store session" ) );
    }
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake->flight != NULL )
    {
        /* Cancel handshake timer */
        ssl_set_timer( ssl, 0 );

        /* Keep last flight around in case we need to resend it:
         * we need the handshake and transform structures for that */
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "skip freeing handshake and transform" ) );
    }
    else
#endif
        ssl_handshake_wrapup_free_hs_transform( ssl );

    //ssl->state++;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "<= handshake wrapup" ) );
}



int mbedtls_ssl_write_finished( mbedtls_ssl_context *ssl )
{
    int ret, hash_len;
	const mbedtls_ssl_ciphersuite_t *suite_info;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write finished" ) );

    /*
     * Set the out_msg pointer to the correct location based on IV length
     */

    if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_2 || ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_3)
    {
        ssl->out_msg = ssl->out_iv + ssl->transform_negotiate->ivlen -
                       ssl->transform_negotiate->fixed_ivlen;
	}
	else if (ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_4) {
		ssl->out_msg = ssl->out_iv;
	}
    else
        ssl->out_msg = ssl->out_iv;

	ret = ssl->handshake->calc_finished(ssl, ssl->out_msg + 4, ssl->conf->endpoint);
	if (ret != 0)
	{
		MBEDTLS_SSL_DEBUG_RET(1, "calc_finished %d",ret);
		return(MBEDTLS_ERR_SSL_BAD_HS_FINISHED);
	}

	suite_info = mbedtls_ssl_ciphersuite_from_id(ssl->session_negotiate->ciphersuite);

	if (suite_info == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_ssl_ciphersuite_from_id in mbedtls_ssl_write_finished failed"));
		return(MBEDTLS_ERR_SSL_BAD_HS_FINISHED);
	}

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
	hash_len = mbedtls_hash_size_for_ciphersuite(suite_info);
#else 
    // TODO TLS/1.2 Hash length is determined by cipher suite (Page 63)
    hash_len = ( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 ) ? 36 : 12;
#endif 

#if defined(MBEDTLS_SSL_RENEGOTIATION)
    ssl->verify_data_len = hash_len;
    memcpy( ssl->own_verify_data, ssl->out_msg + 4, hash_len );
#endif

	ssl->out_msglen = 4 /* 4 for the TLSCiphertext header */ + hash_len; 
	/* We add the additional byte for the ContentType later */;
    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = MBEDTLS_SSL_HS_FINISHED;

#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
    /*
     * In case of session resuming, invert the client and server
     * ChangeCipherSpec messages order.
     */
    if( ssl->handshake->resume != 0 )
    {
#if defined(MBEDTLS_SSL_CLI_C)
        if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
            ssl->state = MBEDTLS_SSL_HANDSHAKE_WRAPUP;
#endif
#if defined(MBEDTLS_SSL_SRV_C)
        if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
            ssl->state = MBEDTLS_SSL_SERVER_FINISHED; // changed it from client_change_cipher_spec
#endif
    }
    else
        ssl->state++;

    /*
     * Switch to our negotiated transform and session parameters for outbound
     * data.
     */
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "switching to new transform spec for outbound data" ) );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        unsigned char i;

        /* Remember current epoch settings for resending */
        ssl->handshake->alt_transform_out = ssl->transform_out;
        memcpy( ssl->handshake->alt_out_ctr, ssl->out_ctr, 8 );

        /* Set sequence_number to zero */
        memset( ssl->out_ctr + 2, 0, 6 );

        /* Increment epoch */
        for( i = 2; i > 0; i-- )
            if( ++ssl->out_ctr[i - 1] != 0 )
                break;

        /* The loop goes to its end iff the counter is wrapping */
        if( i == 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "DTLS epoch would wrap" ) );
            return( MBEDTLS_ERR_SSL_COUNTER_WRAPPING );
        }
    }
    else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    memset( ssl->out_ctr, 0, 8 );

    ssl->transform_out = ssl->transform_negotiate;
    ssl->session_out = ssl->session_negotiate;
	memset(ssl->transform_out->sequence_number_enc, 0x0, 12); /* Set sequence number to zero */
#endif /* TLS 13 */
 
#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
    if( mbedtls_ssl_hw_record_activate != NULL )
    {
        if( ( ret = mbedtls_ssl_hw_record_activate( ssl, MBEDTLS_SSL_CHANNEL_OUTBOUND ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_hw_record_activate", ret );
            return( MBEDTLS_ERR_SSL_HW_ACCEL_FAILED );
        }
    }
#endif /* MBEDTLS_SSL_HW_RECORD_ACCEL */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        mbedtls_ssl_send_flight_completed( ssl );
#endif

    if( ( ret = mbedtls_ssl_write_record( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_record", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write finished" ) );
	
	return( 0 );
}

#if defined(MBEDTLS_SSL_PROTO_SSL3)
#define SSL_MAX_HASH_LEN 36
#else
#define SSL_MAX_HASH_LEN 12
#endif

int mbedtls_ssl_parse_finished( mbedtls_ssl_context *ssl )
{
    int ret;
    unsigned int hash_len;
	const mbedtls_ssl_ciphersuite_t *suite_info;

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
	unsigned char buf[MBEDTLS_MD_MAX_SIZE];
#else
	unsigned char buf[SSL_MAX_HASH_LEN];
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse finished" ) );

	suite_info = mbedtls_ssl_ciphersuite_from_id(ssl->session_negotiate->ciphersuite);

	if (suite_info == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_ssl_ciphersuite_from_id in mbedtls_ssl_parse_finished failed"));
		return(MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO);
	}

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
	hash_len = mbedtls_hash_size_for_ciphersuite(suite_info);
#else
	hash_len = 12;
#endif

	/* Since mbedtls_ssl_read_record also updates the transcript we need to compute 
	 * the Finished first. */
	ret = ssl->handshake->calc_finished(ssl, buf, ssl->conf->endpoint ^ 1);
	if (ret !=0) {
		MBEDTLS_SSL_DEBUG_RET(1, "calc_finished", ret);
		return(ret);
	}

    if( ( ret = mbedtls_ssl_read_record( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        return( ret );
    }

    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad finished message" ) );
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    /* There is currently no ciphersuite using another length with TLS 1.2 */
#if defined(MBEDTLS_SSL_PROTO_SSL3)
    if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 )
        hash_len = 36;
    else
#endif

	
		/* Incoming message is indeed a Finished message */
		if (ssl->in_msg[0] == MBEDTLS_SSL_HS_FINISHED &&
			ssl->in_hslen == mbedtls_ssl_hs_hdr_len(ssl) + hash_len)
		{
			MBEDTLS_SSL_DEBUG_MSG(5, ("Verify finished message"));

//			ssl->handshake->calc_finished(ssl, buf, ssl->conf->endpoint ^ 1);

			MBEDTLS_SSL_DEBUG_BUF(5, "ssl->in_msg + mbedtls_ssl_hs_hdr_len( ssl )", ssl->in_msg + mbedtls_ssl_hs_hdr_len(ssl), hash_len);
			MBEDTLS_SSL_DEBUG_BUF(5, "buf", buf, hash_len);

			if (mbedtls_ssl_safer_memcmp(ssl->in_msg + mbedtls_ssl_hs_hdr_len(ssl),
				buf, hash_len) != 0)
			{
				MBEDTLS_SSL_DEBUG_MSG(1, ("bad finished message"));
				return(MBEDTLS_ERR_SSL_BAD_HS_FINISHED);
			}

			// Now, we also need to update our transcript hash
			//MBEDTLS_SSL_DEBUG_MSG(5, ("--- Update Checksum (mbedtls_ssl_parse_finished)"));
			//ssl->handshake->update_checksum(ssl, ssl->in_msg, ssl->in_hslen);

#if defined(MBEDTLS_SSL_RENEGOTIATION)
			ssl->verify_data_len = hash_len;
			memcpy(ssl->peer_verify_data, buf, hash_len);
#endif

			if (ssl->handshake->resume != 0)
			{
#if defined(MBEDTLS_SSL_CLI_C)
				if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT)
					ssl->state = MBEDTLS_SSL_SERVER_FINISHED; 
#endif
#if defined(MBEDTLS_SSL_SRV_C)
				if (ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER)
					ssl->state = MBEDTLS_SSL_HANDSHAKE_WRAPUP;
#endif
			}
			else
				ssl->state++;

#if defined(MBEDTLS_SSL_PROTO_DTLS)
			if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM)
				mbedtls_ssl_recv_flight_completed(ssl);
#endif

			MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse finished"));
		}
		else {
			/* We haven't specified yet what it is. */
			MBEDTLS_SSL_DEBUG_MSG(1, ("Unknown message: Expected a Finished"));
			return(MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE);
		}

    return( 0 );
}

static void ssl_handshake_params_init( mbedtls_ssl_handshake_params *handshake )
{
    memset( handshake, 0, sizeof( mbedtls_ssl_handshake_params ) );

#if defined(MBEDTLS_SSL_PROTO_SSL3) || defined(MBEDTLS_SSL_PROTO_TLS1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_1)
     mbedtls_md5_init(   &handshake->fin_md5  );
    mbedtls_sha1_init(   &handshake->fin_sha1 );
     mbedtls_md5_starts( &handshake->fin_md5  );
    mbedtls_sha1_starts( &handshake->fin_sha1 );
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_2) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if defined(MBEDTLS_SHA256_C)
    mbedtls_sha256_init(   &handshake->fin_sha256    );
    mbedtls_sha256_starts( &handshake->fin_sha256, 0 /* for SHA-256 */);
#endif
#if defined(MBEDTLS_SHA512_C)
    mbedtls_sha512_init(   &handshake->fin_sha512    );
    mbedtls_sha512_starts( &handshake->fin_sha512, 1 /* for SHA-384 */);
#endif
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 || defined(MBEDTLS_SSL_PROTO_TLS1_3) */

    handshake->update_checksum = ssl_update_checksum_start;
#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && !defined(MBEDTLS_SSL_PROTO_TLS1_3)
	handshake->sig_alg = MBEDTLS_SSL_HASH_SHA1;
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
	handshake->signature_scheme = SIGNATURE_NONE; // initially set to zero
#endif

#if defined(MBEDTLS_DHM_C)
    mbedtls_dhm_init( &handshake->dhm_ctx );
#endif
#if defined(MBEDTLS_ECDH_C)
    mbedtls_ecdh_init( &handshake->ecdh_ctx );
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    mbedtls_ecjpake_init( &handshake->ecjpake_ctx );
#if defined(MBEDTLS_SSL_CLI_C)
    handshake->ecjpake_cache = NULL;
    handshake->ecjpake_cache_len = 0;
#endif
#endif

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION) && defined(MBEDTLS_X509_CRT_PARSE_C)
    handshake->sni_authmode = MBEDTLS_SSL_VERIFY_UNSET;
#endif
}

static void ssl_transform_init( mbedtls_ssl_transform *transform )
{
    memset( transform, 0, sizeof(mbedtls_ssl_transform) );

    mbedtls_cipher_init( &transform->cipher_ctx_enc );
    mbedtls_cipher_init( &transform->cipher_ctx_dec );

    mbedtls_md_init( &transform->md_ctx_enc );
    mbedtls_md_init( &transform->md_ctx_dec );
}

void mbedtls_ssl_session_init( mbedtls_ssl_session *session )
{
    memset( session, 0, sizeof(mbedtls_ssl_session) );
}

static int ssl_handshake_init( mbedtls_ssl_context *ssl )
{
    /* Clear old handshake information if present */
    if( ssl->transform_negotiate )
        mbedtls_ssl_transform_free( ssl->transform_negotiate );
    if( ssl->session_negotiate )
        mbedtls_ssl_session_free( ssl->session_negotiate );
    if( ssl->handshake )
        mbedtls_ssl_handshake_free( ssl->handshake );

    /*
     * Either the pointers are now NULL or cleared properly and can be freed.
     * Now allocate missing structures.
     */
    if( ssl->transform_negotiate == NULL )
    {
        ssl->transform_negotiate = mbedtls_calloc( 1, sizeof(mbedtls_ssl_transform) );
    }

    if( ssl->session_negotiate == NULL )
    {
        ssl->session_negotiate = mbedtls_calloc( 1, sizeof(mbedtls_ssl_session) );
    }

    if( ssl->handshake == NULL )
    {
        ssl->handshake = mbedtls_calloc( 1, sizeof(mbedtls_ssl_handshake_params) );
    }

    /* All pointers should exist and can be directly freed without issue */
    if( ssl->handshake == NULL ||
        ssl->transform_negotiate == NULL ||
        ssl->session_negotiate == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "alloc() of ssl sub-contexts failed" ) );

        mbedtls_free( ssl->handshake );
        mbedtls_free( ssl->transform_negotiate );
        mbedtls_free( ssl->session_negotiate );

        ssl->handshake = NULL;
        ssl->transform_negotiate = NULL;
        ssl->session_negotiate = NULL;

        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    /* Initialize structures */
    mbedtls_ssl_session_init( ssl->session_negotiate );
    ssl_transform_init( ssl->transform_negotiate );
    ssl_handshake_params_init( ssl->handshake );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        ssl->handshake->alt_transform_out = ssl->transform_out;

        if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
            ssl->handshake->retransmit_state = MBEDTLS_SSL_RETRANS_PREPARING;
        else
            ssl->handshake->retransmit_state = MBEDTLS_SSL_RETRANS_WAITING;

        ssl_set_timer( ssl, 0 );
    }
#endif

    return( 0 );
}

#if defined(MBEDTLS_SSL_COOKIE_C) && defined(MBEDTLS_SSL_SRV_C)
/* Dummy cookie callbacks for defaults */

/* 
  ssl_cookie_write_dummy 
    ctx = cookie context
	p = pointer to pointer to the buffer 
	end = pointer to the end of the buffer
	cli_id = client id 
	cli_id_len = client id length
*/
static int ssl_cookie_write_dummy(void *ctx,
	unsigned char **p, unsigned char *end,
	const unsigned char *cli_id, size_t cli_id_len)
{
/*
	// Place a dummy cookie in there. 
	unsigned char dummy_cookie[3] = { 0x1, 0x2, 0x3 };
	*p=memcpy(*p, (void*) &dummy_cookie[0], 3);
	*p += 3; 
	return 0;
*/
    ((void) ctx);
    ((void) p);
    ((void) end);
    ((void) cli_id);
    ((void) cli_id_len);

    return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
}

static int ssl_cookie_check_dummy( void *ctx,
                      const unsigned char *cookie, size_t cookie_len,
                      const unsigned char *cli_id, size_t cli_id_len )
{
	/*
	int result=-1; 

	if (cookie_len == 0) {
		// The cookie has not been provided in the request (as it will be the case with the initial message)
		result=-1;
	} else if (cookie_len > 0) {
		// Compare provided cookie with stored cookie value
		// TBD.
		result = 0;
	}

	return result; 
	*/

	((void) ctx);
	((void) cookie);
	((void) cookie_len);
	((void) cli_id);
	((void) cli_id_len);

    return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
}
#endif /* MBEDTLS_SSL_COOKIE_C && MBEDTLS_SSL_SRV_C */

/*
 * Initialize an SSL context
 */
void mbedtls_ssl_init( mbedtls_ssl_context *ssl )
{
    memset( ssl, 0, sizeof( mbedtls_ssl_context ) );
}

/*
 * Setup an SSL context
 */
int mbedtls_ssl_setup( mbedtls_ssl_context *ssl,
                       const mbedtls_ssl_config *conf )
{
    int ret;
    const size_t len = MBEDTLS_SSL_BUFFER_LEN;

    ssl->conf = conf;

    /*
     * Prepare base structures
     */
    if( ( ssl-> in_buf = mbedtls_calloc( 1, len ) ) == NULL ||
        ( ssl->out_buf = mbedtls_calloc( 1, len ) ) == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "alloc(%d bytes) failed", len ) );
        mbedtls_free( ssl->in_buf );
        ssl->in_buf = NULL;
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        ssl->out_hdr = ssl->out_buf;
        ssl->out_ctr = ssl->out_buf +  3;
        ssl->out_len = ssl->out_buf + 11;
        ssl->out_iv  = ssl->out_buf + 13;
        ssl->out_msg = ssl->out_buf + 13;

        ssl->in_hdr = ssl->in_buf;
        ssl->in_ctr = ssl->in_buf +  3;
        ssl->in_len = ssl->in_buf + 11;
        ssl->in_iv  = ssl->in_buf + 13;
        ssl->in_msg = ssl->in_buf + 13;
    }
    else
#endif
    {
        ssl->out_ctr = ssl->out_buf;
        ssl->out_hdr = ssl->out_buf +  8;
        ssl->out_len = ssl->out_buf + 11;
        ssl->out_iv  = ssl->out_buf + 13;
        ssl->out_msg = ssl->out_buf + 13;

        ssl->in_ctr = ssl->in_buf;
        ssl->in_hdr = ssl->in_buf +  8;
        ssl->in_len = ssl->in_buf + 11;
        ssl->in_iv  = ssl->in_buf + 13;
        ssl->in_msg = ssl->in_buf + 13;
    }

    if( ( ret = ssl_handshake_init( ssl ) ) != 0 )
        return( ret );



	/* Initialize ticket structure */
#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET) && defined(MBEDTLS_SSL_CLI_C)
	ssl->session_negotiate->ticket = NULL;
	ssl->session_negotiate->ticket_nonce_len = 0;
#endif /* ( MBEDTLS_SSL_SESSION_TICKETS) || MBEDTLS_SSL_NEW_SESSION_TICKET ) && MBEDTLS_SSL_CLI_C */

    return( 0 );
}

/*
 * Reset an initialized and used SSL context for re-use while retaining
 * all application-set variables, function pointers and data.
 *
 * If partial is non-zero, keep data in the input buffer and client ID.
 * (Use when a DTLS client reconnects from the same port.)
 */
static int ssl_session_reset_int( mbedtls_ssl_context *ssl, int partial )
{
    int ret;

    ssl->state = MBEDTLS_SSL_HELLO_REQUEST;

    /* Cancel any possibly running timer */
    ssl_set_timer( ssl, 0 );

#if defined(MBEDTLS_SSL_RENEGOTIATION)
    ssl->renego_status = MBEDTLS_SSL_INITIAL_HANDSHAKE;
    ssl->renego_records_seen = 0;

    ssl->verify_data_len = 0;
    memset( ssl->own_verify_data, 0, MBEDTLS_SSL_VERIFY_DATA_MAX_LEN );
    memset( ssl->peer_verify_data, 0, MBEDTLS_SSL_VERIFY_DATA_MAX_LEN );
#endif

#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
    ssl->secure_renegotiation = MBEDTLS_SSL_LEGACY_RENEGOTIATION;
#endif

    ssl->in_offt = NULL;

    ssl->in_msg = ssl->in_buf + 13;
    ssl->in_msgtype = 0;
    ssl->in_msglen = 0;
    if( partial == 0 )
        ssl->in_left = 0;
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    ssl->next_record_offset = 0;
    ssl->in_epoch = 0;
#endif
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    ssl_dtls_replay_reset( ssl );
#endif

    ssl->in_hslen = 0;
    ssl->nb_zero = 0;
    ssl->record_read = 0;

    ssl->out_msg = ssl->out_buf + 13;
    ssl->out_msgtype = 0;
    ssl->out_msglen = 0;
    ssl->out_left = 0;
#if defined(MBEDTLS_SSL_CBC_RECORD_SPLITTING)
    if( ssl->split_done != MBEDTLS_SSL_CBC_RECORD_SPLITTING_DISABLED )
        ssl->split_done = 0;
#endif

    ssl->transform_in = NULL;
    ssl->transform_out = NULL;

    memset( ssl->out_buf, 0, MBEDTLS_SSL_BUFFER_LEN );
    if( partial == 0 )
        memset( ssl->in_buf, 0, MBEDTLS_SSL_BUFFER_LEN );

#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
    if( mbedtls_ssl_hw_record_reset != NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "going for mbedtls_ssl_hw_record_reset()" ) );
        if( ( ret = mbedtls_ssl_hw_record_reset( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_hw_record_reset", ret );
            return( MBEDTLS_ERR_SSL_HW_ACCEL_FAILED );
        }
    }
#endif

    if( ssl->transform )
    {
        mbedtls_ssl_transform_free( ssl->transform );
        mbedtls_free( ssl->transform );
        ssl->transform = NULL;
    }

    if( ssl->session )
    {
        mbedtls_ssl_session_free( ssl->session );
        mbedtls_free( ssl->session );
        ssl->session = NULL;
    }

#if defined(MBEDTLS_SSL_ALPN)
    ssl->alpn_chosen = NULL;
#endif

#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(MBEDTLS_SSL_SRV_C)
    if( partial == 0 )
    {
        mbedtls_free( ssl->cli_id );
        ssl->cli_id = NULL;
        ssl->cli_id_len = 0;
    }
#endif

    if( ( ret = ssl_handshake_init( ssl ) ) != 0 )
        return( ret );

    return( 0 );
}

/*
 * Reset an initialized and used SSL context for re-use while retaining
 * all application-set variables, function pointers and data.
 */
int mbedtls_ssl_session_reset( mbedtls_ssl_context *ssl )
{
    return( ssl_session_reset_int( ssl, 0 ) );
}

/*
 * SSL set accessors
 */
void mbedtls_ssl_conf_endpoint( mbedtls_ssl_config *conf, int endpoint )
{
    conf->endpoint   = endpoint;
}

void mbedtls_ssl_conf_transport( mbedtls_ssl_config *conf, int transport )
{
    conf->transport = transport;
}

#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
void mbedtls_ssl_conf_dtls_anti_replay( mbedtls_ssl_config *conf, char mode )
{
    conf->anti_replay = mode;
}
#endif

#if defined(MBEDTLS_SSL_DTLS_BADMAC_LIMIT)
void mbedtls_ssl_conf_dtls_badmac_limit( mbedtls_ssl_config *conf, unsigned limit )
{
    conf->badmac_limit = limit;
}
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)
void mbedtls_ssl_conf_handshake_timeout( mbedtls_ssl_config *conf, uint32_t min, uint32_t max )
{
    conf->hs_timeout_min = min;
    conf->hs_timeout_max = max;
}
#endif

void mbedtls_ssl_conf_authmode( mbedtls_ssl_config *conf, int authmode )
{
    conf->authmode   = authmode;
}

#if defined(MBEDTLS_ZERO_RTT)
void mbedtls_ssl_conf_early_data(mbedtls_ssl_config *conf, int early_data, char *buffer, unsigned int len, int(*early_data_callback)(mbedtls_ssl_context *,
	unsigned char *, size_t))
{
	if (conf != NULL) {
	  conf->early_data = early_data;
	  if (buffer != NULL && len >0 && early_data==MBEDTLS_SSL_EARLY_DATA_ENABLED) {
		  conf->early_data_buf = buffer; 
		  conf->early_data_len = len; 
		  conf->early_data_callback = early_data_callback; 
	  }
	}
}
#endif /* MBEDTLS_ZERO_RTT */

#if defined(MBEDTLS_X509_CRT_PARSE_C)
void mbedtls_ssl_conf_verify( mbedtls_ssl_config *conf,
                     int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                     void *p_vrfy )
{
    conf->f_vrfy      = f_vrfy;
    conf->p_vrfy      = p_vrfy;
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

void mbedtls_ssl_conf_rng( mbedtls_ssl_config *conf,
                  int (*f_rng)(void *, unsigned char *, size_t),
                  void *p_rng )
{
    conf->f_rng      = f_rng;
    conf->p_rng      = p_rng;
}

void mbedtls_ssl_conf_dbg( mbedtls_ssl_config *conf,
                  void (*f_dbg)(void *, int, const char *, int, const char *),
                  void  *p_dbg )
{
    conf->f_dbg      = f_dbg;
    conf->p_dbg      = p_dbg;
}

void mbedtls_ssl_set_bio( mbedtls_ssl_context *ssl,
        void *p_bio,
        int (*f_send)(void *, const unsigned char *, size_t),
        int (*f_recv)(void *, unsigned char *, size_t),
        int (*f_recv_timeout)(void *, unsigned char *, size_t, uint32_t) )
{
    ssl->p_bio          = p_bio;
    ssl->f_send         = f_send;
    ssl->f_recv         = f_recv;
    ssl->f_recv_timeout = f_recv_timeout;
}

void mbedtls_ssl_conf_read_timeout( mbedtls_ssl_config *conf, uint32_t timeout )
{
    conf->read_timeout   = timeout;
}

void mbedtls_ssl_set_timer_cb( mbedtls_ssl_context *ssl,
                               void *p_timer,
                               void (*f_set_timer)(void *, uint32_t int_ms, uint32_t fin_ms),
                               int (*f_get_timer)(void *) )
{
    ssl->p_timer        = p_timer;
    ssl->f_set_timer    = f_set_timer;
    ssl->f_get_timer    = f_get_timer;

    /* Make sure we start with no timer running */
    ssl_set_timer( ssl, 0 );
}

#if defined(MBEDTLS_SSL_SRV_C)
void mbedtls_ssl_conf_session_cache( mbedtls_ssl_config *conf,
        void *p_cache,
        int (*f_get_cache)(void *, mbedtls_ssl_session *),
        int (*f_set_cache)(void *, const mbedtls_ssl_session *) )
{
    conf->p_cache = p_cache;
    conf->f_get_cache = f_get_cache;
    conf->f_set_cache = f_set_cache;
}
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(MBEDTLS_SSL_CLI_C)
int mbedtls_ssl_set_session( mbedtls_ssl_context *ssl, const mbedtls_ssl_session *session )
{
    int ret;

    if( ssl == NULL ||
        session == NULL ||
        ssl->session_negotiate == NULL ||
        ssl->conf->endpoint != MBEDTLS_SSL_IS_CLIENT )
    {
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    if( ( ret = ssl_session_copy( ssl->session_negotiate, session ) ) != 0 )
        return( ret );

    ssl->handshake->resume = 1;

    return( 0 );
}
#endif /* MBEDTLS_SSL_CLI_C */

void mbedtls_ssl_conf_ciphersuites( mbedtls_ssl_config *conf,
                                   const int *ciphersuites )
{
    conf->ciphersuite_list[MBEDTLS_SSL_MINOR_VERSION_0] = ciphersuites;
    conf->ciphersuite_list[MBEDTLS_SSL_MINOR_VERSION_1] = ciphersuites;
    conf->ciphersuite_list[MBEDTLS_SSL_MINOR_VERSION_2] = ciphersuites;
    conf->ciphersuite_list[MBEDTLS_SSL_MINOR_VERSION_3] = ciphersuites;
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
	conf->ciphersuite_list[MBEDTLS_SSL_MINOR_VERSION_4] = ciphersuites;
#endif
}

void mbedtls_ssl_conf_ciphersuites_for_version( mbedtls_ssl_config *conf,
                                       const int *ciphersuites,
                                       int major, int minor )
{
    if( major != MBEDTLS_SSL_MAJOR_VERSION_3 )
        return;

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
	if (minor < MBEDTLS_SSL_MINOR_VERSION_0 || minor > MBEDTLS_SSL_MINOR_VERSION_4)
#else 
    if( minor < MBEDTLS_SSL_MINOR_VERSION_0 || minor > MBEDTLS_SSL_MINOR_VERSION_3 )
#endif
return;

    conf->ciphersuite_list[minor] = ciphersuites;
}

#if defined(MBEDTLS_X509_CRT_PARSE_C)
void mbedtls_ssl_conf_cert_profile( mbedtls_ssl_config *conf,
                                    const mbedtls_x509_crt_profile *profile )
{
    conf->cert_profile = profile;
}

/* Append a new keycert entry to a (possibly empty) list */
static int ssl_append_key_cert( mbedtls_ssl_key_cert **head,
                                mbedtls_x509_crt *cert,
                                mbedtls_pk_context *key )
{
    mbedtls_ssl_key_cert *new;

    new = mbedtls_calloc( 1, sizeof( mbedtls_ssl_key_cert ) );
    if( new == NULL )
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );

    new->cert = cert;
    new->key  = key;
    new->next = NULL;

    /* Update head is the list was null, else add to the end */
    if( *head == NULL )
    {
        *head = new;
    }
    else
    {
        mbedtls_ssl_key_cert *cur = *head;
        while( cur->next != NULL )
            cur = cur->next;
        cur->next = new;
    }

    return( 0 );
}

int mbedtls_ssl_conf_own_cert( mbedtls_ssl_config *conf,
                              mbedtls_x509_crt *own_cert,
                              mbedtls_pk_context *pk_key )
{
    return( ssl_append_key_cert( &conf->key_cert, own_cert, pk_key ) );
}

void mbedtls_ssl_conf_ca_chain( mbedtls_ssl_config *conf,
                               mbedtls_x509_crt *ca_chain,
                               mbedtls_x509_crl *ca_crl )
{
    conf->ca_chain   = ca_chain;
    conf->ca_crl     = ca_crl;
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION) && defined(MBEDTLS_X509_CRT_PARSE_C)
int mbedtls_ssl_set_hs_own_cert( mbedtls_ssl_context *ssl,
                                 mbedtls_x509_crt *own_cert,
                                 mbedtls_pk_context *pk_key )
{
    return( ssl_append_key_cert( &ssl->handshake->sni_key_cert,
                                 own_cert, pk_key ) );
}

void mbedtls_ssl_set_hs_ca_chain( mbedtls_ssl_context *ssl,
                                  mbedtls_x509_crt *ca_chain,
                                  mbedtls_x509_crl *ca_crl )
{
    ssl->handshake->sni_ca_chain   = ca_chain;
    ssl->handshake->sni_ca_crl     = ca_crl;
}

void mbedtls_ssl_set_hs_authmode( mbedtls_ssl_context *ssl,
                                  int authmode )
{
    ssl->handshake->sni_authmode = authmode;
}
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION && MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
/*
 * Set EC J-PAKE password for current handshake
 */
int mbedtls_ssl_set_hs_ecjpake_password( mbedtls_ssl_context *ssl,
                                         const unsigned char *pw,
                                         size_t pw_len )
{
    mbedtls_ecjpake_role role;

    if( ssl->handshake == NULL && ssl->conf == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
        role = MBEDTLS_ECJPAKE_SERVER;
    else
        role = MBEDTLS_ECJPAKE_CLIENT;

    return( mbedtls_ecjpake_setup( &ssl->handshake->ecjpake_ctx,
                                   role,
                                   MBEDTLS_MD_SHA256,
                                   MBEDTLS_ECP_DP_SECP256R1,
                                   pw, pw_len ) );
}
#endif /* MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)

/* The ssl_parse_new_session_ticket() function is used by the 
 * client to parse the NewSessionTicket message, which contains 
 * the ticket and meta-data provided by the server in a post-
 * handshake message. 
 * 
 * The code is located in ssl_tls.c since the function is called
 * mbedtls_ssl_read. It is a post-handshake message. 
 */
static int ssl_parse_new_session_ticket(mbedtls_ssl_context *ssl)
{
	int ret; 
	uint32_t lifetime, ticket_age_add;
	uint8_t ticket_nonce_len; 
	size_t ticket_len, ext_len; 
	unsigned char *ticket;
	const unsigned char *msg, *extensions;
	const mbedtls_ssl_ciphersuite_t *suite_info;

	MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse new session ticket"));

	msg = ssl->in_msg + mbedtls_ssl_hs_hdr_len(ssl);

	/* Ticket lifetime */
	lifetime = (msg[0] << 24) | (msg[1] << 16) |
		(msg[2] << 8) | (msg[3]);

	ssl->session->ticket_lifetime = lifetime;
	MBEDTLS_SSL_DEBUG_MSG(3, ("ticket->lifetime: %d", lifetime));

	/* Ticket Age Add */
	ticket_age_add = (msg[4] << 24) | (msg[5] << 16) |
		(msg[6] << 8) | (msg[7]);

	ssl->session->ticket_age_add = ticket_age_add;

	MBEDTLS_SSL_DEBUG_BUF(3, "ticket->age_add:", (unsigned char*) &ticket_age_add,4);

	/* Ticket Nonce */
	ticket_nonce_len = msg[8];

	MBEDTLS_SSL_DEBUG_MSG(3, ("ticket->nonce_length: %d", ticket_nonce_len));
	MBEDTLS_SSL_DEBUG_BUF(3, "ticket->nonce:", (unsigned char*)&msg[9], ticket_nonce_len);

	/* Check if we previously received a ticket already. If we did, then we should 
	 * re-use already allocated nonce-space.
	 */
	if (ssl->session->ticket_nonce != NULL || ssl->session->ticket_nonce_len > 0) {
		mbedtls_free(ssl->session->ticket_nonce); 
		ssl->session->ticket_nonce = NULL; 
		ssl->session->ticket_nonce_len = 0; 
	} 
	
	if ((ssl->session->ticket_nonce = mbedtls_calloc(1, ticket_nonce_len)) == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("ticket_nonce alloc failed"));
		return(MBEDTLS_ERR_SSL_ALLOC_FAILED);
	}

	memcpy(ssl->session->ticket_nonce, &msg[9], ticket_nonce_len);
	ssl->session->ticket_nonce_len = ticket_nonce_len;

	/* Ticket Length */
	ticket_len = (msg[9+ ticket_nonce_len] << 8) | (msg[10+ ticket_nonce_len]);

	MBEDTLS_SSL_DEBUG_MSG(3, ("ticket->length: %d", ticket_len));

	/* Ticket Extension Length */
	ext_len = (msg[11+ ticket_nonce_len +ticket_len] << 8) | (msg[12+ ticket_nonce_len + ticket_len]);

	// Check whether the length field is correct
	if ((ticket_len + ticket_nonce_len + ext_len + 13 + mbedtls_ssl_hs_hdr_len(ssl) != ssl->in_msglen) 
		&& ticket_len >0)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("Bad NewSessionTicket message"));
		return(MBEDTLS_ERR_SSL_BAD_HS_NEW_SESSION_TICKET);
	}

	/* Check if we previously received a ticket already. */
	if (ssl->session->ticket != NULL || ssl->session->ticket_len > 0) {
		mbedtls_free(ssl->session->ticket);
		ssl->session->ticket = NULL; 
		ssl->session->ticket_len = 0;
	}

	if ((ticket = mbedtls_calloc(1, ticket_len)) == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("ticket alloc failed"));
		return(MBEDTLS_ERR_SSL_ALLOC_FAILED);
	}

	memcpy(ticket, msg + 11 + ticket_nonce_len, ticket_len);
	ssl->session->ticket = ticket;
	ssl->session->ticket_len = ticket_len;

	MBEDTLS_SSL_DEBUG_BUF(3, "ticket", ticket, ticket_len);

	MBEDTLS_SSL_DEBUG_MSG(3, ("ticket->extension length: %d", ext_len));

	// We are not storing any extensions at the moment
	if (ext_len > 0) {
		extensions = &msg[13 + ticket_nonce_len + ticket_len];
		MBEDTLS_SSL_DEBUG_BUF(3, "ticket->extension", extensions, ext_len);
	}

	/* Compute PSK based on received nonce and resumption_master_secret 
	 * in the following style: 
	 * 
	 *  HKDF-Expand-Label(resumption_master_secret,
	 *                    "resumption", ticket_nonce, Hash.length)
	 */

	suite_info = mbedtls_ssl_ciphersuite_from_id(ssl->session->ciphersuite);

	if (suite_info == NULL)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("suite_info == NULL, ssl_parse_new_session_ticket failed"));
		return(MBEDTLS_ERR_SSL_INTERNAL_ERROR);
	}

	MBEDTLS_SSL_DEBUG_BUF(3, "resumption_master_secret", ssl->session->resumption_master_secret, mbedtls_hash_size_for_ciphersuite(suite_info));

	ret = hkdfExpandLabel(suite_info->hash, ssl->session->resumption_master_secret, mbedtls_hash_size_for_ciphersuite(suite_info), (const unsigned char *)"resumption", strlen("resumption"), (const unsigned char *)&msg[9], MBEDTLS_SSL_TICKET_NONCE_LENGTH, mbedtls_hash_size_for_ciphersuite(suite_info), ssl->session->key, mbedtls_hash_size_for_ciphersuite(suite_info));

	if (ret != 0) {
		MBEDTLS_SSL_DEBUG_RET(2, "Creating the ticket-resumed PSK failed", ret);
		return (ret);
	}

	MBEDTLS_SSL_DEBUG_BUF(3, "Ticket-resumed PSK", ssl->session->key, mbedtls_hash_size_for_ciphersuite(suite_info));
	MBEDTLS_SSL_DEBUG_MSG(3, ("Key_len: %d", mbedtls_hash_size_for_ciphersuite(suite_info)));


#if defined(MBEDTLS_HAVE_TIME)
	// Store ticket creation time
	ssl->session->ticket_received = time(NULL); 
#endif 

	MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse new session ticket"));

	return(0);
}
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

/* mbedtls_ssl_conf_ke() allows to set the key exchange mode. */

int mbedtls_ssl_conf_ke(mbedtls_ssl_config *conf,
	const int key_exchange_mode)
{
	conf->key_exchange_modes = key_exchange_mode;
	return 0; 
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */


#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET) && defined(MBEDTLS_SSL_PROTO_TLS1_3)

/* mbedtls_ssl_conf_ticket_meta() allows to set a 32-bit value that is 
 * used to obscure the age of the ticket. For externally configured PSKs
 * this value is zero. Additionally, the time when the ticket was 
 * received will be set.
 */

int mbedtls_ssl_conf_ticket_meta(mbedtls_ssl_config *conf,
	const uint32_t ticket_age_add, 
	const time_t ticket_received)
{
	conf->ticket_age_add = ticket_age_add; 
#if defined(MBEDTLS_HAVE_TIME)
	conf->ticket_received = ticket_received; 
#endif /* MBEDTLS_HAVE_TIME */
	return 0;
}

#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET && MBEDTLS_SSL_PROTO_TLS1_3 */

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
int mbedtls_ssl_conf_psk( mbedtls_ssl_config *conf,
                const unsigned char *psk, size_t psk_len,
                const unsigned char *psk_identity, size_t psk_identity_len)
{
    if( psk == NULL || psk_identity == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    if( psk_len > MBEDTLS_PSK_MAX_LEN )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    /* Identity len will be encoded on two bytes */
    if( ( psk_identity_len >> 16 ) != 0 ||
        psk_identity_len > MBEDTLS_SSL_MAX_CONTENT_LEN )
    {
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    if( conf->psk != NULL || conf->psk_identity != NULL )
    {
        mbedtls_free( conf->psk );
        mbedtls_free( conf->psk_identity );
        conf->psk = NULL;
        conf->psk_identity = NULL;
    }

    if( ( conf->psk = mbedtls_calloc( 1, psk_len ) ) == NULL ||
        ( conf->psk_identity = mbedtls_calloc( 1, psk_identity_len ) ) == NULL )
    {
        mbedtls_free( conf->psk );
        mbedtls_free( conf->psk_identity );
        conf->psk = NULL;
        conf->psk_identity = NULL;
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    conf->psk_len = psk_len;
    conf->psk_identity_len = psk_identity_len;

    memcpy( conf->psk, psk, conf->psk_len );
    memcpy( conf->psk_identity, psk_identity, conf->psk_identity_len );
	// For externally configured PSKs we set the ticket_age_add value to 0
	conf->ticket_age_add = 0;
    return( 0 );
}

int mbedtls_ssl_set_hs_psk( mbedtls_ssl_context *ssl,
                            const unsigned char *psk, size_t psk_len )
{
    if( psk == NULL || ssl->handshake == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    if( psk_len > MBEDTLS_PSK_MAX_LEN )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    if( ssl->handshake->psk != NULL )
        mbedtls_free( ssl->handshake->psk );

    if( ( ssl->handshake->psk = mbedtls_calloc( 1, psk_len ) ) == NULL )
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );

    ssl->handshake->psk_len = psk_len;
    memcpy( ssl->handshake->psk, psk, ssl->handshake->psk_len );

    return( 0 );
}

void mbedtls_ssl_conf_psk_cb( mbedtls_ssl_config *conf,
                     int (*f_psk)(void *, mbedtls_ssl_context *, const unsigned char *,
                     size_t),
                     void *p_psk )
{
    conf->f_psk = f_psk;
    conf->p_psk = p_psk;
}
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_SSL_SRV_C)
int mbedtls_ssl_conf_dh_param( mbedtls_ssl_config *conf, const char *dhm_P, const char *dhm_G )
{
    int ret;

    if( ( ret = mbedtls_mpi_read_string( &conf->dhm_P, 16, dhm_P ) ) != 0 ||
        ( ret = mbedtls_mpi_read_string( &conf->dhm_G, 16, dhm_G ) ) != 0 )
    {
        mbedtls_mpi_free( &conf->dhm_P );
        mbedtls_mpi_free( &conf->dhm_G );
        return( ret );
    }

    return( 0 );
}

int mbedtls_ssl_conf_dh_param_ctx( mbedtls_ssl_config *conf, mbedtls_dhm_context *dhm_ctx )
{
    int ret;

    if( ( ret = mbedtls_mpi_copy( &conf->dhm_P, &dhm_ctx->P ) ) != 0 ||
        ( ret = mbedtls_mpi_copy( &conf->dhm_G, &dhm_ctx->G ) ) != 0 )
    {
        mbedtls_mpi_free( &conf->dhm_P );
        mbedtls_mpi_free( &conf->dhm_G );
        return( ret );
    }

    return( 0 );
}
#endif /* MBEDTLS_DHM_C && MBEDTLS_SSL_SRV_C */

#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_SSL_CLI_C)
/*
 * Set the minimum length for Diffie-Hellman parameters
 */
void mbedtls_ssl_conf_dhm_min_bitlen( mbedtls_ssl_config *conf,
                                      unsigned int bitlen )
{
    conf->dhm_min_bitlen = bitlen;
}
#endif /* MBEDTLS_DHM_C && MBEDTLS_SSL_CLI_C */

#if defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED) && !defined(MBEDTLS_SSL_PROTO_TLS1_3)
/*
 * Set allowed/preferred hashes for handshake signatures
 */
void mbedtls_ssl_conf_sig_hashes( mbedtls_ssl_config *conf,
                                  const int *hashes )
{
    conf->sig_hashes = hashes;
}
#endif /* MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED && !MBEDTLS_SSL_PROTO_TLS1_3 */

#if defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
/*
* Set allowed/preferred signature schemes for handshake signatures
*/
void mbedtls_ssl_conf_sig_hashes(mbedtls_ssl_config *conf,
	const int *signature_schemes)
{
	conf->signature_schemes = signature_schemes;
}
#endif /* MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED && !MBEDTLS_SSL_PROTO_TLS1_3 */




#if defined(MBEDTLS_ECP_C)
/*
 * Set the allowed elliptic curves
 */
void mbedtls_ssl_conf_curves( mbedtls_ssl_config *conf,
                             const mbedtls_ecp_group_id *curve_list )
{
    conf->curve_list = curve_list;
}
#endif

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
int mbedtls_ssl_set_hostname( mbedtls_ssl_context *ssl, const char *hostname )
{
    size_t hostname_len;

    if( hostname == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    hostname_len = strlen( hostname );

    if( hostname_len + 1 == 0 )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    if( hostname_len > MBEDTLS_SSL_MAX_HOST_NAME_LEN )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    ssl->hostname = mbedtls_calloc( 1, hostname_len + 1 );

    if( ssl->hostname == NULL )
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );

    memcpy( ssl->hostname, hostname, hostname_len );

    ssl->hostname[hostname_len] = '\0';

    return( 0 );
}
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
void mbedtls_ssl_conf_sni( mbedtls_ssl_config *conf,
                  int (*f_sni)(void *, mbedtls_ssl_context *,
                                const unsigned char *, size_t),
                  void *p_sni )
{
    conf->f_sni = f_sni;
    conf->p_sni = p_sni;
}
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(MBEDTLS_SSL_ALPN)
int mbedtls_ssl_conf_alpn_protocols( mbedtls_ssl_config *conf, const char **protos )
{
    size_t cur_len, tot_len;
    const char **p;

    /*
     * "Empty strings MUST NOT be included and byte strings MUST NOT be
     * truncated". Check lengths now rather than later.
     */
    tot_len = 0;
    for( p = protos; *p != NULL; p++ )
    {
        cur_len = strlen( *p );
        tot_len += cur_len;

        if( cur_len == 0 || cur_len > 255 || tot_len > 65535 )
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    conf->alpn_list = protos;

    return( 0 );
}

const char *mbedtls_ssl_get_alpn_protocol( const mbedtls_ssl_context *ssl )
{
    return( ssl->alpn_chosen );
}
#endif /* MBEDTLS_SSL_ALPN */

void mbedtls_ssl_conf_max_version( mbedtls_ssl_config *conf, int major, int minor )
{
    conf->max_major_ver = major;
    conf->max_minor_ver = minor;
}

void mbedtls_ssl_conf_min_version( mbedtls_ssl_config *conf, int major, int minor )
{
    conf->min_major_ver = major;
    conf->min_minor_ver = minor;
}

#if defined(MBEDTLS_SSL_FALLBACK_SCSV) && defined(MBEDTLS_SSL_CLI_C)
void mbedtls_ssl_conf_fallback( mbedtls_ssl_config *conf, char fallback )
{
    conf->fallback = fallback;
}
#endif

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
void mbedtls_ssl_conf_encrypt_then_mac( mbedtls_ssl_config *conf, char etm )
{
    conf->encrypt_then_mac = etm;
}
#endif

#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
void mbedtls_ssl_conf_extended_master_secret( mbedtls_ssl_config *conf, char ems )
{
    conf->extended_ms = ems;
}
#endif

#if defined(MBEDTLS_ARC4_C)
void mbedtls_ssl_conf_arc4_support( mbedtls_ssl_config *conf, char arc4 )
{
    conf->arc4_disabled = arc4;
}
#endif

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
int mbedtls_ssl_conf_max_frag_len( mbedtls_ssl_config *conf, unsigned char mfl_code )
{
    if( mfl_code >= MBEDTLS_SSL_MAX_FRAG_LEN_INVALID ||
        mfl_code_to_length[mfl_code] > MBEDTLS_SSL_MAX_CONTENT_LEN )
    {
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    conf->mfl_code = mfl_code;

    return( 0 );
}
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_SSL_TRUNCATED_HMAC)
void mbedtls_ssl_conf_truncated_hmac( mbedtls_ssl_config *conf, int truncate )
{
    conf->trunc_hmac = truncate;
}
#endif /* MBEDTLS_SSL_TRUNCATED_HMAC */

#if defined(MBEDTLS_SSL_CBC_RECORD_SPLITTING)
void mbedtls_ssl_conf_cbc_record_splitting( mbedtls_ssl_config *conf, char split )
{
    conf->cbc_record_splitting = split;
}
#endif

void mbedtls_ssl_conf_legacy_renegotiation( mbedtls_ssl_config *conf, int allow_legacy )
{
    conf->allow_legacy_renegotiation = allow_legacy;
}

#if defined(MBEDTLS_SSL_RENEGOTIATION)
void mbedtls_ssl_conf_renegotiation( mbedtls_ssl_config *conf, int renegotiation )
{
    conf->disable_renegotiation = renegotiation;
}

void mbedtls_ssl_conf_renegotiation_enforced( mbedtls_ssl_config *conf, int max_records )
{
    conf->renego_max_records = max_records;
}

void mbedtls_ssl_conf_renegotiation_period( mbedtls_ssl_config *conf,
                                   const unsigned char period[8] )
{
    memcpy( conf->renego_period, period, 8 );
}
#endif /* MBEDTLS_SSL_RENEGOTIATION */

#if defined(MBEDTLS_SSL_SESSION_TICKETS) || defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
#if defined(MBEDTLS_SSL_CLI_C)
void mbedtls_ssl_conf_session_tickets( mbedtls_ssl_config *conf, int use_tickets )
{
    conf->session_tickets = use_tickets;
}
#endif

#if defined(MBEDTLS_SSL_SRV_C)
void mbedtls_ssl_conf_session_tickets_cb( mbedtls_ssl_config *conf,
        mbedtls_ssl_ticket_write_t *f_ticket_write,
        mbedtls_ssl_ticket_parse_t *f_ticket_parse,
        void *p_ticket, int use_tickets)
{
    conf->f_ticket_write = f_ticket_write;
    conf->f_ticket_parse = f_ticket_parse;
    conf->p_ticket       = p_ticket;
	conf->session_tickets = use_tickets;
}
#endif
#endif /* MBEDTLS_SSL_SESSION_TICKETS || MBEDTLS_SSL_NEW_SESSION_TICKET */

#if defined(MBEDTLS_SSL_EXPORT_KEYS)
void mbedtls_ssl_conf_export_keys_cb( mbedtls_ssl_config *conf,
        mbedtls_ssl_export_keys_t *f_export_keys,
        void *p_export_keys )
{
    conf->f_export_keys = f_export_keys;
    conf->p_export_keys = p_export_keys;
}
#endif

/*
 * SSL get accessors
 */
size_t mbedtls_ssl_get_bytes_avail( const mbedtls_ssl_context *ssl )
{
    return( ssl->in_offt == NULL ? 0 : ssl->in_msglen );
}

uint32_t mbedtls_ssl_get_verify_result( const mbedtls_ssl_context *ssl )
{
    if( ssl->session != NULL )
        return( ssl->session->verify_result );

    if( ssl->session_negotiate != NULL )
        return( ssl->session_negotiate->verify_result );

    return( 0xFFFFFFFF );
}

const char *mbedtls_ssl_get_ciphersuite( const mbedtls_ssl_context *ssl )
{
    if( ssl == NULL || ssl->session == NULL )
        return( NULL );

    return mbedtls_ssl_get_ciphersuite_name( ssl->session->ciphersuite );
}

const char *mbedtls_ssl_get_version( const mbedtls_ssl_context *ssl )
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        switch( ssl->minor_ver )
        {
            case MBEDTLS_SSL_MINOR_VERSION_2:
                return( "DTLSv1.0" );

            case MBEDTLS_SSL_MINOR_VERSION_3:
                return( "DTLSv1.2" );

			case MBEDTLS_SSL_MINOR_VERSION_4:
				return("DTLSv1.3");

            default:
                return( "unknown (DTLS)" );
        }
    }
#endif

    switch( ssl->minor_ver )
    {
        case MBEDTLS_SSL_MINOR_VERSION_0:
            return( "SSLv3.0" );

        case MBEDTLS_SSL_MINOR_VERSION_1:
            return( "TLSv1.0" );

        case MBEDTLS_SSL_MINOR_VERSION_2:
            return( "TLSv1.1" );

        case MBEDTLS_SSL_MINOR_VERSION_3:
            return( "TLSv1.2" );

		case MBEDTLS_SSL_MINOR_VERSION_4:
			return("TLSv1.3");

        default:
            return( "unknown" );
    }
}

int mbedtls_ssl_get_record_expansion( const mbedtls_ssl_context *ssl )
{
    size_t transform_expansion;
    const mbedtls_ssl_transform *transform = ssl->transform_out;

#if defined(MBEDTLS_ZLIB_SUPPORT)
    if( ssl->session_out->compression != MBEDTLS_SSL_COMPRESS_NULL )
        return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
#endif

    if( transform == NULL )
        return( (int) mbedtls_ssl_hdr_len( ssl ) );

    switch( mbedtls_cipher_get_cipher_mode( &transform->cipher_ctx_enc ) )
    {
        case MBEDTLS_MODE_GCM:
        case MBEDTLS_MODE_CCM:
		case MBEDTLS_MODE_CCM_8:
        case MBEDTLS_MODE_STREAM:
            transform_expansion = transform->minlen;
            break;

        case MBEDTLS_MODE_CBC:
            transform_expansion = transform->maclen
                      + mbedtls_cipher_get_block_size( &transform->cipher_ctx_enc );
            break;

        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    return( (int)( mbedtls_ssl_hdr_len( ssl ) + transform_expansion ) );
}


#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
size_t mbedtls_ssl_get_max_frag_len( const mbedtls_ssl_context *ssl )
{
    size_t max_len;

    /*
     * Assume mfl_code is correct since it was checked when set
     */
    max_len = mfl_code_to_length[ssl->conf->mfl_code];

    /*
     * Check if a smaller max length was negotiated
     */
    if( ssl->session_out != NULL &&
        mfl_code_to_length[ssl->session_out->mfl_code] < max_len )
    {
        max_len = mfl_code_to_length[ssl->session_out->mfl_code];
    }

    return max_len;
}
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_SSL_NEW_SESSION_TICKET)

/*
* Init ticket structure
*/

void mbedtls_ssl_init_client_ticket(mbedtls_ssl_ticket *ticket)
{
	if (ticket == NULL)
		return;

	ticket->ticket = NULL;
	memset(ticket->key,0,sizeof(ticket->key));
}


/*
* Free an ticket structure
*/
void mbedtls_ssl_del_client_ticket(mbedtls_ssl_ticket *ticket)
{
	if (ticket == NULL)
		return;

	if (ticket->ticket != NULL)
	{
		mbedtls_zeroize(ticket->ticket, ticket->ticket_len);
		mbedtls_free(ticket->ticket);
	}

	mbedtls_zeroize(ticket->key, sizeof(ticket->key));
}

int mbedtls_ssl_conf_client_ticket(const mbedtls_ssl_context *ssl, mbedtls_ssl_ticket *ticket) {

	int ret; 
	mbedtls_ssl_config *conf = (mbedtls_ssl_config *) ssl->conf;
	
	// basic consistency checks 
	if (conf == NULL) return -1;
	if (ticket == NULL) return -1; 
	if (ticket->key_len == 0) return -1; 
	if (ticket->ticket_len == 0) return -1; 
	if (ticket->ticket == NULL) return -1; 

	/* We don't request another ticket from the server. 
	 * TBD: This function could be moved to an application-visible API call.
	 */
	mbedtls_ssl_conf_session_tickets(conf, 0);

	// Set the psk and psk_identity
	ret = mbedtls_ssl_conf_psk(conf, ticket->key, ticket->key_len,
		(const unsigned char *)ticket->ticket,
		ticket->ticket_len); 

	if (ret != 0) return -1; 

	/* Set the key exchange mode to PSK
	 * TBD: Ideally, the application developer should have the option 
	 * to decide between plain PSK-KE and PSK-KE-DH
	 */
	ret = mbedtls_ssl_conf_ke(conf, 0);

	if (ret != 0) return -1;

	/* We set the ticket_age_add and the time we received the ticket */
	ret = mbedtls_ssl_conf_ticket_meta(conf, ticket->ticket_age_add, ticket->start); 

	if (ret != 0) return -1;

	return 0; 
}

int mbedtls_ssl_get_client_ticket(const mbedtls_ssl_context *ssl, mbedtls_ssl_ticket *ticket)
{
	if (ssl->session == NULL) return -1; 

	// Check whether we got a ticket already
	if (ssl->session->ticket != NULL) {
		
		// store ticket
		ticket->ticket_len = ssl->session->ticket_len;
		if (ticket->ticket_len == 0) return -1;

		ticket->ticket = mbedtls_calloc(ticket->ticket_len,1);
		if (ticket->ticket == NULL) return -1;
		memcpy(ticket->ticket, ssl->session->ticket, ticket->ticket_len);

		// store ticket lifetime
		ticket->ticket_lifetime = ssl->session->ticket_lifetime;
		
		// store psk key and key length 
		ticket->key_len= mbedtls_hash_size_for_ciphersuite(mbedtls_ssl_ciphersuite_from_id(ssl->session->ciphersuite));
		memcpy(ticket->key, ssl->session->key, ticket->key_len); 
		ssl->session->key_len = ticket->key_len; 

		// store ticket_age_add
		ticket->ticket_age_add = ssl->session->ticket_age_add;

		// store time we received the ticket
		ticket->start = ssl->session->ticket_received; 

		return 0;
	} else return 1; 
}

void mbedtls_ssl_conf_client_ticket_enable(mbedtls_ssl_context *ssl)
{
	mbedtls_ssl_config *conf;
	if (ssl == NULL) return;
	conf = (mbedtls_ssl_config *) ssl->conf;
	if (conf == NULL) return;
	conf->resumption_mode = 1; // enable resumption mode 
}

void mbedtls_ssl_conf_client_ticket_disable(mbedtls_ssl_context *ssl)
{
	mbedtls_ssl_config *conf;

	if (ssl == NULL) return; 
	conf = (mbedtls_ssl_config *) ssl->conf;
	if (conf == NULL) return; 
	conf->resumption_mode = 0; // set full exchange 
}

#endif // MBEDTLS_SSL_PROTO_TLS1_3 && MBEDTLS_SSL_NEW_SESSION_TICKET 


#if defined(MBEDTLS_X509_CRT_PARSE_C)
const mbedtls_x509_crt *mbedtls_ssl_get_peer_cert( const mbedtls_ssl_context *ssl )
{
    if( ssl == NULL || ssl->session == NULL )
        return( NULL );

    return( ssl->session->peer_cert );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_SSL_CLI_C)
int mbedtls_ssl_get_session( const mbedtls_ssl_context *ssl, mbedtls_ssl_session *dst )
{
    if( ssl == NULL ||
        dst == NULL ||
        ssl->session == NULL ||
        ssl->conf->endpoint != MBEDTLS_SSL_IS_CLIENT )
    {
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    return( ssl_session_copy( dst, ssl->session ) );
}
#endif /* MBEDTLS_SSL_CLI_C */

/*
 * Perform a single step of the SSL handshake
 */
int mbedtls_ssl_handshake_step( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;

    if( ssl == NULL || ssl->conf == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
        ret = mbedtls_ssl_handshake_client_step( ssl );
#endif
#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
        ret = mbedtls_ssl_handshake_server_step( ssl );
#endif

    return( ret );
}

/*
 * Perform the SSL handshake
 */
int mbedtls_ssl_handshake( mbedtls_ssl_context *ssl )
{
    int ret = 0;

    if( ssl == NULL || ssl->conf == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> handshake" ) );

    while( ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER )
    {
        ret = mbedtls_ssl_handshake_step( ssl );

        if( ret != 0 )
            break;
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= handshake" ) );

    return( ret );
}

#if defined(MBEDTLS_SSL_RENEGOTIATION)
#if defined(MBEDTLS_SSL_SRV_C)
/*
 * Write HelloRequest to request renegotiation on server
 */
static int ssl_write_hello_request( mbedtls_ssl_context *ssl )
{
    int ret;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write hello request" ) );

    ssl->out_msglen  = 4;
    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = MBEDTLS_SSL_HS_HELLO_REQUEST;

    if( ( ret = mbedtls_ssl_write_record( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_record", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write hello request" ) );

    return( 0 );
}
#endif /* MBEDTLS_SSL_SRV_C */

/*
 * Actually renegotiate current connection, triggered by either:
 * - any side: calling mbedtls_ssl_renegotiate(),
 * - client: receiving a HelloRequest during mbedtls_ssl_read(),
 * - server: receiving any handshake message on server during mbedtls_ssl_read() after
 *   the initial handshake is completed.
 * If the handshake doesn't complete due to waiting for I/O, it will continue
 * during the next calls to mbedtls_ssl_renegotiate() or mbedtls_ssl_read() respectively.
 */
static int ssl_start_renegotiation( mbedtls_ssl_context *ssl )
{
    int ret;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> renegotiate" ) );

    if( ( ret = ssl_handshake_init( ssl ) ) != 0 )
        return( ret );

    /* RFC 6347 4.2.2: "[...] the HelloRequest will have message_seq = 0 and
     * the ServerHello will have message_seq = 1" */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_PENDING )
    {
        if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
            ssl->handshake->out_msg_seq = 1;
        else
            ssl->handshake->in_msg_seq = 1;
    }
#endif

    ssl->state = MBEDTLS_SSL_HELLO_REQUEST;
    ssl->renego_status = MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS;

    if( ( ret = mbedtls_ssl_handshake( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_handshake", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= renegotiate" ) );

    return( 0 );
}

/*
 * Renegotiate current connection on client,
 * or request renegotiation on server
 */
int mbedtls_ssl_renegotiate( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;

    if( ssl == NULL || ssl->conf == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

#if defined(MBEDTLS_SSL_SRV_C)
    /* On server, just send the request */
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        if( ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER )
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

        ssl->renego_status = MBEDTLS_SSL_RENEGOTIATION_PENDING;

        /* Did we already try/start sending HelloRequest? */
        if( ssl->out_left != 0 )
            return( mbedtls_ssl_flush_output( ssl ) );

        return( ssl_write_hello_request( ssl ) );
    }
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(MBEDTLS_SSL_CLI_C)
    /*
     * On client, either start the renegotiation process or,
     * if already in progress, continue the handshake
     */
    if( ssl->renego_status != MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS )
    {
        if( ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER )
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

        if( ( ret = ssl_start_renegotiation( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "ssl_start_renegotiation", ret );
            return( ret );
        }
    }
    else
    {
        if( ( ret = mbedtls_ssl_handshake( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_handshake", ret );
            return( ret );
        }
    }
#endif /* MBEDTLS_SSL_CLI_C */

    return( ret );
}

/*
 * Check record counters and renegotiate if they're above the limit.
 */
static int ssl_check_ctr_renegotiate( mbedtls_ssl_context *ssl )
{
    if( ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER ||
        ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_PENDING ||
        ssl->conf->disable_renegotiation == MBEDTLS_SSL_RENEGOTIATION_DISABLED )
    {
        return( 0 );
    }

    if( memcmp( ssl->in_ctr,  ssl->conf->renego_period, 8 ) <= 0 &&
        memcmp( ssl->out_ctr, ssl->conf->renego_period, 8 ) <= 0 )
    {
        return( 0 );
    }

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "record counter limit reached: renegotiate" ) );
    return( mbedtls_ssl_renegotiate( ssl ) );
}
#endif /* MBEDTLS_SSL_RENEGOTIATION */

/*
 * Receive application data decrypted from the SSL layer
 */
int mbedtls_ssl_read( mbedtls_ssl_context *ssl, unsigned char *buf, size_t len )
{
    int ret, record_read = 0;
    size_t n;

    if( ssl == NULL || ssl->conf == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> read" ) );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        if( ( ret = mbedtls_ssl_flush_output( ssl ) ) != 0 )
            return( ret );

        if( ssl->handshake != NULL &&
            ssl->handshake->retransmit_state == MBEDTLS_SSL_RETRANS_SENDING )
        {
            if( ( ret = mbedtls_ssl_resend( ssl ) ) != 0 )
                return( ret );
        }
    }
#endif

#if defined(MBEDTLS_SSL_RENEGOTIATION)
    if( ( ret = ssl_check_ctr_renegotiate( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "ssl_check_ctr_renegotiate", ret );
        return( ret );
    }
#endif

    if( ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER )
    {
        ret = mbedtls_ssl_handshake( ssl );
        if( ret == MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO )
        {
            record_read = 1;
        }
        else if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_handshake", ret );
            return( ret );
        }
    }

	if (ssl->in_offt == NULL)
	{
		/* Start timer if not already running */
		if (ssl->f_get_timer != NULL &&
			ssl->f_get_timer(ssl->p_timer) == -1)
		{
			ssl_set_timer(ssl, ssl->conf->read_timeout);
		}

		if (!record_read)
		{
			if ((ret = mbedtls_ssl_read_record(ssl)) != 0)
			{
				if (ret == MBEDTLS_ERR_SSL_CONN_EOF)
					return(0);

				if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
					return(0); 

				MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_read_record", ret);
				return(ret);
			}
		}

#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
		if (ssl->in_msglen == 0 &&
			ssl->in_msgtype == MBEDTLS_SSL_MSG_APPLICATION_DATA)
		{
			/*
			 * OpenSSL sends empty messages to randomize the IV
			 */
			if ((ret = mbedtls_ssl_read_record(ssl)) != 0)
			{
				if (ret == MBEDTLS_ERR_SSL_CONN_EOF)
					return(0);

				MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_read_record", ret);
				return(ret);
			}
		}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if defined(MBEDTLS_SSL_RENEGOTIATION)
        if( ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "received handshake message" ) );

#if defined(MBEDTLS_SSL_CLI_C)
            if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT &&
                ( ssl->in_msg[0] != MBEDTLS_SSL_HS_HELLO_REQUEST ||
                  ssl->in_hslen != mbedtls_ssl_hs_hdr_len( ssl ) ) )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "handshake received (not HelloRequest)" ) );

                /* With DTLS, drop the packet (probably from last handshake) */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
                if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
                    return( MBEDTLS_ERR_SSL_WANT_READ );
#endif
                return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
            }

            if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER &&
                ssl->in_msg[0] != MBEDTLS_SSL_HS_CLIENT_HELLO )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "handshake received (not ClientHello)" ) );

                /* With DTLS, drop the packet (probably from last handshake) */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
                if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
                    return( MBEDTLS_ERR_SSL_WANT_READ );
#endif
                return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
            }
#endif

            if( ssl->conf->disable_renegotiation == MBEDTLS_SSL_RENEGOTIATION_DISABLED ||
                ( ssl->secure_renegotiation == MBEDTLS_SSL_LEGACY_RENEGOTIATION &&
                  ssl->conf->allow_legacy_renegotiation ==
                                                MBEDTLS_SSL_LEGACY_NO_RENEGOTIATION ) )
            {
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "refusing renegotiation, sending alert" ) );

#if defined(MBEDTLS_SSL_PROTO_SSL3)
                if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 )
                {
                    /*
                     * SSLv3 does not have a "no_renegotiation" alert
                     */
                    if( ( ret = mbedtls_ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
                        return( ret );
                }
                else
#endif /* MBEDTLS_SSL_PROTO_SSL3 */
#if defined(MBEDTLS_SSL_PROTO_TLS1) || defined(MBEDTLS_SSL_PROTO_TLS1_1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_2) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_3)
                if( ssl->minor_ver >= MBEDTLS_SSL_MINOR_VERSION_1 )
                {
                    if( ( ret = mbedtls_ssl_send_alert_message( ssl,
                                    MBEDTLS_SSL_ALERT_LEVEL_WARNING,
                                    MBEDTLS_SSL_ALERT_MSG_NO_RENEGOTIATION ) ) != 0 )
                    {
                        return( ret );
                    }
                }
                else
#endif /* MBEDTLS_SSL_PROTO_TLS1 || MBEDTLS_SSL_PROTO_TLS1_1 ||
          MBEDTLS_SSL_PROTO_TLS1_2 || defined(MBEDTLS_SSL_PROTO_TLS1_3)*/
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
                    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
                }
            }
            else
            {
                /* DTLS clients need to know renego is server-initiated */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
                if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
                    ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
                {
                    ssl->renego_status = MBEDTLS_SSL_RENEGOTIATION_PENDING;
                }
#endif
                ret = ssl_start_renegotiation( ssl );
                if( ret == MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO )
                {
                    record_read = 1;
                }
                else if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "ssl_start_renegotiation", ret );
                    return( ret );
                }
            }

            /* If a non-handshake record was read during renego, fallthrough,
             * else tell the user they should call mbedtls_ssl_read() again */
            if( ! record_read )
                return( MBEDTLS_ERR_SSL_WANT_READ );
        }
        else if( ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_PENDING )
        {

            if( ssl->conf->renego_max_records >= 0 )
            {
                if( ++ssl->renego_records_seen > ssl->conf->renego_max_records )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "renegotiation requested, "
                                        "but not honored by client" ) );
                    return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
                }
            }
        }
#endif /* MBEDTLS_SSL_RENEGOTIATION */
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

        /* Fatal and closure alerts handled by mbedtls_ssl_read_record() */
        if( ssl->in_msgtype == MBEDTLS_SSL_MSG_ALERT )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "ignoring non-fatal non-closure alert" ) );
            return( MBEDTLS_ERR_SSL_WANT_READ );
        }

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
		/* Post-Handshake messages, like the NewSessionTicket message, appear after the finished
		* message was sent */
		if (ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE) {
			MBEDTLS_SSL_DEBUG_MSG(3, ("received handshake message"));

#if defined(MBEDTLS_SSL_CLI_C)
			if ((ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT) &&
				(ssl->in_hslen != mbedtls_ssl_hs_hdr_len(ssl)) &&
				(ssl->in_msg[0] == MBEDTLS_SSL_HS_NEW_SESSION_TICKET)) {
				MBEDTLS_SSL_DEBUG_MSG(3, ("NewSessionTicket received"));
				ret = ssl_parse_new_session_ticket(ssl);
			}
#endif /* MBEDTLS_SSL_CLI_C */
		} else 
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

        if( ssl->in_msgtype != MBEDTLS_SSL_MSG_APPLICATION_DATA )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad application data message" ) );
            return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        }

        ssl->in_offt = ssl->in_msg;

        /* We're going to return something now, cancel timer,
         * except if handshake (renegotiation) is in progress */
        if( ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER )
            ssl_set_timer( ssl, 0 );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
        /* If we requested renego but received AppData, resend HelloRequest.
         * Do it now, after setting in_offt, to avoid taking this branch
         * again if ssl_write_hello_request() returns WANT_WRITE */
#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_RENEGOTIATION)
        if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER &&
            ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_PENDING )
        {
            if( ( ret = ssl_resend_hello_request( ssl ) ) != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_resend_hello_request", ret );
                return( ret );
            }
        }
#endif /* MBEDTLS_SSL_SRV_C && MBEDTLS_SSL_RENEGOTIATION */
#endif
    }

    n = ( len < ssl->in_msglen )
        ? len : ssl->in_msglen;

    memcpy( buf, ssl->in_offt, n );
    ssl->in_msglen -= n;

    if( ssl->in_msglen == 0 )
        /* all bytes consumed  */
        ssl->in_offt = NULL;
    else
        /* more data available */
        ssl->in_offt += n;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= read" ) );

    return( (int) n );
}

/*
 * Send application data to be encrypted by the SSL layer,
 * taking care of max fragment length and buffer size
 */
static int ssl_write_real( mbedtls_ssl_context *ssl,
                           const unsigned char *buf, size_t len )
{
    int ret;
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    size_t max_len = mbedtls_ssl_get_max_frag_len( ssl );

	
    if( len > max_len )
    {
#if defined(MBEDTLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "fragment larger than the (negotiated) "
                                "maximum fragment length: %d > %d",
                                len, max_len ) );
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
        }
        else
#endif
            len = max_len;
    }
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

    if( ssl->out_left != 0 )
    {
        if( ( ret = mbedtls_ssl_flush_output( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_flush_output", ret );
            return( ret );
        }
    }
    else
    {      
        ssl->out_msgtype = MBEDTLS_SSL_MSG_APPLICATION_DATA;
        memcpy( ssl->out_msg, buf, len );

		/* Adding content type at the end of the data*/
		ssl->out_msg[len] = MBEDTLS_SSL_MSG_APPLICATION_DATA; 
		ssl->out_msglen = len + 1; 
		len++; 

        if( ( ret = mbedtls_ssl_write_record( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_record", ret );
            return( ret );
        }
    }

    return( (int) len );
}

/*
 * Write application data, doing 1/n-1 splitting if necessary.
 *
 * With non-blocking I/O, ssl_write_real() may return WANT_WRITE,
 * then the caller will call us again with the same arguments, so
 * remember wether we already did the split or not.
 */
#if defined(MBEDTLS_SSL_CBC_RECORD_SPLITTING)
static int ssl_write_split( mbedtls_ssl_context *ssl,
                            const unsigned char *buf, size_t len )
{
    int ret;

    if( ssl->conf->cbc_record_splitting ==
            MBEDTLS_SSL_CBC_RECORD_SPLITTING_DISABLED ||
        len <= 1 ||
        ssl->minor_ver > MBEDTLS_SSL_MINOR_VERSION_1 ||
        mbedtls_cipher_get_cipher_mode( &ssl->transform_out->cipher_ctx_enc )
                                != MBEDTLS_MODE_CBC )
    {
        return( ssl_write_real( ssl, buf, len ) );
    }

    if( ssl->split_done == 0 )
    {
        if( ( ret = ssl_write_real( ssl, buf, 1 ) ) <= 0 )
            return( ret );
        ssl->split_done = 1;
    }

    if( ( ret = ssl_write_real( ssl, buf + 1, len - 1 ) ) <= 0 )
        return( ret );
    ssl->split_done = 0;

    return( ret + 1 );
}
#endif /* MBEDTLS_SSL_CBC_RECORD_SPLITTING */


/* Early Data Extension
*
* struct {} Empty;
*
* struct {
*   select (Handshake.msg_type) {
*     case new_session_ticket:   uint32 max_early_data_size;
*     case client_hello:         Empty;
*     case encrypted_extensions: Empty;
*   };
* } EarlyDataIndication;
*/
#if defined(MBEDTLS_ZERO_RTT)
int ssl_write_early_data_ext(mbedtls_ssl_context *ssl,
	unsigned char *buf,
	size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + MBEDTLS_SSL_MAX_CONTENT_LEN;

#if defined(MBEDTLS_SSL_SRV_C)
	if (ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER)
	{
		if (ssl->conf->key_exchange_modes != KEY_EXCHANGE_MODE_PSK_KE ||
			ssl->conf->early_data == MBEDTLS_SSL_EARLY_DATA_DISABLED) {

			MBEDTLS_SSL_DEBUG_MSG(2, ("skip write early_data extension"));
			ssl->handshake->early_data = MBEDTLS_SSL_EARLY_DATA_OFF;
			return(0);
		}
	}
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(MBEDTLS_SSL_CLI_C)
	if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT)
	{
		if (ssl->conf->key_exchange_modes == KEY_EXCHANGE_MODE_ECDHE_ECDSA ||
			ssl->conf->early_data == MBEDTLS_SSL_EARLY_DATA_DISABLED) {

//			MBEDTLS_SSL_DEBUG_MSG(5, ("<= skip write early_data extension"));
			ssl->handshake->early_data = MBEDTLS_SSL_EARLY_DATA_OFF;
			return(0);
		}
	}
#endif /* MBEDTLS_SSL_CLI_C */

	if ((size_t)(end - p) < 4)
	{
		MBEDTLS_SSL_DEBUG_MSG(1, ("buffer too small"));
		return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
	}

#if defined(MBEDTLS_SSL_CLI_C)
	if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT)
	{
		MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, adding early_data extension"));
	}
#endif /* MBEDTLS_SSL_CLI_C */

#if defined(MBEDTLS_SSL_SRV_C)
	if (ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER)
	{
		MBEDTLS_SSL_DEBUG_MSG(3, ("server hello, adding early_data extension"));
	}
#endif /* MBEDTLS_SSL_SRV_C */

	ssl->handshake->early_data = MBEDTLS_SSL_EARLY_DATA_ON;

	// Write extension header 
	*p++ = (unsigned char)((MBEDTLS_TLS_EXT_EARLY_DATA >> 8) & 0xFF);
	*p++ = (unsigned char)((MBEDTLS_TLS_EXT_EARLY_DATA) & 0xFF);

	// Write total extension length
	*p++ = 0;
	*p++ = 0;

	*olen = 4;
	return 0;
}
#endif

/*
 * Write application data (public-facing wrapper)
 */
int mbedtls_ssl_write( mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len )
{
    int ret;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write" ) );

    if( ssl == NULL || ssl->conf == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

#if defined(MBEDTLS_SSL_RENEGOTIATION)
    if( ( ret = ssl_check_ctr_renegotiate( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "ssl_check_ctr_renegotiate", ret );
        return( ret );
    }
#endif

#if defined(MBEDTLS_ZERO_RTT)
	if ((ssl->handshake!= NULL) && (ssl->handshake->early_data == MBEDTLS_SSL_EARLY_DATA_OFF))
#endif	
	{
		if (ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER)
		{
			if ((ret = mbedtls_ssl_handshake(ssl)) != 0)
			{
				MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_handshake", ret);
				return(ret);
			}
		}
	}
#if defined(MBEDTLS_SSL_CBC_RECORD_SPLITTING)
    ret = ssl_write_split( ssl, buf, len );
#else
    ret = ssl_write_real( ssl, buf, len );
#endif

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write" ) );

    return( ret );
}

/*
 * Notify the peer that the connection is being closed
 */
int mbedtls_ssl_close_notify( mbedtls_ssl_context *ssl )
{
    int ret;

    if( ssl == NULL || ssl->conf == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write close notify" ) );

    if( ssl->out_left != 0 )
        return( mbedtls_ssl_flush_output( ssl ) );

    if( ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER )
    {
        if( ( ret = mbedtls_ssl_send_alert_message( ssl,
                        MBEDTLS_SSL_ALERT_LEVEL_WARNING,
                        MBEDTLS_SSL_ALERT_MSG_CLOSE_NOTIFY ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_send_alert_message", ret );
            return( ret );
        }
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write close notify" ) );

    return( 0 );
}

void mbedtls_ssl_transform_free( mbedtls_ssl_transform *transform )
{
    if( transform == NULL )
        return;

#if defined(MBEDTLS_ZLIB_SUPPORT)
    deflateEnd( &transform->ctx_deflate );
    inflateEnd( &transform->ctx_inflate );
#endif

    mbedtls_cipher_free( &transform->cipher_ctx_enc );
    mbedtls_cipher_free( &transform->cipher_ctx_dec );

    mbedtls_md_free( &transform->md_ctx_enc );
    mbedtls_md_free( &transform->md_ctx_dec );

    mbedtls_zeroize( transform, sizeof( mbedtls_ssl_transform ) );
}

#if defined(MBEDTLS_X509_CRT_PARSE_C)
static void ssl_key_cert_free( mbedtls_ssl_key_cert *key_cert )
{
    mbedtls_ssl_key_cert *cur = key_cert, *next;

    while( cur != NULL )
    {
        next = cur->next;
        mbedtls_free( cur );
        cur = next;
    }
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

void mbedtls_ssl_handshake_free( mbedtls_ssl_handshake_params *handshake )
{
    if( handshake == NULL )
        return;

#if defined(MBEDTLS_SSL_PROTO_SSL3) || defined(MBEDTLS_SSL_PROTO_TLS1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_1)
    mbedtls_md5_free(    &handshake->fin_md5  );
    mbedtls_sha1_free(   &handshake->fin_sha1 );
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_2) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if defined(MBEDTLS_SHA256_C)
    mbedtls_sha256_free(   &handshake->fin_sha256    );
#endif
#if defined(MBEDTLS_SHA512_C)
    mbedtls_sha512_free(   &handshake->fin_sha512    );
#endif
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 || defined(MBEDTLS_SSL_PROTO_TLS1_3)*/

#if defined(MBEDTLS_DHM_C)
    mbedtls_dhm_free( &handshake->dhm_ctx );
#endif
#if defined(MBEDTLS_ECDH_C)
    mbedtls_ecdh_free( &handshake->ecdh_ctx );
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    mbedtls_ecjpake_free( &handshake->ecjpake_ctx );
#if defined(MBEDTLS_SSL_CLI_C)
    mbedtls_free( handshake->ecjpake_cache );
    handshake->ecjpake_cache = NULL;
    handshake->ecjpake_cache_len = 0;
#endif
#endif

#if defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C)
    /* explicit void pointer cast for buggy MS compiler */
    mbedtls_free( (void *) handshake->curves );
#endif

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    if( handshake->psk != NULL )
    {
        mbedtls_zeroize( handshake->psk, handshake->psk_len );
        mbedtls_free( handshake->psk );
    }
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C) && \
    defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    /*
     * Free only the linked list wrapper, not the keys themselves
     * since the belong to the SNI callback
     */
    if( handshake->sni_key_cert != NULL )
    {
        mbedtls_ssl_key_cert *cur = handshake->sni_key_cert, *next;

        while( cur != NULL )
        {
            next = cur->next;
            mbedtls_free( cur );
            cur = next;
        }
    }
#endif /* MBEDTLS_X509_CRT_PARSE_C && MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    mbedtls_free( handshake->verify_cookie );
    mbedtls_free( handshake->hs_msg );
    ssl_flight_free( handshake->flight );
#endif

    mbedtls_zeroize( handshake, sizeof( mbedtls_ssl_handshake_params ) );
}

void mbedtls_ssl_session_free( mbedtls_ssl_session *session )
{
    if( session == NULL )
        return;

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if( session->peer_cert != NULL )
    {
        mbedtls_x509_crt_free( session->peer_cert );
        mbedtls_free( session->peer_cert );
    }
#endif

#if ( defined(MBEDTLS_SSL_SESSION_TICKETS) || defined(MBEDTLS_SSL_NEW_SESSION_TICKET) ) && defined(MBEDTLS_SSL_CLI_C)
    if (session->ticket!=NULL) mbedtls_free( session->ticket );
	if (session->ticket_nonce_len>0) mbedtls_free(session->ticket_nonce);
#endif /* ( MBEDTLS_SSL_SESSION_TICKETS) || MBEDTLS_SSL_NEW_SESSION_TICKET ) && MBEDTLS_SSL_CLI_C */

    mbedtls_zeroize( session, sizeof( mbedtls_ssl_session ) );
}

/*
 * Free an SSL context
 */
void mbedtls_ssl_free( mbedtls_ssl_context *ssl )
{
    if( ssl == NULL )
        return;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> free" ) );

    if( ssl->out_buf != NULL )
    {
        mbedtls_zeroize( ssl->out_buf, MBEDTLS_SSL_BUFFER_LEN );
        mbedtls_free( ssl->out_buf );
    }

    if( ssl->in_buf != NULL )
    {
        mbedtls_zeroize( ssl->in_buf, MBEDTLS_SSL_BUFFER_LEN );
        mbedtls_free( ssl->in_buf );
    }

#if defined(MBEDTLS_ZLIB_SUPPORT)
    if( ssl->compress_buf != NULL )
    {
        mbedtls_zeroize( ssl->compress_buf, MBEDTLS_SSL_BUFFER_LEN );
        mbedtls_free( ssl->compress_buf );
    }
#endif

    if( ssl->transform )
    {
        mbedtls_ssl_transform_free( ssl->transform );
        mbedtls_free( ssl->transform );
    }

    if( ssl->handshake )
    {
        mbedtls_ssl_handshake_free( ssl->handshake );
        mbedtls_ssl_transform_free( ssl->transform_negotiate );
        mbedtls_ssl_session_free( ssl->session_negotiate );

        mbedtls_free( ssl->handshake );
        mbedtls_free( ssl->transform_negotiate );
        mbedtls_free( ssl->session_negotiate );
    }

    if( ssl->session )
    {
        mbedtls_ssl_session_free( ssl->session );
        mbedtls_free( ssl->session );
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if( ssl->hostname != NULL )
    {
        mbedtls_zeroize( ssl->hostname, strlen( ssl->hostname ) );
        mbedtls_free( ssl->hostname );
    }
#endif

#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
    if( mbedtls_ssl_hw_record_finish != NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "going for mbedtls_ssl_hw_record_finish()" ) );
        mbedtls_ssl_hw_record_finish( ssl );
    }
#endif

#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(MBEDTLS_SSL_SRV_C)
    mbedtls_free( ssl->cli_id );
#endif

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= free" ) );

    /* Actually clear after last debug message */
    mbedtls_zeroize( ssl, sizeof( mbedtls_ssl_context ) );
}

/*
 * Initialze mbedtls_ssl_config
 */
void mbedtls_ssl_config_init( mbedtls_ssl_config *conf )
{
    memset( conf, 0, sizeof( mbedtls_ssl_config ) );
}

#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
static int ssl_preset_suiteb_ciphersuites[] = {
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    0
};
#else 
static int ssl_preset_suiteb_ciphersuites[] = {
	TLS_AES_128_GCM_SHA256,
	TLS_AES_256_GCM_SHA384,
	0
};
#endif /* !MBEDTLS_SSL_PROTO_TLS1_3 */

#if defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED) && !defined(MBEDTLS_SSL_PROTO_TLS1_3)
static int ssl_preset_suiteb_hashes[] = {
    MBEDTLS_MD_SHA256,
    MBEDTLS_MD_SHA384,
    MBEDTLS_MD_NONE
};
#endif

#if defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
static int ssl_preset_signature_schemes[] = {
#if defined(MBEDTLS_ECDSA_SECP256r1_SHA256)
	SIGNATURE_ECDSA_SECP256r1_SHA256,
#endif
#if defined(MBEDTLS_ECDSA_SECP384r1_SHA384)
	SIGNATURE_ECDSA_SECP384r1_SHA384,
#endif
#if defined(MBEDTLS_ECDSA_SECP521r1_SHA512)
	SIGNATURE_ECDSA_SECP521r1_SHA512,
#endif
	SIGNATURE_NONE
};
#endif


#if defined(MBEDTLS_ECP_C)
static mbedtls_ecp_group_id ssl_preset_suiteb_curves[] = {
    MBEDTLS_ECP_DP_SECP256R1,
    MBEDTLS_ECP_DP_SECP384R1,
    MBEDTLS_ECP_DP_NONE
};
#endif

/*
 * Load default in mbedtls_ssl_config
 */
int mbedtls_ssl_config_defaults( mbedtls_ssl_config *conf,
                                 int endpoint, int transport, int preset )
{
#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_SSL_SRV_C)
    int ret;
#endif

    /* Use the functions here so that they are covered in tests,
     * but otherwise access member directly for efficiency */
    mbedtls_ssl_conf_endpoint( conf, endpoint );
    mbedtls_ssl_conf_transport( conf, transport );

    /*
     * Things that are common to all presets
     */
#if defined(MBEDTLS_SSL_CLI_C)
    if( endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        conf->authmode = MBEDTLS_SSL_VERIFY_REQUIRED;
#if defined(MBEDTLS_SSL_SESSION_TICKETS) || defined (MBEDTLS_SSL_NEW_SESSION_TICKET)
        conf->session_tickets = MBEDTLS_SSL_SESSION_TICKETS_ENABLED;
#endif /* MBEDTLS_SSL_SESSION_TICKETS || MBEDTLS_SSL_NEW_SESSION_TICKET */
    }
#endif /* MBEDTLS_SSL_CLI_C */

#if defined(MBEDTLS_ARC4_C)
    conf->arc4_disabled = MBEDTLS_SSL_ARC4_DISABLED;
#endif

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    conf->encrypt_then_mac = MBEDTLS_SSL_ETM_ENABLED;
#endif

#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    conf->extended_ms = MBEDTLS_SSL_EXTENDED_MS_ENABLED;
#endif

#if defined(MBEDTLS_SSL_CBC_RECORD_SPLITTING)
    conf->cbc_record_splitting = MBEDTLS_SSL_CBC_RECORD_SPLITTING_ENABLED;
#endif

#if !defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(MBEDTLS_SSL_SRV_C)
    conf->f_cookie_write = ssl_cookie_write_dummy;
    conf->f_cookie_check = ssl_cookie_check_dummy;
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_SSL_SRV_C)
    conf->f_cookie_write = ssl_cookie_write_dummy;
    conf->f_cookie_check = ssl_cookie_check_dummy;
#endif 

#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    conf->anti_replay = MBEDTLS_SSL_ANTI_REPLAY_ENABLED;
#endif

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
	conf->psk = NULL;
	conf->psk_identity = NULL;
	conf->psk_identity_len = 0;
	conf->psk_len = 0; 
#endif 

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    conf->hs_timeout_min = MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MIN;
    conf->hs_timeout_max = MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MAX;
#endif

#if defined(MBEDTLS_SSL_RENEGOTIATION)
    conf->renego_max_records = MBEDTLS_SSL_RENEGO_MAX_RECORDS_DEFAULT;
    memset( conf->renego_period, 0xFF, 7 );
    conf->renego_period[7] = 0x00;
#endif

#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_SSL_SRV_C)
            if( endpoint == MBEDTLS_SSL_IS_SERVER )
            {
                if( ( ret = mbedtls_ssl_conf_dh_param( conf,
                                MBEDTLS_DHM_RFC5114_MODP_2048_P,
                                MBEDTLS_DHM_RFC5114_MODP_2048_G ) ) != 0 )
                {
                    return( ret );
                }
            }
#endif

    /*
     * Preset-specific defaults
     */
    switch( preset )
    {
        /*
         * NSA Suite B
         */
        case MBEDTLS_SSL_PRESET_SUITEB:
            conf->min_major_ver = MBEDTLS_SSL_MAJOR_VERSION_3;
            conf->min_minor_ver = MBEDTLS_SSL_MINOR_VERSION_3; /* TLS 1.2 */
            conf->max_major_ver = MBEDTLS_SSL_MAX_MAJOR_VERSION;
            conf->max_minor_ver = MBEDTLS_SSL_MAX_MINOR_VERSION;

            conf->ciphersuite_list[MBEDTLS_SSL_MINOR_VERSION_0] =
            conf->ciphersuite_list[MBEDTLS_SSL_MINOR_VERSION_1] =
            conf->ciphersuite_list[MBEDTLS_SSL_MINOR_VERSION_2] =
			conf->ciphersuite_list[MBEDTLS_SSL_MINOR_VERSION_3] =
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
			conf->ciphersuite_list[MBEDTLS_SSL_MINOR_VERSION_4] =
#endif
                                   ssl_preset_suiteb_ciphersuites;

#if defined(MBEDTLS_X509_CRT_PARSE_C)
            conf->cert_profile = &mbedtls_x509_crt_profile_suiteb;
#endif

#if defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)  && !defined(MBEDTLS_SSL_PROTO_TLS1_3)
            conf->sig_hashes = ssl_preset_suiteb_hashes;
#endif

#if defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)  && defined(MBEDTLS_SSL_PROTO_TLS1_3)
			/* This isn't really NSA Suite B since TLS 1.3 works a bit differently than TLS 1.2 */
			conf->signature_schemes = ssl_preset_signature_schemes;
#endif

#if defined(MBEDTLS_ECP_C)
            conf->curve_list = ssl_preset_suiteb_curves;
#endif
            break;

        /*
         * Default
         */
        default:
            conf->min_major_ver = MBEDTLS_SSL_MAJOR_VERSION_3;
            conf->min_minor_ver = MBEDTLS_SSL_MINOR_VERSION_1; /* TLS 1.0 */
            conf->max_major_ver = MBEDTLS_SSL_MAX_MAJOR_VERSION;
            conf->max_minor_ver = MBEDTLS_SSL_MAX_MINOR_VERSION;

#if defined(MBEDTLS_SSL_PROTO_DTLS)
            if( transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
                conf->min_minor_ver = MBEDTLS_SSL_MINOR_VERSION_2;
#endif

            conf->ciphersuite_list[MBEDTLS_SSL_MINOR_VERSION_0] =
            conf->ciphersuite_list[MBEDTLS_SSL_MINOR_VERSION_1] =
            conf->ciphersuite_list[MBEDTLS_SSL_MINOR_VERSION_2] =
            conf->ciphersuite_list[MBEDTLS_SSL_MINOR_VERSION_3] =
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
			conf->ciphersuite_list[MBEDTLS_SSL_MINOR_VERSION_4] = 
#endif
				mbedtls_ssl_list_ciphersuites();

#if defined(MBEDTLS_X509_CRT_PARSE_C)
            conf->cert_profile = &mbedtls_x509_crt_profile_default;
#endif

#if defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)  && !defined(MBEDTLS_SSL_PROTO_TLS1_3)
			conf->sig_hashes = mbedtls_md_list();
#endif

#if defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)  && defined(MBEDTLS_SSL_PROTO_TLS1_3)
			conf->signature_schemes = ssl_preset_signature_schemes;
#endif

#if defined(MBEDTLS_ECP_C)
            conf->curve_list = mbedtls_ecp_grp_id_list();
#endif

#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_SSL_CLI_C)
            conf->dhm_min_bitlen = 1024;
#endif
    }

    return( 0 );
}

/*
 * Free mbedtls_ssl_config
 */
void mbedtls_ssl_config_free( mbedtls_ssl_config *conf )
{
#if defined(MBEDTLS_DHM_C)
    mbedtls_mpi_free( &conf->dhm_P );
    mbedtls_mpi_free( &conf->dhm_G );
#endif

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    if( conf->psk != NULL )
    {
        mbedtls_zeroize( conf->psk, conf->psk_len );
        mbedtls_zeroize( conf->psk_identity, conf->psk_identity_len );
        mbedtls_free( conf->psk );
        mbedtls_free( conf->psk_identity );
        conf->psk_len = 0;
        conf->psk_identity_len = 0;
    }
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    ssl_key_cert_free( conf->key_cert );
#endif

    mbedtls_zeroize( conf, sizeof( mbedtls_ssl_config ) );
}

#if defined(MBEDTLS_PK_C) && \
    ( defined(MBEDTLS_RSA_C) || defined(MBEDTLS_ECDSA_C) )
/*
 * Convert between MBEDTLS_PK_XXX and SSL_SIG_XXX
 */
unsigned char mbedtls_ssl_sig_from_pk( mbedtls_pk_context *pk )
{
#if defined(MBEDTLS_RSA_C)
    if( mbedtls_pk_can_do( pk, MBEDTLS_PK_RSA ) )
        return( MBEDTLS_SSL_SIG_RSA );
#endif
#if defined(MBEDTLS_ECDSA_C)
    if( mbedtls_pk_can_do( pk, MBEDTLS_PK_ECDSA ) )
        return( MBEDTLS_SSL_SIG_ECDSA );
#endif
    return( MBEDTLS_SSL_SIG_ANON );
}

mbedtls_pk_type_t mbedtls_ssl_pk_alg_from_sig( unsigned char sig )
{
    switch( sig )
    {
#if defined(MBEDTLS_RSA_C)
        case MBEDTLS_SSL_SIG_RSA:
            return( MBEDTLS_PK_RSA );
#endif
#if defined(MBEDTLS_ECDSA_C)
        case MBEDTLS_SSL_SIG_ECDSA:
            return( MBEDTLS_PK_ECDSA );
#endif
        default:
            return( MBEDTLS_PK_NONE );
    }
}
#endif /* MBEDTLS_PK_C && ( MBEDTLS_RSA_C || MBEDTLS_ECDSA_C ) */

/*
 * Convert from MBEDTLS_SSL_HASH_XXX to MBEDTLS_MD_XXX
 */
mbedtls_md_type_t mbedtls_ssl_md_alg_from_hash( unsigned char hash )
{
    switch( hash )
    {
#if defined(MBEDTLS_MD5_C)
        case MBEDTLS_SSL_HASH_MD5:
            return( MBEDTLS_MD_MD5 );
#endif
#if defined(MBEDTLS_SHA1_C)
        case MBEDTLS_SSL_HASH_SHA1:
            return( MBEDTLS_MD_SHA1 );
#endif
#if defined(MBEDTLS_SHA256_C)
        case MBEDTLS_SSL_HASH_SHA224:
            return( MBEDTLS_MD_SHA224 );
        case MBEDTLS_SSL_HASH_SHA256:
            return( MBEDTLS_MD_SHA256 );
#endif
#if defined(MBEDTLS_SHA512_C)
        case MBEDTLS_SSL_HASH_SHA384:
            return( MBEDTLS_MD_SHA384 );
        case MBEDTLS_SSL_HASH_SHA512:
            return( MBEDTLS_MD_SHA512 );
#endif
        default:
            return( MBEDTLS_MD_NONE );
    }
}

/*
 * Convert from MBEDTLS_MD_XXX to MBEDTLS_SSL_HASH_XXX
 */
unsigned char mbedtls_ssl_hash_from_md_alg( int md )
{
    switch( md )
    {
#if defined(MBEDTLS_MD5_C)
        case MBEDTLS_MD_MD5:
            return( MBEDTLS_SSL_HASH_MD5 );
#endif
#if defined(MBEDTLS_SHA1_C)
        case MBEDTLS_MD_SHA1:
            return( MBEDTLS_SSL_HASH_SHA1 );
#endif
#if defined(MBEDTLS_SHA256_C)
        case MBEDTLS_MD_SHA224:
            return( MBEDTLS_SSL_HASH_SHA224 );
        case MBEDTLS_MD_SHA256:
            return( MBEDTLS_SSL_HASH_SHA256 );
#endif
#if defined(MBEDTLS_SHA512_C)
        case MBEDTLS_MD_SHA384:
            return( MBEDTLS_SSL_HASH_SHA384 );
        case MBEDTLS_MD_SHA512:
            return( MBEDTLS_SSL_HASH_SHA512 );
#endif
        default:
            return( MBEDTLS_SSL_HASH_NONE );
    }
}

#if defined(MBEDTLS_ECP_C)
/*
 * Check if a curve proposed by the peer is in our list.
 * Return 0 if we're willing to use it, -1 otherwise.
 */
int mbedtls_ssl_check_curve( const mbedtls_ssl_context *ssl, mbedtls_ecp_group_id grp_id )
{
    const mbedtls_ecp_group_id *gid;

    if( ssl->conf->curve_list == NULL )
        return( -1 );

    for( gid = ssl->conf->curve_list; *gid != MBEDTLS_ECP_DP_NONE; gid++ )
        if( *gid == grp_id )
            return( 0 );

    return( -1 );
}
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED) && !defined(MBEDTLS_SSL_PROTO_TLS1_3)
/*
 * Check if a hash proposed by the peer is in our list.
 * Return 0 if we're willing to use it, -1 otherwise.
 */
int mbedtls_ssl_check_sig_hash( const mbedtls_ssl_context *ssl,
                                mbedtls_md_type_t md )
{
    const int *cur;

    if( ssl->conf->sig_hashes == NULL )
        return( -1 );

    for( cur = ssl->conf->sig_hashes; *cur != MBEDTLS_MD_NONE; cur++ )
        if( *cur == (int) md )
            return( 0 );

    return( -1 );
}
#endif /* MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED && !MBEDTLS_SSL_PROTO_TLS1_3 */


#if defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
/*
* Check if a signature scheme proposed by the peer is in our list.
* Return 0 if we're willing to use it, -1 otherwise.
*/
int mbedtls_ssl_check_signature_scheme(const mbedtls_ssl_context *ssl,
	int signature_scheme)
{
	const int *cur;

	if (ssl->conf->signature_schemes == NULL)
		return(-1);

	for (cur = ssl->conf->signature_schemes; *cur != SIGNATURE_NONE; cur++)
		if (*cur == signature_scheme)
			return(0);

	return(-1);
}
#endif /* MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED && MBEDTLS_SSL_PROTO_TLS1_3 */

#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
int mbedtls_ssl_check_cert_usage(const mbedtls_x509_crt *cert,
	const mbedtls_key_exchange_type_t key_exchange,
	int cert_endpoint,
	uint32_t *flags)
#else 
int mbedtls_ssl_check_cert_usage( const mbedtls_x509_crt *cert,
                          const mbedtls_ssl_ciphersuite_t *ciphersuite,
                          int cert_endpoint,
                          uint32_t *flags )
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

{
    int ret = 0;
#if defined(MBEDTLS_X509_CHECK_KEY_USAGE)
    int usage = 0;
#endif
#if defined(MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE)
    const char *ext_oid;
    size_t ext_len;
#endif

#if !defined(MBEDTLS_X509_CHECK_KEY_USAGE) &&          \
    !defined(MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE)
    ((void) cert);
    ((void) cert_endpoint);
    ((void) flags);
#endif

#if defined(MBEDTLS_X509_CHECK_KEY_USAGE)
    if( cert_endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        /* Server part of the key exchange */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
        switch(key_exchange)
#else 
        switch(ciphersuite->key_exchange)
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

        {
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
            case MBEDTLS_KEY_EXCHANGE_RSA:
            case MBEDTLS_KEY_EXCHANGE_RSA_PSK:
                usage = MBEDTLS_X509_KU_KEY_ENCIPHERMENT;
                break;

            case MBEDTLS_KEY_EXCHANGE_DHE_RSA:
            case MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
#endif /* !MBEDTLS_SSL_PROTO_TLS1_3 */
            case MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
                usage = MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
                break;
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
            case MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
            case MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
                usage = MBEDTLS_X509_KU_KEY_AGREEMENT;
                break;
#endif /* !MBEDTLS_SSL_PROTO_TLS1_3 */
            /* Don't use default: we want warnings when adding new values */
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
            case MBEDTLS_KEY_EXCHANGE_NONE:
            case MBEDTLS_KEY_EXCHANGE_PSK:
            case MBEDTLS_KEY_EXCHANGE_DHE_PSK:
            case MBEDTLS_KEY_EXCHANGE_ECJPAKE:
#endif /* !MBEDTLS_SSL_PROTO_TLS1_3 */
            case MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
                usage = 0;
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
            case MBEDTLS_KEY_EXCHANGE_NONE: 
                return -1; 
            case MBEDTLS_KEY_EXCHANGE_PSK: 
                return -1; 
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */            
        }
    }
    else
    {
        /* Client auth: we only implement rsa_sign and mbedtls_ecdsa_sign for now */
        usage = MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
    }

    if( mbedtls_x509_crt_check_key_usage( cert, usage ) != 0 )
    {
        *flags |= MBEDTLS_X509_BADCERT_KEY_USAGE;
        ret = -1;
    }
#else
    ((void) ciphersuite);
#endif /* MBEDTLS_X509_CHECK_KEY_USAGE */

#if defined(MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE)
    if( cert_endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        ext_oid = MBEDTLS_OID_SERVER_AUTH;
        ext_len = MBEDTLS_OID_SIZE( MBEDTLS_OID_SERVER_AUTH );
    }
    else
    {
        ext_oid = MBEDTLS_OID_CLIENT_AUTH;
        ext_len = MBEDTLS_OID_SIZE( MBEDTLS_OID_CLIENT_AUTH );
    }

    if( mbedtls_x509_crt_check_extended_key_usage( cert, ext_oid, ext_len ) != 0 )
    {
        *flags |= MBEDTLS_X509_BADCERT_EXT_KEY_USAGE;
        ret = -1;
    }
#endif /* MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE */

    return( ret );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

/*
 * Convert version numbers to/from wire format
 * and, for DTLS, to/from TLS equivalent.
 *
 * For TLS this is the identity.
 * For DTLS, use one complement (v -> 255 - v, and then map as follows:
 * 1.0 <-> 3.2      (DTLS 1.0 is based on TLS 1.1)
 * 1.x <-> 3.x+1    for x != 0 (DTLS 1.2 based on TLS 1.2)
 */
void mbedtls_ssl_write_version( int major, int minor, int transport,
                        unsigned char ver[2] )
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        if( minor == MBEDTLS_SSL_MINOR_VERSION_2 )
            --minor; /* DTLS 1.0 stored as TLS 1.1 internally */

        ver[0] = (unsigned char)( 255 - ( major - 2 ) );
        ver[1] = (unsigned char)( 255 - ( minor - 1 ) );
    }
    else
#else
    ((void) transport);
#endif
    {
		ver[0] = (unsigned char) major;
        ver[1] = (unsigned char) minor;
	}
}

void mbedtls_ssl_read_version( int *major, int *minor, int transport,
                       const unsigned char ver[2] )
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        *major = 255 - ver[0] + 2;
        *minor = 255 - ver[1] + 1;

        if( *minor == MBEDTLS_SSL_MINOR_VERSION_1 )
            ++*minor; /* DTLS 1.0 stored as TLS 1.1 internally */
    }
    else
#else
    ((void) transport);
#endif
    {
        *major = ver[0];
        *minor = ver[1];
    }
}

#endif /* MBEDTLS_SSL_TLS_C */
