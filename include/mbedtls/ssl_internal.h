/**
 * \file ssl_internal.h
 *
 * \brief Internal functions shared by the SSL modules
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
#ifndef MBEDTLS_SSL_INTERNAL_H
#define MBEDTLS_SSL_INTERNAL_H

#include "ssl.h"
#include "mbedtls/hkdf-tls.h"

#if defined(MBEDTLS_MD5_C)
#include "md5.h"
#endif

#if defined(MBEDTLS_SHA1_C)
#include "sha1.h"
#endif

#if defined(MBEDTLS_SHA256_C)
#include "sha256.h"
#endif

#if defined(MBEDTLS_SHA512_C)
#include "sha512.h"
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
#include "ecjpake.h"
#endif

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

/* Determine minimum supported version */
#define MBEDTLS_SSL_MIN_MAJOR_VERSION           MBEDTLS_SSL_MAJOR_VERSION_3

#if defined(MBEDTLS_SSL_PROTO_SSL3)
#define MBEDTLS_SSL_MIN_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_0
#else
#if defined(MBEDTLS_SSL_PROTO_TLS1)
#define MBEDTLS_SSL_MIN_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_1
#else
#if defined(MBEDTLS_SSL_PROTO_TLS1_1)
#define MBEDTLS_SSL_MIN_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_2
#else
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#define MBEDTLS_SSL_MIN_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_3
#else 
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#define MBEDTLS_SSL_MIN_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_4
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_SSL_PROTO_TLS1_1 */
#endif /* MBEDTLS_SSL_PROTO_TLS1   */
#endif /* MBEDTLS_SSL_PROTO_SSL3   */

/* Determine maximum supported version */
#define MBEDTLS_SSL_MAX_MAJOR_VERSION           MBEDTLS_SSL_MAJOR_VERSION_3

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#define MBEDTLS_SSL_MAX_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_3
#else
#if defined(MBEDTLS_SSL_PROTO_TLS1_1)
#define MBEDTLS_SSL_MAX_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_2
#else
#if defined(MBEDTLS_SSL_PROTO_TLS1)
#define MBEDTLS_SSL_MAX_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_1
#else
#if defined(MBEDTLS_SSL_PROTO_SSL3)
#define MBEDTLS_SSL_MAX_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_0
#endif /* MBEDTLS_SSL_PROTO_SSL3   */
#endif /* MBEDTLS_SSL_PROTO_TLS1   */
#endif /* MBEDTLS_SSL_PROTO_TLS1_1 */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

#define MBEDTLS_SSL_INITIAL_HANDSHAKE           0
#define MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS   1   /* In progress */
#define MBEDTLS_SSL_RENEGOTIATION_DONE          2   /* Done or aborted */
#define MBEDTLS_SSL_RENEGOTIATION_PENDING       3   /* Requested (server only) */

/*
 * DTLS retransmission states, see RFC 6347 4.2.4
 *
 * The SENDING state is merged in PREPARING for initial sends,
 * but is distinct for resends.
 *
 * Note: initial state is wrong for server, but is not used anyway.
 */
#define MBEDTLS_SSL_RETRANS_PREPARING       0
#define MBEDTLS_SSL_RETRANS_SENDING         1
#define MBEDTLS_SSL_RETRANS_WAITING         2
#define MBEDTLS_SSL_RETRANS_FINISHED        3

/*
 * Allow extra bytes for record, authentication and encryption overhead:
 * counter (8) + header (5) + IV(16) + MAC (16-48) + padding (0-256)
 * and allow for a maximum of 1024 of compression expansion if
 * enabled.
 */
#if defined(MBEDTLS_ZLIB_SUPPORT)
#define MBEDTLS_SSL_COMPRESSION_ADD          1024
#else
#define MBEDTLS_SSL_COMPRESSION_ADD             0
#endif

#if defined(MBEDTLS_ARC4_C) || defined(MBEDTLS_CIPHER_MODE_CBC)
/* Ciphersuites using HMAC */
#if defined(MBEDTLS_SHA512_C)
#define MBEDTLS_SSL_MAC_ADD                 48  /* SHA-384 used for HMAC */
#elif defined(MBEDTLS_SHA256_C)
#define MBEDTLS_SSL_MAC_ADD                 32  /* SHA-256 used for HMAC */
#else
#define MBEDTLS_SSL_MAC_ADD                 20  /* SHA-1   used for HMAC */
#endif
#else
/* AEAD ciphersuites: GCM and CCM use a 128 bits tag */
#define MBEDTLS_SSL_MAC_ADD                 16
#endif

#if defined(MBEDTLS_CIPHER_MODE_CBC)
#define MBEDTLS_SSL_PADDING_ADD            256
#else
#define MBEDTLS_SSL_PADDING_ADD              0
#endif

#define MBEDTLS_SSL_BUFFER_LEN  ( MBEDTLS_SSL_MAX_CONTENT_LEN               \
                        + MBEDTLS_SSL_COMPRESSION_ADD               \
                        + 29 /* counter + header + IV */    \
                        + MBEDTLS_SSL_MAC_ADD                       \
                        + MBEDTLS_SSL_PADDING_ADD                   \
                        )

/*
 * TLS extension flags (for extensions with outgoing ServerHello content
 * that need it (e.g. for RENEGOTIATION_INFO the server already knows because
 * of state of the renegotiation flag, so no indicator is required)
 */
#define MBEDTLS_TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT (1 << 0)
#define MBEDTLS_TLS_EXT_ECJPAKE_KKPP_OK                 (1 << 1)

#ifdef __cplusplus
extern "C" {
#endif



/*
 * This structure contains the parameters only needed during handshake.
 */
struct mbedtls_ssl_handshake_params
{
    /*
     * Handshake specific crypto variables
     */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
	int signature_scheme;                        /*!<  Signature scheme  */
	mbedtls_ecp_curve_info server_preferred_curve; /*!<  Preferred curve requested by server (obtained in HelloRetryRequest  */
#if defined(MBEDTLS_SSL_CLI_C)
	int hello_retry_requests_received; /*!<  Number of Hello Retry Request messages received from the server.  */
#endif /* MBEDTLS_SSL_CLI_C */
#if defined(MBEDTLS_SSL_SRV_C)
	int hello_retry_requests_sent; /*!<  Number of Hello Retry Request messages sent by the server.  */
#endif /* MBEDTLS_SSL_SRV_C */
#if defined(MBEDTLS_COMPATIBILITY_MODE)
	int ccs_sent; /* Number of CCS messages sent */
#endif /* MBEDTLS_COMPATIBILITY_MODE */
#else
    int sig_alg;                        /*!<  Hash algorithm for signature   */
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
	int cert_type;                      /*!<  Requested cert type            */
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
	int verify_sig_alg;                 /*!<  Signature algorithm for verify */
#endif 
#if defined(MBEDTLS_DHM_C)
    mbedtls_dhm_context dhm_ctx;                /*!<  DHM key exchange        */
#endif

#if defined(MBEDTLS_ECDH_C)
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
	// For TLS 1.3 we might need to store more than one key exchange payload
	mbedtls_ecdh_context ecdh_ctx[MBEDTLS_SSL_MAX_KEY_SHARES]; /*!<  ECDH key exchange       */
	int ecdh_ctx_selected; /*!< Selected ECDHE context */
	int ecdh_ctx_max; /* !< Maximum number of used structures */
#else
	mbedtls_ecdh_context ecdh_ctx;              /*!<  ECDH key exchange       */
#endif 
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    mbedtls_ecjpake_context ecjpake_ctx;        /*!< EC J-PAKE key exchange */
#if defined(MBEDTLS_SSL_CLI_C)
    unsigned char *ecjpake_cache;               /*!< Cache for ClientHello ext */
    size_t ecjpake_cache_len;                   /*!< Length of cached data */
#endif
#endif
#if defined(MBEDTLS_ECDSA_C)
	unsigned char certificate_request_context_len;
	unsigned char *certificate_request_context;
#endif 
#if defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    const mbedtls_ecp_curve_info **curves;      /*!<  Supported elliptic curves */
#endif
#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    unsigned char *psk;                 /*!<  PSK from the callback         */
    size_t psk_len;                     /*!<  Length of PSK from callback   */
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_ssl_key_cert *key_cert;     /*!< chosen key/cert pair (server)  */
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    int sni_authmode;                   /*!< authmode from SNI callback     */
    mbedtls_ssl_key_cert *sni_key_cert; /*!< key/cert list from SNI         */
    mbedtls_x509_crt *sni_ca_chain;     /*!< trusted CAs from SNI callback  */
    mbedtls_x509_crl *sni_ca_crl;       /*!< trusted CAs CRLs from SNI      */
#endif
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_SSL_COOKIE_C)
	unsigned char *verify_cookie;       /*!<  Cli: HelloVerifyRequest cookie
										Srv: unused                    */
	uint16_t verify_cookie_len;    /*!<  Cli: cookie length
										Srv: flag for sending a cookie */
#endif 

#if defined(MBEDTLS_SSL_PROTO_DTLS)
	unsigned int out_msg_seq;           /*!<  Outgoing handshake sequence number */
	unsigned int in_msg_seq;            /*!<  Incoming handshake sequence number */


	unsigned char *hs_msg;              /*!<  Reassembled handshake message  */

	uint32_t retransmit_timeout;        /*!<  Current value of timeout       */
	unsigned char retransmit_state;     /*!<  Retransmission state           */
	mbedtls_ssl_flight_item *flight;            /*!<  Current outgoing flight        */
	mbedtls_ssl_flight_item *cur_msg;           /*!<  Current message in flight      */
	unsigned int in_flight_start_seq;   /*!<  Minimum message sequence in the
										flight being received          */
	mbedtls_ssl_transform *alt_transform_out;   /*!<  Alternative transform for
												resending messages             */
	unsigned char alt_out_ctr[8];       /*!<  Alternative record epoch/counter
										for resending messages         */
#endif

    /*
     * Checksum contexts
     */
#if defined(MBEDTLS_SSL_PROTO_SSL3) || defined(MBEDTLS_SSL_PROTO_TLS1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_1)
       mbedtls_md5_context fin_md5;
      mbedtls_sha1_context fin_sha1;
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_SHA256_C)
    mbedtls_sha256_context fin_sha256;
#endif
#if defined(MBEDTLS_SHA512_C)
    mbedtls_sha512_context fin_sha512;
#endif
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

    void (*update_checksum)(mbedtls_ssl_context *, const unsigned char *, size_t);
    int (*calc_verify)(mbedtls_ssl_context *, unsigned char *, int);
	int(*calc_finished)(mbedtls_ssl_context *, unsigned char *, int);

#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
	int  (*tls_prf)(const unsigned char *, size_t, const char *,
                    const unsigned char *, size_t,
                    unsigned char *, size_t);
#endif
    unsigned char randbytes[64];        /*!<  random bytes            */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

#if defined(MBEDTLS_ECDH_C) && defined(MBEDTLS_SSL_CLI_C)
	/* This is the actual key share list we sent.
	 * The list configured by the application may 
	 * get modified via the server provided hint 
	 * using the HRR message. 
	 */
	mbedtls_ecp_group_id *key_shares_curve_list; /*!< curves to send as key shares */
#endif /* MBEDTLS_ECDH_C && MBEDTLS_SSL_CLI_C */

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
	// pointer to the pre_shared_key extension
	unsigned char *pre_shared_key_pointer; 
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

	unsigned char exporter_secret[MBEDTLS_MD_MAX_SIZE];
	unsigned char early_secret[MBEDTLS_MD_MAX_SIZE];
	unsigned char handshake_secret[MBEDTLS_MD_MAX_SIZE];
	unsigned char client_handshake_traffic_secret[MBEDTLS_MD_MAX_SIZE];
	unsigned char server_handshake_traffic_secret[MBEDTLS_MD_MAX_SIZE];
	unsigned char master_secret[MBEDTLS_MD_MAX_SIZE];
	unsigned char client_traffic_secret[MBEDTLS_MD_MAX_SIZE];
	unsigned char server_traffic_secret[MBEDTLS_MD_MAX_SIZE];
	unsigned char client_finished_key[MBEDTLS_MD_MAX_SIZE];
	unsigned char server_finished_key[MBEDTLS_MD_MAX_SIZE];

#if defined(MBEDTLS_ZERO_RTT)
	unsigned char binder_key[MBEDTLS_MD_MAX_SIZE];
	unsigned char client_early_traffic_secret[MBEDTLS_MD_MAX_SIZE]; 

	/*!< Early data indication:
	0  -- MBEDTLS_SSL_EARLY_DATA_DISABLED (for no early data), and
	1  -- MBEDTLS_SSL_EARLY_DATA_ENABLED (for use early data)
	*/
	int early_data;
#endif /* MBEDTLS_ZERO_RTT */

#else 
	size_t pmslen;                      /*!<  premaster length        */

	unsigned char premaster[MBEDTLS_PREMASTER_SIZE];
	/*!<  premaster secret        */
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
    int resume;                         /*!< session resume indicator*/
    int max_major_ver;                  /*!< max. major version client*/
    int max_minor_ver;                  /*!< max. minor version client*/
    int extensions_present;             /*!< which extension were present; the */

#if (defined(MBEDTLS_SSL_SESSION_TICKETS) || defined(MBEDTLS_SSL_NEW_SESSION_TICKET))
    int new_session_ticket;             /*!< use NewSessionTicket?    */
#endif /* MBEDTLS_SSL_SESSION_TICKETS */
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    int extended_ms;                    /*!< use Extended Master Secret? */
#endif
};

/*
 * This structure contains a full set of runtime transform parameters
 * either in negotiation or active.
 */
struct mbedtls_ssl_transform
{
    /*
     * Session specific crypto layer
     */
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
                                        /*!<  Chosen cipersuite_info  */
    unsigned int keylen;                /*!<  symmetric key length (bytes)  */

    size_t minlen;                      /*!<  min. ciphertext length  */
    size_t ivlen;                       /*!<  IV length               */
	size_t fixed_ivlen;                 /*!<  Fixed part of IV (AEAD) */
    size_t maclen;                      /*!<  MAC length              */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
	KeySet traffic_keys;
	KeySet traffic_keys_previous;

	unsigned char *iv_enc;           /*!<  IV (encryption)         */
	unsigned char *iv_dec;           /*!<  IV (decryption)         */
	unsigned char sequence_number_dec[12]; /* sequence number for incoming (decrypting) traffic */
	unsigned char sequence_number_enc[12]; /* sequence number for outgoing (encrypting) traffic */
#else
    unsigned char iv_enc[16];           /*!<  IV (encryption)         */
    unsigned char iv_dec[16];           /*!<  IV (decryption)         */
#endif
#if defined(MBEDTLS_SSL_PROTO_SSL3)
    /* Needed only for SSL v3.0 secret */
    unsigned char mac_enc[20];          /*!<  SSL v3.0 secret (enc)   */
    unsigned char mac_dec[20];          /*!<  SSL v3.0 secret (dec)   */
#endif /* MBEDTLS_SSL_PROTO_SSL3 */

    mbedtls_md_context_t md_ctx_enc;            /*!<  MAC (encryption)        */
    mbedtls_md_context_t md_ctx_dec;            /*!<  MAC (decryption)        */

    mbedtls_cipher_context_t cipher_ctx_enc;    /*!<  encryption context      */
    mbedtls_cipher_context_t cipher_ctx_dec;    /*!<  decryption context      */

    /*
     * Session specific compression layer
     */
#if defined(MBEDTLS_ZLIB_SUPPORT)
    z_stream ctx_deflate;               /*!<  compression context     */
    z_stream ctx_inflate;               /*!<  decompression context   */
#endif
};

#if defined(MBEDTLS_X509_CRT_PARSE_C)
/*
 * List of certificate + private key pairs
 */
struct mbedtls_ssl_key_cert
{
    mbedtls_x509_crt *cert;                 /*!< cert                       */
    mbedtls_pk_context *key;                /*!< private key                */
    mbedtls_ssl_key_cert *next;             /*!< next key/cert pair         */
};
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
/*
 * List of handshake messages kept around for resending
 */
struct mbedtls_ssl_flight_item
{
    unsigned char *p;       /*!< message, including handshake headers   */
    size_t len;             /*!< length of p                            */
    unsigned char type;     /*!< type of the message: handshake or CCS  */
    mbedtls_ssl_flight_item *next;  /*!< next handshake message(s)              */
};
#endif /* MBEDTLS_SSL_PROTO_DTLS */


/**
 * \brief           Free referenced items in an SSL transform context and clear
 *                  memory
 *
 * \param transform SSL transform context
 */
void mbedtls_ssl_transform_free( mbedtls_ssl_transform *transform );

/**
 * \brief           Free referenced items in an SSL handshake context and clear
 *                  memory
 *
 * \param handshake SSL handshake context
 */
void mbedtls_ssl_handshake_free( mbedtls_ssl_handshake_params *handshake );

int mbedtls_ssl_handshake_client_step( mbedtls_ssl_context *ssl );
int mbedtls_ssl_handshake_server_step( mbedtls_ssl_context *ssl );
void mbedtls_ssl_handshake_wrapup( mbedtls_ssl_context *ssl );

int mbedtls_ssl_send_fatal_handshake_failure( mbedtls_ssl_context *ssl );

void mbedtls_ssl_reset_checksum( mbedtls_ssl_context *ssl );
int mbedtls_ssl_derive_keys( mbedtls_ssl_context *ssl );

int mbedtls_ssl_read_record( mbedtls_ssl_context *ssl );
int mbedtls_ssl_fetch_input( mbedtls_ssl_context *ssl, size_t nb_want );

int mbedtls_ssl_write_record( mbedtls_ssl_context *ssl );
int mbedtls_ssl_flush_output( mbedtls_ssl_context *ssl );

int mbedtls_ssl_parse_certificate( mbedtls_ssl_context *ssl );
int mbedtls_ssl_write_certificate( mbedtls_ssl_context *ssl );

int mbedtls_ssl_write_certificate_verify(mbedtls_ssl_context *ssl, int from);
int mbedtls_ssl_parse_certificate_verify(mbedtls_ssl_context *ssl, int from);


#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
int mbedtls_ssl_parse_change_cipher_spec( mbedtls_ssl_context *ssl );
int mbedtls_ssl_write_change_cipher_spec( mbedtls_ssl_context *ssl );
#endif

int mbedtls_ssl_parse_finished( mbedtls_ssl_context *ssl );
int mbedtls_ssl_write_finished( mbedtls_ssl_context *ssl );

int mbedtls_ssl_key_derivation(mbedtls_ssl_context *ssl, KeySet *traffic_keys); 

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
int mbedtls_ssl_derive_master_secret(mbedtls_ssl_context *ssl); 
int mbedtls_set_traffic_key(mbedtls_ssl_context *ssl, KeySet *traffic_keys, mbedtls_ssl_transform *transform,int mode); 
int mbedtls_ssl_generate_application_traffic_keys(mbedtls_ssl_context *ssl, KeySet *traffic_keys);
int mbedtls_ssl_generate_resumption_master_secret(mbedtls_ssl_context *ssl);
int ssl_write_encrypted_extension(mbedtls_ssl_context *ssl);
int mbedtls_ssl_derive_traffic_keys(mbedtls_ssl_context *ssl, KeySet *traffic_keys);
int incrementSequenceNumber(unsigned char *sequenceNumber, unsigned char *nonce, size_t ivlen);

#if defined(MBEDTLS_COMPATIBILITY_MODE)
int mbedtls_ssl_write_change_cipher_spec(mbedtls_ssl_context *ssl);
#endif /* MBEDTLS_COMPATIBILITY_MODE */

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
int ssl_write_pre_shared_key_ext(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t *olen, int dummy_run); 
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
int ssl_write_signature_algorithms_ext(mbedtls_ssl_context *ssl, unsigned char *buf, size_t *olen);
int ssl_parse_signature_algorithms_ext(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len); 
int mbedtls_ssl_check_signature_scheme(const mbedtls_ssl_context *ssl, int signature_scheme); 
#endif /* MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */
#if defined(MBEDTLS_ZERO_RTT)
int mbedtls_ssl_early_data_key_derivation(mbedtls_ssl_context *ssl, KeySet *traffic_keys); 
int ssl_write_early_data_ext(mbedtls_ssl_context *ssl, unsigned char *buf, size_t *olen);
#endif /* MBEDTLS_ZERO_RTT */
#if (defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C))
int ssl_parse_supported_groups_ext(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len); 
#endif /* MBEDTLS_ECDH_C ||  MBEDTLS_ECDSA_C */
#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
int ssl_create_binder(mbedtls_ssl_context *ssl, unsigned char *psk, size_t psk_len, const mbedtls_md_info_t *md, const mbedtls_ssl_ciphersuite_t *suite_info, unsigned char *buffer, size_t blen, unsigned char *result);
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */
#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
int mbedtls_ssl_parse_new_session_ticket_server(mbedtls_ssl_context *ssl, unsigned char *buf, size_t len, mbedtls_ssl_ticket *ticket); 
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */
#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
int ssl_parse_client_psk_identity_ext(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len); 
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
#define MBEDTLS_SSL_ACK_RECORDS_SENT 0 
#define MBEDTLS_SSL_ACK_RECORDS_RECEIVED 1
int mbedtls_ssl_parse_ack(mbedtls_ssl_context *ssl);
int mbedtls_ssl_write_ack(mbedtls_ssl_context *ssl);
void mbedtls_ack_clear_all(mbedtls_ssl_context *ssl, int mode); 
int mbedtls_ack_add_record(mbedtls_ssl_context *ssl, uint8_t record, int mode);
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

void mbedtls_ssl_optimize_checksum( mbedtls_ssl_context *ssl,
                            const mbedtls_ssl_ciphersuite_t *ciphersuite_info );

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED) && !defined(MBEDTLS_SSL_PROTO_TLS1_3)
int mbedtls_ssl_psk_derive_premaster( mbedtls_ssl_context *ssl, mbedtls_key_exchange_type_t key_ex );
#endif

#if defined(MBEDTLS_PK_C)
unsigned char mbedtls_ssl_sig_from_pk( mbedtls_pk_context *pk );
mbedtls_pk_type_t mbedtls_ssl_pk_alg_from_sig( unsigned char sig );
#endif

mbedtls_md_type_t mbedtls_ssl_md_alg_from_hash( unsigned char hash );
unsigned char mbedtls_ssl_hash_from_md_alg( int md );

#if defined(MBEDTLS_ECP_C)
int mbedtls_ssl_check_curve( const mbedtls_ssl_context *ssl, mbedtls_ecp_group_id grp_id );
#endif

#if defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
int mbedtls_ssl_check_sig_hash( const mbedtls_ssl_context *ssl,
                                mbedtls_md_type_t md );
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
static inline mbedtls_pk_context *mbedtls_ssl_own_key( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_key_cert *key_cert;

    if( ssl->handshake != NULL && ssl->handshake->key_cert != NULL )
        key_cert = ssl->handshake->key_cert;
    else
        key_cert = ssl->conf->key_cert;

    return( key_cert == NULL ? NULL : key_cert->key );
}

static inline mbedtls_x509_crt *mbedtls_ssl_own_cert( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_key_cert *key_cert;

    if( ssl->handshake != NULL && ssl->handshake->key_cert != NULL )
        key_cert = ssl->handshake->key_cert;
    else
        key_cert = ssl->conf->key_cert;

    return( key_cert == NULL ? NULL : key_cert->cert );
}

/*
 * Check usage of a certificate wrt extensions:
 * keyUsage, extendedKeyUsage (later), and nSCertType (later).
 *
 * Warning: cert_endpoint is the endpoint of the cert (ie, of our peer when we
 * check a cert we received from them)!
 *
 * Return 0 if everything is OK, -1 if not.
 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
int mbedtls_ssl_check_cert_usage(const mbedtls_x509_crt *cert,
	const mbedtls_key_exchange_type_t key_exchange,
	int cert_endpoint,
	uint32_t *flags);
#else
int mbedtls_ssl_check_cert_usage( const mbedtls_x509_crt *cert,
                          const mbedtls_ssl_ciphersuite_t *ciphersuite,
                          int cert_endpoint,
                          uint32_t *flags );
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#endif /* MBEDTLS_X509_CRT_PARSE_C */

void mbedtls_ssl_write_version( int major, int minor, int transport,
                        unsigned char ver[2] );
void mbedtls_ssl_read_version( int *major, int *minor, int transport,
                       const unsigned char ver[2] );

#if defined(MBEDTLS_SSL_PROTO_TLS1_3) 
static inline size_t mbedtls_ssl_hdr_len( const mbedtls_ssl_context *ssl, int direction, mbedtls_ssl_transform *transform)
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM ) {

		int len; 

		/* We are dealing with a plaintext DTLS 1.3 packet if transform is NULL */
		if (transform == NULL)  return(13); 

		/* If the DTLS 1.3 packet is encrypted then we need to deterine the header size.
		 * For the moment we assumed a 16-bit sequence number and that the length field 
		 * is included in the payload. 
		 */
		len = 1 /* unified header */ + 2 /* sequence number */ + 2 /* length */; 

		/* Check whether it includes a CID */
#if defined(MBEDTLS_CID)
		if (direction == MBEDTLS_SSL_DIRECTION_OUT) 
			len += ssl->out_cid_len;
		else
			len += ssl->in_cid_len;
#endif /* MBEDTLS_CID */			
		return (len); 
	}
	else
#else
	    ((void) ssl);
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    return( 5 ); /* TLS 1.3 header */
}
#else 
static inline size_t mbedtls_ssl_hdr_len(const mbedtls_ssl_context *ssl)
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
	if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
		return(13);
	}
#else
	((void)ssl);
#endif
	return(5);
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

static inline size_t mbedtls_ssl_hs_hdr_len( const mbedtls_ssl_context *ssl )
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        return( 12 );
#else
    ((void) ssl);
#endif
    return( 4 );
}

#if defined(MBEDTLS_SSL_PROTO_DTLS)
void mbedtls_ssl_send_flight_completed( mbedtls_ssl_context *ssl );
void mbedtls_ssl_recv_flight_completed( mbedtls_ssl_context *ssl );
int mbedtls_ssl_resend( mbedtls_ssl_context *ssl );
#endif

#if defined(MBEDTLS_CID)
int ssl_parse_cid_ext(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len);
void ssl_write_cid_ext(mbedtls_ssl_context *ssl, unsigned char *buf, size_t *olen);
#endif /* MBEDTLS_CID */

/* Visible for testing purposes only */
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
int mbedtls_ssl_dtls_replay_check( mbedtls_ssl_context *ssl );
void mbedtls_ssl_dtls_replay_update( mbedtls_ssl_context *ssl );
#endif

/* constant-time buffer comparison */
static inline int mbedtls_ssl_safer_memcmp( const void *a, const void *b, size_t n )
{
    size_t i;
    const unsigned char *A = (const unsigned char *) a;
    const unsigned char *B = (const unsigned char *) b;
    unsigned char diff = 0;

    for( i = 0; i < n; i++ )
        diff |= A[i] ^ B[i];

    return( diff );
}

#ifdef __cplusplus
}
#endif

#endif /* ssl_internal.h */
