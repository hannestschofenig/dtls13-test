#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_QUIC)

#include "mbedtls/quic.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf
#define mbedtls_snprintf   snprintf
#endif

#include <string.h>
#include "mbedtls/debug.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/ssl.h"



int quic_write_record(mbedtls_ssl_context *ssl)
{
	uint8_t flags; 
	int ret;
	unsigned char*p;

	uint32_t quic_version; 
	

#if defined(MBEDTLS_SSL_SRV_C)
	if (ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER)
	{

	}
#endif
#if defined(MBEDTLS_SSL_CLI_C)
	if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT)
	{

		switch (ssl->quic_sstate.state) {
		case QUIC_STATE_INITIAL:
			/* Flags = 8 bit
				- version : 1 (0x01)
				- reset : 0
				- diversification nonce : 0
				- connection id length : 1 (0x08)
				- packet number length : 00 (conditional)
				- multipath : 0
				- reserved : 0
             */
			flags = 9;
			quic_version = 0;
			ssl->quic_sstate.sequence_nr = 1; 

			if ((ret = ssl->conf->f_rng(ssl->conf->p_rng, ssl->quic_sstate.connection_id, 8)) != 0) {
				MBEDTLS_SSL_DEBUG_RET(1, "Generating the connection id failed", ret);
				return(ret);
			}
			break;

		default:
			MBEDTLS_SSL_DEBUG_MSG(1, ("Unknown QUIC state"));
			return(-1);
		}
	}
#endif

	/* Make room for the QUIC header */
	//memmove(ssl->out_msg + 14, ssl->out_msg, 14);
	//ssl->out_msglen += 14;

	memmove(ssl->out_hdr + 14, ssl->out_hdr, mbedtls_ssl_hdr_len(ssl) + ssl->out_msglen);
	ssl->out_msglen += 14;
	ssl->out_left += 14;
	p = ssl->out_hdr;

	memcpy_s(p, 1, (unsigned char*) &flags, 1);
	memcpy_s(p + 1, 8, (unsigned char*) &ssl->quic_sstate.connection_id, 8);
	memcpy_s(p + 1 + 8, 4, (unsigned char*) &quic_version, 4);
	memcpy_s(p + 1 + 8 + 4, 1, (unsigned char*)&ssl->quic_sstate.sequence_nr, 1);

	return (0);
}


int quic_read_record(mbedtls_ssl_context *ssl)
{
	return (0);
}

#endif /* MBEDTLS_QUIC */