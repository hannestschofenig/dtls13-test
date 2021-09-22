/* RFC 5869 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <string.h>
#include "mbedtls/hkdf.h"

/* HKDF-Extract + HKDF-Expand */
int mbedtls_hkdf(const mbedtls_md_info_t *md, const unsigned char *salt,
                 int salt_len, const unsigned char *ikm, int ikm_len,
                 const unsigned char *info, int info_len, unsigned char *okm,
                 int okm_len)
{
	int ret; 
    unsigned char prk[MBEDTLS_MD_MAX_SIZE];

	ret = mbedtls_hkdf_extract(md, salt, salt_len, ikm, ikm_len, prk); 
	
	if (ret == 0) {
		ret = mbedtls_hkdf_expand(md, prk, mbedtls_md_get_size(md), info, info_len, okm, okm_len);
	} 
	return ret;
}

/* HKDF-Extract(salt, IKM) -> PRK */
int mbedtls_hkdf_extract(const mbedtls_md_info_t *md, const unsigned char *salt,
                         int salt_len, const unsigned char *ikm, int ikm_len,
                         unsigned char *prk)
{
    int hash_len; 
    unsigned char null_salt[MBEDTLS_MD_MAX_SIZE] = {'\0'};

    if (salt_len < 0) {
        return MBEDTLS_ERR_HKDF_BAD_PARAM;
    }

    hash_len = mbedtls_md_get_size(md);

	if (hash_len==0) {
		return MBEDTLS_ERR_HKDF_BAD_PARAM;
	}

    if (salt == NULL) {
        salt = null_salt;
        salt_len = hash_len;
    }

    return mbedtls_md_hmac(md, salt, salt_len, ikm, ikm_len, prk);
}

/* HKDF-Expand(PRK, info, L) -> OKM */
int mbedtls_hkdf_expand(const mbedtls_md_info_t *md, const unsigned char *prk,
                        int prk_len, const unsigned char *info, int info_len,
                        unsigned char *okm, int okm_len)
{
	unsigned char T[MBEDTLS_MD_MAX_SIZE];
	int T_len = 0, where = 0, i, ret;
	mbedtls_md_context_t ctx;
	int hash_len, N; 
	unsigned char c; 


    if (info_len < 0 || okm_len < 0 || okm == NULL) {
        return(MBEDTLS_ERR_HKDF_BAD_PARAM);
    }

    hash_len = mbedtls_md_get_size(md);

    if ( (prk_len < hash_len) || (hash_len==0) ){
        return(MBEDTLS_ERR_HKDF_BAD_PARAM);
    }

    if (info == NULL) {
        info = (const unsigned char *)"";
		info_len = 0;
    }

    N = okm_len / hash_len;

    if ((okm_len % hash_len) != 0) {
        N++;
    }

    if (N > 255) {
		return(MBEDTLS_ERR_HKDF_BAD_PARAM);
    }

    mbedtls_md_init(&ctx);

    if ((ret = mbedtls_md_setup(&ctx, md, 1)) != 0) {
        return ret;
    }

    /* Section 2.3. */
    for (i = 1; i <= N; i++) {
        c = i;

        ret = mbedtls_md_hmac_starts(&ctx, prk, prk_len) ||
              mbedtls_md_hmac_update(&ctx, T, T_len) ||
              mbedtls_md_hmac_update(&ctx, info, info_len) ||
              /* The constant concatenated to the end of each T(n) is a single
                 octet. */
              mbedtls_md_hmac_update(&ctx, &c, 1) ||
              mbedtls_md_hmac_finish(&ctx, T);

        if (ret != 0) {
			mbedtls_md_free(&ctx); 
            return ret;
        }

        memcpy(okm + where, T, (i != N) ? hash_len : (okm_len - where));
        where += hash_len;
        T_len = hash_len;
    }

	mbedtls_md_free(&ctx);

    return 0;
}
