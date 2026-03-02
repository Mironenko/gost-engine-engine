#include <string.h>

#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "gost_kdftree.h"
#include "e_gost_err.h"

static uint32_t be32(uint32_t host)
{
#ifdef L_ENDIAN
    return (host & 0xff000000) >> 24 |
           (host & 0x00ff0000) >> 8  |
           (host & 0x0000ff00) << 8  |
           (host & 0x000000ff) << 24;
#else
    return host;
#endif
}

int gost_kdftree2012_256(unsigned char *keyout, size_t keyout_len,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *label, size_t label_len,
                         const unsigned char *seed, size_t seed_len,
                         const size_t representation)
{
    int iters, i = 0;
    unsigned char zero = 0;
    unsigned char *ptr = keyout;
    HMAC_CTX *ctx;
    unsigned char *len_ptr = NULL;
    uint32_t len_repr = be32(keyout_len * 8);
    size_t len_repr_len = 4;

    ctx = HMAC_CTX_new();
    if (ctx == NULL) {
        GOSTerr(GOST_F_GOST_KDFTREE2012_256, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if ((keyout_len == 0) || (keyout_len % 32 != 0)) {
        GOSTerr(GOST_F_GOST_KDFTREE2012_256, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    iters = keyout_len / 32;

    len_ptr = (unsigned char *)&len_repr;
    while (*len_ptr == 0) {
        len_ptr++;
        len_repr_len--;
    }

    for (i = 1; i <= iters; i++) {
        uint32_t iter_net = be32(i);
        unsigned char *rep_ptr =
            ((unsigned char *)&iter_net) + (4 - representation);

        if (HMAC_Init_ex(ctx, key, keylen,
                         EVP_get_digestbynid(NID_id_GostR3411_2012_256),
                         NULL) <= 0
            || HMAC_Update(ctx, rep_ptr, representation) <= 0
            || HMAC_Update(ctx, label, label_len) <= 0
            || HMAC_Update(ctx, &zero, 1) <= 0
            || HMAC_Update(ctx, seed, seed_len) <= 0
            || HMAC_Update(ctx, len_ptr, len_repr_len) <= 0
            || HMAC_Final(ctx, ptr, NULL) <= 0) {
            GOSTerr(GOST_F_GOST_KDFTREE2012_256, ERR_R_INTERNAL_ERROR);
            HMAC_CTX_free(ctx);
            return 0;
        }

        HMAC_CTX_reset(ctx);
        ptr += 32;
    }

    HMAC_CTX_free(ctx);

    return 1;
}

static inline int gost_tlstree(int cipher_id, const unsigned char *in, unsigned char *out,
                               const unsigned char *tlsseq, int mode);

#define MAKE_GOST_TLSTREE_FUNCTION(name) \
static const int tlstree_cipher_id_ ## name = __LINE__; \
\
int gost_tlstree_ ## name(const unsigned char *in, unsigned char *out, \
                          const unsigned char *tlsseq, int mode) { \
    return gost_tlstree(tlstree_cipher_id_ ## name, in, out, tlsseq, mode); \
}

MAKE_GOST_TLSTREE_FUNCTION(magma_cbc)
MAKE_GOST_TLSTREE_FUNCTION(grasshopper_cbc)
MAKE_GOST_TLSTREE_FUNCTION(magma_mgm)
MAKE_GOST_TLSTREE_FUNCTION(grasshopper_mgm)

static inline int gost_tlstree(int cipher_id, const unsigned char *in, unsigned char *out,
                               const unsigned char *tlsseq, int mode)
{
    uint64_t c1, c2, c3;
    uint64_t seed1, seed2, seed3;
    uint64_t seq;
    unsigned char ko1[32], ko2[32];
    int ret;

    if (cipher_id == tlstree_cipher_id_magma_cbc) {
        c1 = 0x00000000C0FFFFFF;
        c2 = 0x000000FEFFFFFFFF;
        c3 = 0x00F0FFFFFFFFFFFF;
    } else if (cipher_id == tlstree_cipher_id_grasshopper_cbc) {
        c1 = 0x00000000FFFFFFFF;
        c2 = 0x0000F8FFFFFFFFFF;
        c3 = 0xC0FFFFFFFFFFFFFF;
    } else if (cipher_id == tlstree_cipher_id_magma_mgm) {
        if (mode == TLSTREE_MODE_S) {    // TLS_GOSTR341112_256_WITH_MAGMA_MGM_S
            c1 = 0x000000fcffffffff;
            c2 = 0x00e0ffffffffffff;
            c3 = 0xffffffffffffffff;
        } else if (mode == TLSTREE_MODE_L) { // TLS_GOSTR341112_256_WITH_MAGMA_MGM_L
            c1 = 0x000000000000e0ff;
            c2 = 0x000000c0ffffffff;
            c3 = 0x80ffffffffffffff;
        } else {
            return 0;
        }
    } else if (cipher_id == tlstree_cipher_id_grasshopper_mgm) {
        if (mode == TLSTREE_MODE_S) {    // TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S
            c1 = 0x000000e0ffffffff;
            c2 = 0x0000ffffffffffff;
            c3 = 0xf8ffffffffffffff;
        } else if (mode == TLSTREE_MODE_L) { // TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L
            c1 = 0x00000000000000f8;
            c2 = 0x00000000f0ffffff;
            c3 = 0x00e0ffffffffffff;
        } else {
            return 0;
        }
    } else {
        return 0; /* неизвестный cipher_nid */
    }
#ifndef L_ENDIAN
    BUF_reverse((unsigned char *)&seq, tlsseq, 8);
#else
    memcpy(&seq, tlsseq, 8);
#endif
    seed1 = seq & c1;
    seed2 = seq & c2;
    seed3 = seq & c3;

    ret = !(gost_kdftree2012_256(ko1, 32, in, 32, (const unsigned char *)"level1", 6,
                         (const unsigned char *)&seed1, 8, 1) <= 0
			  || gost_kdftree2012_256(ko2, 32, ko1, 32, (const unsigned char *)"level2", 6,
                         (const unsigned char *)&seed2, 8, 1) <= 0
        || gost_kdftree2012_256(out, 32, ko2, 32, (const unsigned char *)"level3", 6,
                         (const unsigned char *)&seed3, 8, 1) <= 0);

    OPENSSL_cleanse(ko1, sizeof(ko1));
    OPENSSL_cleanse(ko2, sizeof(ko2));
    return ret;
}