#pragma once

#include "gost_cipher_ctx.h"

#define GOST_CIPHER_CTX_BUF_SIZE (EVP_MAX_BLOCK_LENGTH * 2)

struct gost_cipher_ctx_st {
    const GOST_cipher *cipher;
    void *cipher_data;
    int flags;
    int encrypt;
    int buf_len;
    int iv_len;
    int key_len;
    int num;
    void *app_data;
    void *allocated_self;
    unsigned char buf[GOST_CIPHER_CTX_BUF_SIZE];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char original_iv[EVP_MAX_IV_LENGTH];
    unsigned char key[EVP_MAX_KEY_LENGTH];
};

/* Internal cipher descriptor layout. Public users must treat GOST_cipher as opaque. */
struct gost_cipher_st {
    struct gost_cipher_st *template; /* template struct */
    int nid;
    int block_size;     /* (bytes) */
    int key_len;        /* (bytes) */
    int iv_len;
    int flags;
    int (*init) (struct gost_cipher_ctx_st *ctx, const unsigned char *key,
                 const unsigned char *iv, int enc);
    int (*do_cipher)(struct gost_cipher_ctx_st *ctx, unsigned char *out,
                     const unsigned char *in, size_t inl);
    int (*cleanup)(struct gost_cipher_ctx_st *);
    int ctx_size;
    int (*set_asn1_parameters)(struct gost_cipher_ctx_st *, ASN1_TYPE *);
    int (*get_asn1_parameters)(struct gost_cipher_ctx_st *, ASN1_TYPE *);
    int (*ctrl)(struct gost_cipher_ctx_st *, int type, int arg, void *ptr);
};
