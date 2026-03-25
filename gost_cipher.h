#pragma once

#include <stddef.h>
#include <openssl/types.h>

struct gost_cipher_ctx_st;

/* Struct describing cipher and used for init/deinit.*/
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

typedef struct gost_cipher_st GOST_cipher;

int GOST_cipher_init(GOST_cipher *c);
int GOST_cipher_type(const GOST_cipher *c);
int GOST_cipher_nid(const GOST_cipher *c);
int GOST_cipher_flags(const GOST_cipher *c);
int GOST_cipher_key_length(const GOST_cipher *c);
int GOST_cipher_iv_length(const GOST_cipher *c);
int GOST_cipher_block_size(const GOST_cipher *c);
int GOST_cipher_mode(const GOST_cipher *c);
int GOST_cipher_ctx_size(const GOST_cipher *c);
int (*GOST_cipher_init_fn(const GOST_cipher *c))(struct gost_cipher_ctx_st *ctx,
                                                 const unsigned char *key,
                                                 const unsigned char *iv,
                                                 int enc);
int (*GOST_cipher_do_cipher_fn(const GOST_cipher *c))(struct gost_cipher_ctx_st *ctx,
                                                      unsigned char *out,
                                                      const unsigned char *in,
                                                      size_t inl);
int (*GOST_cipher_cleanup_fn(const GOST_cipher *c))(struct gost_cipher_ctx_st *ctx);
int (*GOST_cipher_ctrl_fn(const GOST_cipher *c))(struct gost_cipher_ctx_st *ctx,
                                                 int type, int arg,
                                                 void *ptr);