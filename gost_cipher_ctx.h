#pragma once

#include <openssl/evp.h>

#include "gost_cipher.h"

struct gost_cipher_ctx_st;
typedef struct gost_cipher_ctx_st GOST_cipher_ctx;

/* GOST_cipher_ctx management functions */
GOST_cipher_ctx *GOST_cipher_ctx_new(void);
void GOST_cipher_ctx_free(GOST_cipher_ctx *ctx);
int GOST_cipher_ctx_copy(GOST_cipher_ctx *out, const GOST_cipher_ctx *in);

/* GOST_cipher_ctx accessor functions */
int GOST_cipher_ctx_block_size(GOST_cipher_ctx *ctx);
unsigned char *GOST_cipher_ctx_buf_noconst(GOST_cipher_ctx *ctx);
const GOST_cipher *GOST_cipher_ctx_cipher(GOST_cipher_ctx *ctx);
int GOST_cipher_ctx_encrypting(GOST_cipher_ctx *ctx);
int GOST_cipher_ctx_iv_length(GOST_cipher_ctx *ctx);
const unsigned char *GOST_cipher_ctx_iv(GOST_cipher_ctx *ctx);
unsigned char *GOST_cipher_ctx_iv_noconst(GOST_cipher_ctx *ctx);
int GOST_cipher_ctx_key_length(GOST_cipher_ctx *ctx);
int GOST_cipher_ctx_mode(GOST_cipher_ctx *ctx);
int GOST_cipher_ctx_nid(GOST_cipher_ctx *ctx);
int GOST_cipher_ctx_num(GOST_cipher_ctx *ctx);
const unsigned char *GOST_cipher_ctx_original_iv(GOST_cipher_ctx *ctx);
void *GOST_cipher_ctx_get_app_data(GOST_cipher_ctx *ctx);
void *GOST_cipher_ctx_get_cipher_data(GOST_cipher_ctx *ctx);

/* GOST_cipher_ctx mutator functions */
int GOST_cipher_ctx_set_key_length(GOST_cipher_ctx *ctx, int keylen);
int GOST_cipher_ctx_set_num(GOST_cipher_ctx *ctx, int num);
int GOST_cipher_ctx_set_padding(GOST_cipher_ctx *ctx, int pad);
int GOST_cipher_ctx_set_flags(GOST_cipher_ctx *ctx, int flags);
void GOST_cipher_ctx_set_app_data(GOST_cipher_ctx *ctx, void *data);

/* GOST_cipher_ctx control and operation functions */
int GOST_cipher_ctx_cleanup(GOST_cipher_ctx *ctx);
int GOST_cipher_ctx_ctrl(GOST_cipher_ctx *ctx, int type, int arg, void *ptr);

/* GOST_cipher descriptor accessor functions */
int GOST_cipher_init(GOST_cipher *c);
int GOST_cipher_type(const GOST_cipher *c);
int GOST_cipher_nid(const GOST_cipher *c);
int GOST_cipher_flags(const GOST_cipher *c);
int GOST_cipher_key_length(const GOST_cipher *c);
int GOST_cipher_iv_length(const GOST_cipher *c);
int GOST_cipher_block_size(const GOST_cipher *c);
int GOST_cipher_mode(const GOST_cipher *c);
int GOST_cipher_ctx_size(const GOST_cipher *c);
int (*GOST_cipher_init_fn(const GOST_cipher *c))(GOST_cipher_ctx *ctx,
                                                 const unsigned char *key,
                                                 const unsigned char *iv,
                                                 int enc);
int (*GOST_cipher_do_cipher_fn(const GOST_cipher *c))(GOST_cipher_ctx *ctx,
                                                      unsigned char *out,
                                                      const unsigned char *in,
                                                      size_t inl);
int (*GOST_cipher_cleanup_fn(const GOST_cipher *c))(GOST_cipher_ctx *ctx);
int (*GOST_cipher_ctrl_fn(const GOST_cipher *c))(GOST_cipher_ctx *ctx,
                                                 int type, int arg,
                                                 void *ptr);

/* High-level GOST cipher operations */
int GOST_CipherInit_ex(GOST_cipher_ctx *ctx, const GOST_cipher *cipher,
                       const unsigned char *key, const unsigned char *iv, int enc);
int GOST_CipherUpdate(GOST_cipher_ctx *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl);
int GOST_CipherFinal(GOST_cipher_ctx *ctx, unsigned char *out, int *outl);