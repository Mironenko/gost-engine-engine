#pragma once

#include <openssl/evp.h>

#include "gost_cipher.h"

struct gost_cipher_ctx_st;
typedef struct gost_cipher_ctx_st GOST_cipher_ctx;

/* GOST_cipher_ctx accessor functions */
int GOST_cipher_ctx_block_size(GOST_cipher_ctx *ctx);
unsigned char *GOST_cipher_ctx_buf_noconst(GOST_cipher_ctx *ctx);
const struct gost_cipher_st *GOST_cipher_ctx_cipher(GOST_cipher_ctx *ctx);
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

/* GOST_cipher_ctx control, operation and instance management functions */
int GOST_cipher_ctx_cleanup(GOST_cipher_ctx *ctx);
int GOST_cipher_ctx_ctrl(GOST_cipher_ctx *ctx, int type, int arg, void *ptr);
int GOST_cipher_ctx_copy(GOST_cipher_ctx *out, const GOST_cipher_ctx *in);
