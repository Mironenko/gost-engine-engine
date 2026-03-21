#pragma once

#include "gost_cipher_ctx.h"

/* GOST_cipher_ctx instancep management functions */
GOST_cipher_ctx *GOST_cipher_ctx_new(void);
void GOST_cipher_ctx_free(GOST_cipher_ctx *ctx);

/* High-level GOST cipher operations */
int GOST_CipherInit_ex(GOST_cipher_ctx *ctx, const struct gost_cipher_st *cipher,
                       const unsigned char *key, const unsigned char *iv, int enc);
int GOST_CipherUpdate(GOST_cipher_ctx *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl);
int GOST_CipherFinal(GOST_cipher_ctx *ctx, unsigned char *out, int *outl);
