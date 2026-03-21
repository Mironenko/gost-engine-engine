#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "gost_cipher_ctx.h"
#include "gost_cipher_ctx_evp_details.h"

/* Engine-specific GOST_cipher_ctx implementation.
 * This implementation wraps an EVP_CIPHER_CTX and a pointer to the
 * corresponding GOST_cipher descriptor. All operations are forwarded to
 * the underlying EVP_CIPHER_CTX or to the GOST_cipher descriptor as needed.
 */

int GOST_cipher_ctx_copy(GOST_cipher_ctx *out, const GOST_cipher_ctx *in)
{
    if (out == NULL || in == NULL)
        return 0;

    if (out->cctx == NULL) {
        return 0;
    }

    /* Copy underlying EVP_CIPHER_CTX */
    if (!EVP_CIPHER_CTX_copy(out->cctx, in->cctx))
        return 0;

    out->cipher = in->cipher;
    return 1;
}

int GOST_cipher_ctx_block_size(GOST_cipher_ctx *ctx)
{
    return EVP_CIPHER_CTX_block_size(ctx->cctx);
}

unsigned char *GOST_cipher_ctx_buf_noconst(GOST_cipher_ctx *ctx)
{
    return EVP_CIPHER_CTX_buf_noconst(ctx->cctx);
}

const GOST_cipher *GOST_cipher_ctx_cipher(GOST_cipher_ctx *ctx)
{
    return ctx->cipher;
}

int GOST_cipher_ctx_encrypting(GOST_cipher_ctx *ctx)
{
    return EVP_CIPHER_CTX_encrypting(ctx->cctx);
}

void *GOST_cipher_ctx_get_app_data(GOST_cipher_ctx *ctx)
{
    return EVP_CIPHER_CTX_get_app_data(ctx->cctx);
}

void *GOST_cipher_ctx_get_cipher_data(GOST_cipher_ctx *ctx)
{
    return EVP_CIPHER_CTX_get_cipher_data(ctx->cctx);
}

const unsigned char *GOST_cipher_ctx_iv(GOST_cipher_ctx *ctx)
{
    return EVP_CIPHER_CTX_iv(ctx->cctx);
}

int GOST_cipher_ctx_iv_length(GOST_cipher_ctx *ctx)
{
    return EVP_CIPHER_CTX_iv_length(ctx->cctx);
}

unsigned char *GOST_cipher_ctx_iv_noconst(GOST_cipher_ctx *ctx)
{
    return EVP_CIPHER_CTX_iv_noconst(ctx->cctx);
}

int GOST_cipher_ctx_key_length(GOST_cipher_ctx *ctx)
{
    return EVP_CIPHER_CTX_key_length(ctx->cctx);
}

int GOST_cipher_ctx_mode(GOST_cipher_ctx *ctx)
{
    return EVP_CIPHER_CTX_mode(ctx->cctx);
}

int GOST_cipher_ctx_nid(GOST_cipher_ctx *ctx)
{
    return EVP_CIPHER_CTX_nid(ctx->cctx);
}

int GOST_cipher_ctx_num(GOST_cipher_ctx *ctx)
{
    return EVP_CIPHER_CTX_num(ctx->cctx);
}

const unsigned char *GOST_cipher_ctx_original_iv(GOST_cipher_ctx *ctx)
{
    return EVP_CIPHER_CTX_original_iv(ctx->cctx);
}

int GOST_cipher_ctx_set_key_length(GOST_cipher_ctx *ctx, int keylen)
{
    return EVP_CIPHER_CTX_set_key_length(ctx->cctx, keylen);
}

int GOST_cipher_ctx_set_num(GOST_cipher_ctx *ctx, int num)
{
    return EVP_CIPHER_CTX_set_num(ctx->cctx, num);
}

int GOST_cipher_ctx_set_padding(GOST_cipher_ctx *ctx, int pad)
{
    return EVP_CIPHER_CTX_set_padding(ctx->cctx, pad);
}

int GOST_cipher_ctx_set_flags(GOST_cipher_ctx *ctx, int flags)
{
    EVP_CIPHER_CTX_set_flags(ctx->cctx, flags);
    return 1;
}

void GOST_cipher_ctx_set_app_data(GOST_cipher_ctx *ctx, void *data)
{
    EVP_CIPHER_CTX_set_app_data(ctx->cctx, data);
}

int GOST_cipher_ctx_cleanup(GOST_cipher_ctx *ctx)
{
    return EVP_CIPHER_CTX_cleanup(ctx->cctx);
}

int GOST_cipher_ctx_ctrl(GOST_cipher_ctx *ctx, int type, int arg, void *ptr)
{
    return EVP_CIPHER_CTX_ctrl(ctx->cctx, type, arg, ptr);
}
