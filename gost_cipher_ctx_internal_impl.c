#include <string.h>

#include <openssl/crypto.h>

#include "gost_lcl.h"
#include "gost_cipher_ctx.h"
#include "gost_cipher_ctx_internal_details.h"


int GOST_cipher_ctx_copy(GOST_cipher_ctx *out, const GOST_cipher_ctx *in)
{
    size_t ctx_size = 0;
    int ret = 1;

    if (out == NULL || in == NULL)
        return 0;

    GOST_cipher_ctx_cleanup(out);
    OPENSSL_clear_free(out->cipher_data,
                       out->cipher != NULL ? GOST_cipher_ctx_size(out->cipher) : 0);
    OPENSSL_clear_free(out->buf, GOST_CIPHER_CTX_BUF_SIZE);

    memcpy(out, in, sizeof(*out));
    out->cipher_data = NULL;
    out->buf = NULL;

    if (in->cipher != NULL) {
        ctx_size = (size_t)GOST_cipher_ctx_size(in->cipher);
        if (ctx_size > 0) {
            out->cipher_data = OPENSSL_malloc(ctx_size);
            if (out->cipher_data == NULL)
                ret = 0;
            else
                memcpy(out->cipher_data, in->cipher_data, ctx_size);
        }
    }

    if (ret && in->buf != NULL) {
        out->buf = OPENSSL_malloc(GOST_CIPHER_CTX_BUF_SIZE);
        if (out->buf == NULL)
            ret = 0;
        else
            memcpy(out->buf, in->buf, GOST_CIPHER_CTX_BUF_SIZE);
    }

    if (ret && in->app_data == in->cipher_data)
        out->app_data = out->cipher_data;

    if (!ret) {
        OPENSSL_clear_free(out->cipher_data, ctx_size);
        OPENSSL_clear_free(out->buf, GOST_CIPHER_CTX_BUF_SIZE);
        out->cipher_data = NULL;
        out->buf = NULL;
        return 0;
    }

    if (out->cipher != NULL
        && (GOST_cipher_flags(out->cipher) & EVP_CIPH_CUSTOM_COPY) != 0
        && GOST_cipher_ctrl_fn(out->cipher) != NULL)
        return GOST_cipher_ctrl_fn(out->cipher)((GOST_cipher_ctx *)in,
                                                EVP_CTRL_COPY, 0, out);

    return 1;
}

int GOST_cipher_ctx_block_size(GOST_cipher_ctx *ctx)
{
    return ctx != NULL && ctx->cipher != NULL ? GOST_cipher_block_size(ctx->cipher) : 0;
}

unsigned char *GOST_cipher_ctx_buf_noconst(GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->buf : NULL;
}

const GOST_cipher *GOST_cipher_ctx_cipher(GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->cipher : NULL;
}

int GOST_cipher_ctx_encrypting(GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->encrypt : 0;
}

void *GOST_cipher_ctx_get_app_data(GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->app_data : NULL;
}

void *GOST_cipher_ctx_get_cipher_data(GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->cipher_data : NULL;
}

const unsigned char *GOST_cipher_ctx_iv(GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->iv : NULL;
}

int GOST_cipher_ctx_iv_length(GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->iv_len : 0;
}

unsigned char *GOST_cipher_ctx_iv_noconst(GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->iv : NULL;
}

int GOST_cipher_ctx_key_length(GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->key_len : 0;
}

int GOST_cipher_ctx_mode(GOST_cipher_ctx *ctx)
{
    return ctx != NULL && ctx->cipher != NULL ? GOST_cipher_mode(ctx->cipher) : 0;
}

int GOST_cipher_ctx_nid(GOST_cipher_ctx *ctx)
{
    return ctx != NULL && ctx->cipher != NULL ? GOST_cipher_nid(ctx->cipher) : NID_undef;
}

int GOST_cipher_ctx_num(GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->num : 0;
}

const unsigned char *GOST_cipher_ctx_original_iv(GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->original_iv : NULL;
}

int GOST_cipher_ctx_set_key_length(GOST_cipher_ctx *ctx, int keylen)
{
    if (ctx == NULL || ctx->cipher == NULL)
        return 0;
    if (keylen > EVP_MAX_KEY_LENGTH)
        return 0;
    ctx->key_len = keylen;
    return 1;
}

int GOST_cipher_ctx_set_num(GOST_cipher_ctx *ctx, int num)
{
    if (ctx == NULL)
        return 0;
    ctx->num = num;
    return 1;
}

int GOST_cipher_ctx_set_padding(GOST_cipher_ctx *ctx, int pad)
{
    if (ctx == NULL || ctx->cipher == NULL)
        return 0;
    if (pad)
        ctx->flags &= ~EVP_CIPH_NO_PADDING;
    else
        ctx->flags |= EVP_CIPH_NO_PADDING;
    return 1;
}

int GOST_cipher_ctx_set_flags(GOST_cipher_ctx *ctx, int flags)
{
    if (ctx == NULL)
        return 0;
    ctx->flags |= flags;
    return 1;
}

void GOST_cipher_ctx_set_app_data(GOST_cipher_ctx *ctx, void *data)
{
    if (ctx != NULL)
        ctx->app_data = data;
}

int GOST_cipher_ctx_cleanup(GOST_cipher_ctx *ctx)
{
    int ok = 1;

    if (ctx == NULL)
        return 0;

    if (ctx->cipher != NULL && GOST_cipher_cleanup_fn(ctx->cipher) != NULL)
        ok = GOST_cipher_cleanup_fn(ctx->cipher)(ctx);

    ctx->app_data = NULL;
    ctx->encrypt = 0;
    ctx->final_used = 0;
    ctx->num = 0;
    return ok;
}

int GOST_cipher_ctx_ctrl(GOST_cipher_ctx *ctx, int type, int arg, void *ptr)
{
    if (ctx == NULL || ctx->cipher == NULL || GOST_cipher_ctrl_fn(ctx->cipher) == NULL)
        return 0;
    return GOST_cipher_ctrl_fn(ctx->cipher)(ctx, type, arg, ptr);
}
