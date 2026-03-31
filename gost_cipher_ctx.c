#include "gost_cipher_details.h"

#include <string.h>

#include <openssl/crypto.h>

static size_t gost_cipher_algctx_size(const GOST_cipher_ctx *ctx)
{
    if (ctx == NULL || ctx->cipher == NULL)
        return 0;

    return (size_t)GOST_cipher_ctx_size(ctx->cipher);
}

static int gost_cipher_ctx_release(GOST_cipher_ctx *ctx, int call_cleanup)
{
    void *allocated_self;
    size_t algctx_size;
    int ok = 1;

    if (ctx == NULL)
        return 0;

    allocated_self = ctx->allocated_self;
    algctx_size = gost_cipher_algctx_size(ctx);

    if (call_cleanup
        && ctx->cipher != NULL
        && GOST_cipher_cleanup_fn(ctx->cipher) != NULL
        && (ctx->cipher_data != NULL || algctx_size == 0)) {
        ok = GOST_cipher_cleanup_fn(ctx->cipher)(ctx);
    }

    OPENSSL_clear_free(ctx->cipher_data, algctx_size);

    memset(ctx, 0, sizeof(*ctx));
    ctx->allocated_self = allocated_self;

    return ok;
}

size_t GOST_cipher_ctx_sizeof(void)
{
    return sizeof(GOST_cipher_ctx);
}

GOST_cipher_ctx *GOST_cipher_ctx_new(void)
{
    GOST_cipher_ctx *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        ctx->allocated_self = ctx;

    return ctx;
}

void GOST_cipher_ctx_free(GOST_cipher_ctx *ctx)
{
    void *allocated_self;

    if (ctx == NULL)
        return;

    allocated_self = ctx->allocated_self;
    gost_cipher_ctx_release(ctx, 1);

    if (allocated_self != NULL)
        OPENSSL_clear_free(allocated_self, sizeof(*ctx));
}

int GOST_cipher_ctx_copy(GOST_cipher_ctx *out, const GOST_cipher_ctx *in)
{
    void *allocated_self;
    size_t algctx_size = 0;
    int ret = 1;

    if (out == NULL || in == NULL)
        return 0;
    if (out == in)
        return 1;

    allocated_self = out->allocated_self;
    if (out->cipher_data != NULL && out->cipher_data == in->cipher_data) {
        out->cipher_data = NULL;
        gost_cipher_ctx_release(out, 0);
    } else if (out->cipher != NULL || out->cipher_data != NULL) {
        gost_cipher_ctx_release(out, 1);
    }

    memcpy(out, in, sizeof(*out));
    out->allocated_self = allocated_self;
    out->cipher_data = NULL;

    if (in->cipher != NULL) {
        algctx_size = (size_t)GOST_cipher_ctx_size(in->cipher);
        if (algctx_size > 0) {
            out->cipher_data = OPENSSL_malloc(algctx_size);
            if (out->cipher_data == NULL)
                ret = 0;
            else
                memcpy(out->cipher_data, in->cipher_data, algctx_size);
        }
    }

    if (ret && in->app_data == in->cipher_data)
        out->app_data = out->cipher_data;

    if (ret
        && out->cipher != NULL
        && (GOST_cipher_flags(out->cipher) & EVP_CIPH_CUSTOM_COPY) != 0) {
        ret = GOST_cipher_ctx_ctrl((GOST_cipher_ctx *)in, EVP_CTRL_COPY, 0, out) > 0;
    }

    if (!ret)
        gost_cipher_ctx_release(out, 1);

    return ret;
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

int GOST_cipher_ctx_iv_length(GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->iv_len : 0;
}

const unsigned char *GOST_cipher_ctx_iv(GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->iv : NULL;
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

void *GOST_cipher_ctx_get_app_data(GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->app_data : NULL;
}

void *GOST_cipher_ctx_get_cipher_data(GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->cipher_data : NULL;
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
    if (ctx == NULL)
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
    return gost_cipher_ctx_release(ctx, 1);
}

int GOST_cipher_ctx_ctrl(GOST_cipher_ctx *ctx, int type, int arg, void *ptr)
{
    if (ctx == NULL || ctx->cipher == NULL || GOST_cipher_ctrl_fn(ctx->cipher) == NULL)
        return -2;

    return GOST_cipher_ctrl_fn(ctx->cipher)(ctx, type, arg, ptr);
}

int GOST_CipherInit_ex(GOST_cipher_ctx *ctx, const GOST_cipher *cipher,
                       const unsigned char *key, const unsigned char *iv,
                       int enc)
{
    if (ctx == NULL)
        return 0;

    if (cipher != NULL) {
        const GOST_cipher *old_cipher = ctx->cipher;
        int same_cipher = old_cipher == cipher;
        int keep_key_len = same_cipher ? ctx->key_len : 0;
        int wrap_allow = ctx->flags & EVP_CIPHER_CTX_FLAG_WRAP_ALLOW;

        if (!same_cipher)
            gost_cipher_ctx_release(ctx, 1);

        ctx->cipher = cipher;
        if (ctx->cipher_data == NULL && GOST_cipher_ctx_size(cipher) > 0) {
            ctx->cipher_data = OPENSSL_zalloc((size_t)GOST_cipher_ctx_size(cipher));
            if (ctx->cipher_data == NULL)
                return 0;
        }

        ctx->flags = wrap_allow | GOST_cipher_flags(cipher);
        ctx->iv_len = GOST_cipher_iv_length(cipher);
        ctx->key_len = keep_key_len > 0 ? keep_key_len : GOST_cipher_key_length(cipher);

        /*
         * Match EVP_CipherInit_ex() semantics for repeated init of the same
         * cipher: preserve algorithm state unless the cipher itself changes.
         */
        if (!same_cipher && (GOST_cipher_flags(cipher) & EVP_CIPH_CTRL_INIT) != 0) {
            if (GOST_cipher_ctx_ctrl(ctx, EVP_CTRL_INIT, 0, NULL) <= 0)
                return 0;
        }

        if (!(ctx->flags & EVP_CIPHER_CTX_FLAG_WRAP_ALLOW)
            && GOST_cipher_mode(cipher) == EVP_CIPH_WRAP_MODE)
            return 0;
    }

    if (enc >= 0)
        ctx->encrypt = enc != 0;

    if (key != NULL && ctx->key_len > 0)
        memcpy(ctx->key, key, (size_t)ctx->key_len);

    if (iv != NULL && ctx->iv_len > 0) {
        memcpy(ctx->original_iv, iv, (size_t)ctx->iv_len);
        memcpy(ctx->iv, iv, (size_t)ctx->iv_len);
    }

    if (ctx->cipher != NULL
        && GOST_cipher_init_fn(ctx->cipher) != NULL
        && !GOST_cipher_init_fn(ctx->cipher)(ctx, key, iv, ctx->encrypt))
        return 0;

    ctx->buf_len = 0;

    return 1;
}
