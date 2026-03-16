/* C source: gost_cipher_ctx.c */
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "gost_lcl.h"

#define TPL(st, field) (((st)->field) ? ((st)->field) : TPL_VAL(st, field))
#define TPL_VAL(st, field) ((st)->template ? (st)->template->field : 0)
#define GOST_CIPHER_CTX_BUF_SIZE (EVP_MAX_BLOCK_LENGTH * 2)

int GOST_cipher_init(GOST_cipher *c)
{
    if (c == NULL)
        return 0;

    if (c->block_size == 0)
        c->block_size = TPL_VAL(c, block_size);
    if (c->key_len == 0)
        c->key_len = TPL_VAL(c, key_len);
    if (c->iv_len == 0)
        c->iv_len = TPL_VAL(c, iv_len);
    c->flags |= TPL_VAL(c, flags);
    if (c->init == NULL)
        c->init = TPL_VAL(c, init);
    if (c->do_cipher == NULL)
        c->do_cipher = TPL_VAL(c, do_cipher);
    if (c->cleanup == NULL)
        c->cleanup = TPL_VAL(c, cleanup);
    if (c->ctx_size == 0)
        c->ctx_size = TPL_VAL(c, ctx_size);
    if (c->set_asn1_parameters == NULL)
        c->set_asn1_parameters = TPL_VAL(c, set_asn1_parameters);
    if (c->get_asn1_parameters == NULL)
        c->get_asn1_parameters = TPL_VAL(c, get_asn1_parameters);
    if (c->ctrl == NULL)
        c->ctrl = TPL_VAL(c, ctrl);

    return 1;
}

GOST_cipher_ctx *GOST_cipher_ctx_new(void)
{
    return OPENSSL_zalloc(sizeof(GOST_cipher_ctx));
}

void GOST_cipher_ctx_free(GOST_cipher_ctx *ctx)
{
    if (ctx == NULL)
        return;

    GOST_cipher_ctx_cleanup(ctx);
    OPENSSL_clear_free(ctx->cipher_data, ctx->cipher != NULL ? GOST_cipher_ctx_size(ctx->cipher) : 0);
    OPENSSL_clear_free(ctx->buf, GOST_CIPHER_CTX_BUF_SIZE);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

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

int GOST_cipher_type(const GOST_cipher *c)
{
    return c != NULL ? c->nid : NID_undef;
}

int GOST_cipher_nid(const GOST_cipher *c)
{
    return GOST_cipher_type(c);
}

int GOST_cipher_flags(const GOST_cipher *c)
{
    return c != NULL ? c->flags : 0;
}

int GOST_cipher_key_length(const GOST_cipher *c)
{
    return c != NULL ? c->key_len : 0;
}

int GOST_cipher_iv_length(const GOST_cipher *c)
{
    return c != NULL ? c->iv_len : 0;
}

int GOST_cipher_block_size(const GOST_cipher *c)
{
    return c != NULL ? c->block_size : 0;
}

int GOST_cipher_mode(const GOST_cipher *c)
{
    return c != NULL ? (c->flags & EVP_CIPH_MODE) : 0;
}

int GOST_cipher_ctx_size(const GOST_cipher *c)
{
    return c != NULL ? c->ctx_size : 0;
}

int (*GOST_cipher_init_fn(const GOST_cipher *c))(GOST_cipher_ctx *ctx,
                                                 const unsigned char *key,
                                                 const unsigned char *iv,
                                                 int enc)
{
    return c != NULL ? c->init : NULL;
}

int (*GOST_cipher_do_cipher_fn(const GOST_cipher *c))(GOST_cipher_ctx *ctx,
                                                      unsigned char *out,
                                                      const unsigned char *in,
                                                      size_t inl)
{
    return c != NULL ? c->do_cipher : NULL;
}

int (*GOST_cipher_cleanup_fn(const GOST_cipher *c))(GOST_cipher_ctx *ctx)
{
    return c != NULL ? c->cleanup : NULL;
}

int (*GOST_cipher_ctrl_fn(const GOST_cipher *c))(GOST_cipher_ctx *ctx,
                                                 int type, int arg,
                                                 void *ptr)
{
    return c != NULL ? c->ctrl : NULL;
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

        ctx->cipher = cipher;
        ctx->flags = GOST_cipher_flags(cipher);
        ctx->iv_len = GOST_cipher_iv_length(cipher);
        ctx->key_len = keep_key_len > 0 ? keep_key_len : GOST_cipher_key_length(cipher);

        if (!same_cipher) {
            OPENSSL_clear_free(ctx->cipher_data,
                               old_cipher != NULL ? GOST_cipher_ctx_size(old_cipher) : 0);
            ctx->cipher_data = NULL;
            if (GOST_cipher_ctx_size(cipher) > 0) {
                ctx->cipher_data = OPENSSL_zalloc((size_t)GOST_cipher_ctx_size(cipher));
                if (ctx->cipher_data == NULL)
                    return 0;
            }

            OPENSSL_clear_free(ctx->buf, GOST_CIPHER_CTX_BUF_SIZE);
            ctx->buf = OPENSSL_zalloc(GOST_CIPHER_CTX_BUF_SIZE);
            if (ctx->buf == NULL)
                return 0;
        }
    }

    if (enc >= 0)
        ctx->encrypt = enc != 0;

    if (key != NULL && ctx->key_len > 0)
        memcpy(ctx->key, key, (size_t)ctx->key_len);

    if (iv != NULL && ctx->iv_len > 0) {
        memcpy(ctx->original_iv, iv, (size_t)ctx->iv_len);
        memcpy(ctx->iv, iv, (size_t)ctx->iv_len);
    }

    if (ctx->cipher != NULL && GOST_cipher_init_fn(ctx->cipher) != NULL
        && !GOST_cipher_init_fn(ctx->cipher)(ctx, key, iv, ctx->encrypt))
        return 0;

    ctx->buf_len = 0;
    ctx->final_used = 0;
    ctx->block_mask = ctx->cipher != NULL ? GOST_cipher_block_size(ctx->cipher) - 1 : 0;
    return 1;
}

int GOST_CipherUpdate(GOST_cipher_ctx *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl)
{
    int i, j, bl;

    if (ctx == NULL || ctx->cipher == NULL || GOST_cipher_do_cipher_fn(ctx->cipher) == NULL)
        return 0;

    if (outl != NULL)
        *outl = 0;

    if (GOST_cipher_flags(ctx->cipher) & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        i = GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, in, (size_t)inl);
        if (i < 0)
            return 0;
        if (outl != NULL)
            *outl = i;
        return 1;
    }

    if (inl <= 0)
        return inl == 0;

    if (ctx->flags & EVP_CIPH_NO_PADDING) {
        if (!GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, in, (size_t)inl))
            return 0;
        if (outl != NULL)
            *outl = inl;
        return 1;
    }

    bl = GOST_cipher_block_size(ctx->cipher);
    if (ctx->buf_len == 0 && (inl & ctx->block_mask) == 0) {
        if (!GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, in, (size_t)inl))
            return 0;
        if (outl != NULL)
            *outl = inl;
        return 1;
    }

    i = ctx->buf_len;
    if (i != 0) {
        if (bl - i > inl) {
            memcpy(&(ctx->buf[i]), in, (size_t)inl);
            ctx->buf_len += inl;
            return 1;
        }

        j = bl - i;
        memcpy(&(ctx->buf[i]), in, (size_t)j);
        inl -= j;
        in += j;
        if (!GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, ctx->buf, (size_t)bl))
            return 0;
        out += bl;
        if (outl != NULL)
            *outl = bl;
    }

    i = inl & (bl - 1);
    inl -= i;
    if (inl > 0) {
        if (!GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, in, (size_t)inl))
            return 0;
        if (outl != NULL)
            *outl += inl;
    }

    if (i != 0)
        memcpy(ctx->buf, &(in[inl]), (size_t)i);
    ctx->buf_len = i;
    return 1;
}

int GOST_CipherFinal(GOST_cipher_ctx *ctx, unsigned char *out, int *outl)
{
    int i, n, ret;
    unsigned int b;

    if (ctx == NULL || ctx->cipher == NULL
        || GOST_cipher_do_cipher_fn(ctx->cipher) == NULL)
        return 0;

    if (outl != NULL)
        *outl = 0;

    if (GOST_cipher_flags(ctx->cipher) & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        ret = GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, NULL, 0);
        if (ret < 0)
            return 0;
        if (outl != NULL)
            *outl = ret;
        return 1;
    }

    b = (unsigned int)GOST_cipher_block_size(ctx->cipher);
    if (b == 1)
        return 1;

    if (ctx->flags & EVP_CIPH_NO_PADDING) {
        if (ctx->buf_len != 0)
            return 0;
        return 1;
    }

    if (ctx->encrypt) {
        n = (int)b - ctx->buf_len;
        for (i = ctx->buf_len; i < (int)b; i++)
            ctx->buf[i] = (unsigned char)n;
        ret = GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, ctx->buf, b);
        if (ret <= 0)
            return 0;
        if (outl != NULL)
            *outl = (int)b;
        return 1;
    }

    if (ctx->buf_len || !ctx->final_used)
        return 0;

    n = ctx->final[b - 1];
    if (n == 0 || n > (int)b)
        return 0;
    for (i = 0; i < n; i++) {
        if (ctx->final[--b] != n)
            return 0;
    }
    n = GOST_cipher_block_size(ctx->cipher) - n;
    for (i = 0; i < n; i++)
        out[i] = ctx->final[i];
    if (outl != NULL)
        *outl = n;
    return 1;
}
