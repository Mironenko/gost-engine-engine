/* C source: gost_cipher_ctx.c */
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "gost_lcl.h"

#define GOST_CIPHER_CTX_BUF_SIZE (EVP_MAX_BLOCK_LENGTH * 2)

/* New GOST cipher context structure */
struct gost_cipher_ctx_st {
    const GOST_cipher *cipher;   /* cipher descriptor */
    unsigned char *buf;          /* mode-specific working buffer */
    int buf_len;                 /* number of bytes in partial block buffer */
    int final_used;              /* final block flag */
    int block_mask;              /* block_size - 1 */
    int encrypt;                 /* encrypt flag (1) or decrypt (0) */
    unsigned char final[EVP_MAX_BLOCK_LENGTH]; /* final block buffer */
    int flags;                   /* cipher flags */
    unsigned char iv[EVP_MAX_IV_LENGTH];    /* initialization vector */
    unsigned char original_iv[EVP_MAX_IV_LENGTH]; /* original IV */
    int iv_len;                  /* IV length */
    unsigned char key[EVP_MAX_KEY_LENGTH];  /* key */
    int key_len;                 /* key length */
    int num;                     /* mode-specific counter */
    void *app_data;              /* application data */
    void *cipher_data;           /* cipher-specific data (e.g., ossl_gost_cipher_ctx) */
};

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
        /* preserve only the wrap allow flag across reinitialisation; this
         * mirrors the legacy EVP_CipherInit_ex behaviour which preserves
         * EVP_CIPHER_CTX_FLAG_WRAP_ALLOW while zeroing other flags. */
        int wrap_allow = ctx->flags & EVP_CIPHER_CTX_FLAG_WRAP_ALLOW;

        ctx->cipher = cipher;
        ctx->flags = (wrap_allow) | GOST_cipher_flags(cipher);
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

            /* Reset transient state similar to EVP_CipherInit_ex behaviour. */
            ctx->app_data = NULL;
            ctx->encrypt = 0;
            ctx->final_used = 0;
            ctx->num = 0;
        }

        /* Disallow wrap mode unless explicitly enabled by the caller. */
        if (!(ctx->flags & EVP_CIPHER_CTX_FLAG_WRAP_ALLOW)
            && (GOST_cipher_mode(cipher) == EVP_CIPH_WRAP_MODE))
            return 0;

        /* If the cipher wants an initial ctrl invocation, call it now. */
        if (GOST_cipher_flags(cipher) & EVP_CIPH_CTRL_INIT) {
            if (GOST_cipher_ctrl_fn(cipher) == NULL
                || GOST_cipher_ctrl_fn(cipher)((GOST_cipher_ctx *)ctx, EVP_CTRL_INIT, 0, NULL) <= 0)
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

    bl = GOST_cipher_block_size(ctx->cipher);

    /* Stream cipher / block size 1: just forward everything */
    if (bl == 1) {
        if (!GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, in, (size_t)inl))
            return 0;
        if (outl != NULL)
            *outl = inl;
        return 1;
    }

    /* NO PADDING: pass through directly (must be multiple of block size) */
    if (ctx->flags & EVP_CIPH_NO_PADDING) {
        if (!GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, in, (size_t)inl))
            return 0;
        if (outl != NULL)
            *outl = inl;
        return 1;
    }

    /* With padding enabled: encryption keeps partial in ctx->buf; decryption
     * must always keep one block decrypted in ctx->final and not output it
     * until final() where padding is checked. */
    if (ctx->encrypt) {
        /* Encryption: accumulate and process all full blocks */
        i = ctx->buf_len;
        if (i != 0) {
            j = bl - i;
            if (inl < j) {
                memcpy(&(ctx->buf[i]), in, (size_t)inl);
                ctx->buf_len += inl;
                return 1;
            }
            memcpy(&(ctx->buf[i]), in, (size_t)j);
            in += j;
            inl -= j;
            if (!GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, ctx->buf, (size_t)bl))
                return 0;
            out += bl;
            if (outl != NULL)
                *outl = bl;
            ctx->buf_len = 0;
        }

        /* process all whole blocks from input */
        i = inl & ~(bl - 1);
        if (i > 0) {
            if (!GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, in, (size_t)i))
                return 0;
            if (outl != NULL)
                *outl += i;
            in += i;
            inl -= i;
        }

        /* leftover goes to buffer */
        if (inl != 0) {
            memcpy(ctx->buf, in, (size_t)inl);
            ctx->buf_len = inl;
        }
        return 1;
    } else {
        /* Decryption: need to leave last block decrypted in ctx->final */
        int total = ctx->buf_len + inl;
        if (total < bl) {
            /* Not enough for a full block: buffer it */
            if (inl > 0) {
                memcpy(&(ctx->buf[ctx->buf_len]), in, (size_t)inl);
                ctx->buf_len += inl;
            }
            return 1;
        }

        /* number of bytes we will output now (excluding the final saved block) */
        int to_process = ((total / bl) - 1) * bl;
        int produced = 0;

        /* first finish filling buffer if present */
        i = ctx->buf_len;
        if (i != 0) {
            int need = bl - i;
            if (to_process >= need) {
                /* we will process the completed block as part of to_process */
                memcpy(&(ctx->buf[i]), in, (size_t)need);
                in += need;
                inl -= need;
                to_process -= need;
                if (!GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, ctx->buf, (size_t)bl))
                    return 0;
                out += bl;
                produced += bl;
                ctx->buf_len = 0;
            } else {
                /* to_process is zero: we should not process the filled buffer now
                 * because it may be the final block that must be saved */
                memcpy(&(ctx->buf[i]), in, (size_t)inl);
                ctx->buf_len += inl;
                return 1;
            }
        }

        /* process as many whole blocks from input as needed (to_process) */
        if (to_process > 0) {
            if (!GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, in, (size_t)to_process))
                return 0;
            out += to_process;
            produced += to_process;
            in += to_process;
            inl -= to_process;
        }

        /* now 'in'/'inl' contain exactly one block (the block to decrypt and
         * save for final) or more but the excess should be zero here */
        /* build the last block (either from remaining input or from buffered data) */
        if (inl > 0) {
            /* copy last block ciphertext into ctx->final by first assembling it */
            if (inl == bl) {
                /* decrypt directly into final */
                if (!GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, ctx->final, in, (size_t)bl))
                    return 0;
            } else if (inl < bl) {
                /* remaining bytes plus none in buffer: shouldn't happen here */
                /* assemble from buffer (should be empty) and in */
                memcpy(ctx->final, in, (size_t)inl);
                /* if any bytes missing (shouldn't), they would come from buffer */
                if (!GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, ctx->final, ctx->final, (size_t)bl))
                    return 0;
            } else {
                /* inl > bl: take last block from the tail */
                if (!GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, ctx->final, in + (inl - bl), (size_t)bl))
                    return 0;
            }
        } else {
            /* no remaining input: last block came from previously buffered data
             * (should not happen because we handled buffer earlier), but handle
             * conservatively by returning error */
            return 0;
        }

        ctx->final_used = 1;
        if (outl != NULL)
            *outl = produced;
        ctx->buf_len = 0;
        return 1;
    }
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

    /* Custom cipher: delegate finalisation to cipher implementation */
    if (GOST_cipher_flags(ctx->cipher) & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        ret = GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, NULL, 0);
        if (ret < 0)
            return 0;
        if (outl != NULL)
            *outl = ret;
        return 1;
    }

    b = (unsigned int)GOST_cipher_block_size(ctx->cipher);
    /* Stream cipher / byte-oriented: nothing to do */
    if (b == 1)
        return 1;

    /* No padding: buffer must be empty */
    if (ctx->flags & EVP_CIPH_NO_PADDING) {
        if (ctx->buf_len != 0)
            return 0;
        return 1;
    }

    if (ctx->encrypt) {
        /* Encryption: pad the remaining bytes and encrypt one final block */
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

    /* Decryption: must have a saved final block to check padding */
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
    if (out != NULL)
        memcpy(out, ctx->final, (size_t)n);
    if (outl != NULL)
        *outl = n;
    return 1;
}