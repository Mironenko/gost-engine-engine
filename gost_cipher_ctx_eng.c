#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "gost_lcl.h"

/* Engine-specific GOST_cipher_ctx implementation.
 * This implementation wraps an EVP_CIPHER_CTX and a pointer to the
 * corresponding GOST_cipher descriptor. All operations are forwarded to
 * the underlying EVP_CIPHER_CTX or to the GOST_cipher descriptor as needed.
 */

struct gost_cipher_ctx_st {
    const GOST_cipher *cipher;   /* cipher descriptor */
    EVP_CIPHER_CTX *cctx;        /* underlying EVP context */
};

// GOST_cipher_ctx *GOST_cipher_ctx_new(void)
// {
//     return NULL;
//     // GOST_cipher_ctx *ctx = OPENSSL_zalloc(sizeof(*ctx));
//     // if (ctx == NULL)
//     //     return NULL;
//     // ctx->cctx = EVP_CIPHER_CTX_new();
//     // if (ctx->cctx == NULL) {
//     //     OPENSSL_free(ctx);
//     //     return NULL;
//     // }
//     // return ctx;
// }

// void GOST_cipher_ctx_free(GOST_cipher_ctx *ctx)
// {
//     return NULL;
// }

GOST_cipher_ctx GOST_cipher_ctx_val(GOST_cipher* cipher, EVP_CIPHER_CTX *cctx)
{
    GOST_cipher_ctx gctx = {
        .cipher = cipher,
        .cctx = cctx
    };
    return gctx;
}

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

// int GOST_CipherInit_ex(GOST_cipher_ctx *ctx, const GOST_cipher *cipher,
//                        const unsigned char *key, const unsigned char *iv,
//                        int enc)
// {
//     if (ctx == NULL || ctx->cctx == NULL)
//         return 0;

//     if (cipher != NULL) {
//         ctx->cipher = cipher;
//         /* Set underlying EVP_CIPHER from gid-nid mapping via GOST_init_cipher */
//         EVP_CIPHER *evp_cipher = GOST_init_cipher((GOST_cipher *)cipher);
//         if (evp_cipher == NULL)
//             return 0;
//         if (!EVP_CipherInit_ex(ctx->cctx, evp_cipher, NULL, NULL, NULL, enc))
//             return 0;
//     }

//     /* Forward key/iv to underlying EVP context */
//     if (key != NULL || iv != NULL) {
//         if (!EVP_CipherInit_ex(ctx->cctx, NULL, NULL, key, iv, -1))
//             return 0;
//     }

//     return 1;
// }

// int GOST_CipherUpdate(GOST_cipher_ctx *ctx, unsigned char *out, int *outl,
//                       const unsigned char *in, int inl)
// {
//     if (ctx == NULL || ctx->cctx == NULL)
//         return 0;
//     int ret = EVP_CipherUpdate(ctx->cctx, out, outl, in, inl);
//     return ret != 0;
// }

// int GOST_CipherFinal(GOST_cipher_ctx *ctx, unsigned char *out, int *outl)
// {
//     if (ctx == NULL || ctx->cctx == NULL)
//         return 0;
//     int ret = EVP_CipherFinal_ex(ctx->cctx, out, outl);
//     return ret != 0;
// }
