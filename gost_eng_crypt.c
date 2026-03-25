/**********************************************************************
 *             gost_crypt.c - Initialize all ciphers                  *
 *                                                                    *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *             Copyright (c) 2020 Chikunov Vitaly <vt@altlinux.org>   *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *       OpenSSL interface to GOST 28147-89 cipher functions          *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
#include <assert.h>
#include <string.h>
#include "gost89.h"
#include <openssl/err.h>
#include <openssl/rand.h>
#include "e_gost_err.h"
#include "gost_lcl.h"
#include "gost_eng_crypt.h"
#include "gost_gost2015.h"
#include "gost_tls12_additional.h"

/*
 * Single level template accessor.
 * Note: that you cannot template 0 value.
 */
#define TPL(st,field) ( \
    ((st)->field) ? ((st)->field) : TPL_VAL(st,field) \
)

#define TPL_VAL(st,field) ( \
    ((st)->template ? (st)->template->field : 0) \
)

EVP_CIPHER *GOST_init_cipher(GOST_cipher *c)
{
    if (c->cipher)
        return c->cipher;

    /* Some sanity checking. */
    int flags = c->flags | TPL_VAL(c, flags);
    int block_size = TPL(c, block_size);
    switch (flags & EVP_CIPH_MODE) {
    case EVP_CIPH_CBC_MODE:
    case EVP_CIPH_ECB_MODE:
    case EVP_CIPH_WRAP_MODE:
        OPENSSL_assert(block_size != 1);
        OPENSSL_assert(!(flags & EVP_CIPH_NO_PADDING));
        break;
    default:
        OPENSSL_assert(block_size == 1);
        OPENSSL_assert(flags & EVP_CIPH_NO_PADDING);
    }

    if (TPL(c, iv_len))
        OPENSSL_assert(flags & EVP_CIPH_CUSTOM_IV);
    else
        OPENSSL_assert(!(flags & EVP_CIPH_CUSTOM_IV));

    EVP_CIPHER *cipher;
    if (!(cipher = EVP_CIPHER_meth_new(c->nid, block_size, TPL(c, key_len)))
        || !EVP_CIPHER_meth_set_iv_length(cipher, TPL(c, iv_len))
        || !EVP_CIPHER_meth_set_flags(cipher, flags)
        || !EVP_CIPHER_meth_set_init(cipher, TPL(c, init))
        || !EVP_CIPHER_meth_set_do_cipher(cipher, TPL(c, do_cipher))
        || !EVP_CIPHER_meth_set_cleanup(cipher, TPL(c, cleanup))
        || !EVP_CIPHER_meth_set_impl_ctx_size(cipher, TPL(c, ctx_size))
        || !EVP_CIPHER_meth_set_set_asn1_params(cipher, TPL(c, set_asn1_parameters))
        || !EVP_CIPHER_meth_set_get_asn1_params(cipher, TPL(c, get_asn1_parameters))
        || !EVP_CIPHER_meth_set_ctrl(cipher, TPL(c, ctrl))) {
        EVP_CIPHER_meth_free(cipher);
        cipher = NULL;
    }
    c->cipher = cipher;
    return c->cipher;
}

void GOST_deinit_cipher(GOST_cipher *c)
{
    if (c->cipher) {
        EVP_CIPHER_meth_free(c->cipher);
        c->cipher = NULL;
    }
}

static void mac_block_mesh(struct ossl_gost_imit_ctx *c,
                           const unsigned char *data)
{
    /*
     * We are using NULL for iv because CryptoPro doesn't interpret
     * internal state of MAC algorithm as iv during keymeshing (but does
     * initialize internal state from iv in key transport
     */
    assert(c->count % 8 == 0 && c->count <= 1024);
    if (c->key_meshing && c->count == 1024) {
        cryptopro_key_meshing(&(c->cctx), NULL);
    }
    mac_block(&(c->cctx), c->buffer, data);
    c->count = c->count % 1024 + 8;
}

static int gost_imit_init(EVP_MD_CTX *ctx, gost_subst_block * block)
{
    struct ossl_gost_imit_ctx *c = EVP_MD_CTX_md_data(ctx);
    memset(c->buffer, 0, sizeof(c->buffer));
    memset(c->partial_block, 0, sizeof(c->partial_block));
    c->count = 0;
    c->bytes_left = 0;
    c->key_meshing = 1;
    c->dgst_size = 4;
    gost_init(&(c->cctx), block);
    return 1;
}

static int gost_imit_init_cpa(EVP_MD_CTX *ctx)
{
    return gost_imit_init(ctx, &Gost28147_CryptoProParamSetA);
}

static int gost_imit_init_cp_12(EVP_MD_CTX *ctx)
{
    return gost_imit_init(ctx, &Gost28147_TC26ParamSetZ);
}

static int gost_imit_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    struct ossl_gost_imit_ctx *c = EVP_MD_CTX_md_data(ctx);
    const unsigned char *p = data;
    size_t bytes = count;
    if (!(c->key_set)) {
        GOSTerr(GOST_F_GOST_IMIT_UPDATE, GOST_R_MAC_KEY_NOT_SET);
        return 0;
    }
    if (c->bytes_left) {
        size_t i;
        for (i = c->bytes_left; i < 8 && bytes > 0; bytes--, i++, p++) {
            c->partial_block[i] = *p;
        }
        if (i == 8) {
            mac_block_mesh(c, c->partial_block);
        } else {
            c->bytes_left = i;
            return 1;
        }
    }
    while (bytes > 8) {
        mac_block_mesh(c, p);
        p += 8;
        bytes -= 8;
    }
    if (bytes > 0) {
        memcpy(c->partial_block, p, bytes);
    }
    c->bytes_left = bytes;
    return 1;
}

static int gost_imit_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    struct ossl_gost_imit_ctx *c = EVP_MD_CTX_md_data(ctx);
    if (!c->key_set) {
        GOSTerr(GOST_F_GOST_IMIT_FINAL, GOST_R_MAC_KEY_NOT_SET);
        return 0;
    }
    if (c->count == 0 && c->bytes_left) {
        unsigned char buffer[8];
        memset(buffer, 0, 8);
        gost_imit_update(ctx, buffer, 8);
    }
    if (c->bytes_left) {
        int i;
        for (i = c->bytes_left; i < 8; i++) {
            c->partial_block[i] = 0;
        }
        mac_block_mesh(c, c->partial_block);
    }
    get_mac(c->buffer, 8 * c->dgst_size, md);
    return 1;
}

static int gost_imit_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    if (EVP_MD_CTX_md_data(to) && EVP_MD_CTX_md_data(from)) {
        memcpy(EVP_MD_CTX_md_data(to), EVP_MD_CTX_md_data(from),
               sizeof(struct ossl_gost_imit_ctx));
    }
    return 1;
}

/* Clean up imit ctx */
static int gost_imit_cleanup(EVP_MD_CTX *ctx)
{
    memset(EVP_MD_CTX_md_data(ctx), 0, sizeof(struct ossl_gost_imit_ctx));
    return 1;
}

static int gost_imit_ctrl(EVP_MD_CTX *ctx, int type, int arg, void *ptr)
{
    switch (type) {
    case EVP_MD_CTRL_KEY_LEN:
        *((unsigned int *)(ptr)) = 32;
        return 1;
    case EVP_MD_CTRL_SET_KEY:
        {
            struct ossl_gost_imit_ctx *gost_imit_ctx = EVP_MD_CTX_md_data(ctx);

            if (EVP_MD_meth_get_init(EVP_MD_CTX_md(ctx)) (ctx) <= 0) {
                GOSTerr(GOST_F_GOST_IMIT_CTRL, GOST_R_MAC_KEY_NOT_SET);
                return 0;
            }
            EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NO_INIT);

            if (arg == 0) {
                struct gost_mac_key *key = (struct gost_mac_key *)ptr;
                if (key->mac_param_nid != NID_undef) {
                    const struct gost_cipher_info *param =
                        get_encryption_params(OBJ_nid2obj(key->mac_param_nid));
                    if (param == NULL) {
                        GOSTerr(GOST_F_GOST_IMIT_CTRL,
                                GOST_R_INVALID_MAC_PARAMS);
                        return 0;
                    }
                    gost_init(&(gost_imit_ctx->cctx), param->sblock);
                }
                gost_key(&(gost_imit_ctx->cctx), key->key);
                gost_imit_ctx->key_set = 1;

                return 1;
            } else if (arg == 32) {
                gost_key(&(gost_imit_ctx->cctx), ptr);
                gost_imit_ctx->key_set = 1;
                return 1;
            }
            GOSTerr(GOST_F_GOST_IMIT_CTRL, GOST_R_INVALID_MAC_KEY_SIZE);
            return 0;
        }
    case EVP_MD_CTRL_XOF_LEN:
        {
            struct ossl_gost_imit_ctx *c = EVP_MD_CTX_md_data(ctx);
            if (arg < 1 || arg > 8) {
                GOSTerr(GOST_F_GOST_IMIT_CTRL, GOST_R_INVALID_MAC_SIZE);
                return 0;
            }
            c->dgst_size = arg;
            return 1;
        }

    default:
        return 0;
    }
}

GOST_digest Gost28147_89_MAC_digest_legacy = {
    .nid = NID_id_Gost28147_89_MAC,
    .result_size = 4,
    .input_blocksize = 8,
    .app_datasize = sizeof(struct ossl_gost_imit_ctx),
    .flags = EVP_MD_FLAG_XOF,
    .init = gost_imit_init_cpa,
    .update = gost_imit_update,
    .final = gost_imit_final,
    .copy = gost_imit_copy,
    .cleanup = gost_imit_cleanup,
    .ctrl = gost_imit_ctrl,
};

GOST_digest Gost28147_89_mac_12_digest_legacy = {
    .nid = NID_gost_mac_12,
    .result_size = 4,
    .input_blocksize = 8,
    .app_datasize = sizeof(struct ossl_gost_imit_ctx),
    .flags = EVP_MD_FLAG_XOF,
    .init = gost_imit_init_cp_12,
    .update = gost_imit_update,
    .final = gost_imit_final,
    .copy = gost_imit_copy,
    .cleanup = gost_imit_cleanup,
    .ctrl = gost_imit_ctrl,
};
