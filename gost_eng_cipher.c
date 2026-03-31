#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "gost_lcl.h"
#include "gost_eng_cipher.h"
#include "gost_cipher_ctx.h"

struct gost_eng_cipher_st {
    GOST_cipher *cipher;
    EVP_CIPHER *evp_cipher;
};

int gost_engine_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc);
int gost_engine_cipher_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 const unsigned char *in, size_t inl);
int gost_engine_cipher_cleanup(EVP_CIPHER_CTX *ctx);
int gost_engine_cipher_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int gost_engine_cipher_set_asn1_parameters(EVP_CIPHER_CTX *ctx,
                                           ASN1_TYPE *params);
int gost_engine_cipher_get_asn1_parameters(EVP_CIPHER_CTX *ctx,
                                           ASN1_TYPE *params);

static EVP_CIPHER *gost_evp_cipher_new(GOST_cipher *c)
{
    /* Some sanity checking. */
    int flags = GOST_cipher_flags(c) | EVP_CIPH_CUSTOM_COPY;
    int block_size = GOST_cipher_block_size(c);

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

    if (GOST_cipher_iv_length(c) != 0)
        OPENSSL_assert(flags & EVP_CIPH_CUSTOM_IV);
    else
        OPENSSL_assert(!(flags & EVP_CIPH_CUSTOM_IV));

    EVP_CIPHER *cipher = NULL;
    if (!(cipher = EVP_CIPHER_meth_new(GOST_cipher_nid(c), block_size,
                                       GOST_cipher_key_length(c)))
        || !EVP_CIPHER_meth_set_iv_length(cipher, GOST_cipher_iv_length(c))
        || !EVP_CIPHER_meth_set_flags(cipher, flags)
        || !EVP_CIPHER_meth_set_init(cipher, gost_engine_cipher_init)
        || !EVP_CIPHER_meth_set_do_cipher(cipher, gost_engine_cipher_do_cipher)
        || !EVP_CIPHER_meth_set_cleanup(cipher, gost_engine_cipher_cleanup)
        || !EVP_CIPHER_meth_set_impl_ctx_size(cipher, (int)GOST_cipher_ctx_sizeof())
        || !EVP_CIPHER_meth_set_set_asn1_params(cipher, gost_engine_cipher_set_asn1_parameters)
        || !EVP_CIPHER_meth_set_get_asn1_params(cipher, gost_engine_cipher_get_asn1_parameters)
        || !EVP_CIPHER_meth_set_ctrl(cipher, gost_engine_cipher_ctrl)) {
        EVP_CIPHER_meth_free(cipher);
        cipher = NULL;
    }
    return cipher;
}

/* Wrapper functions to expose GOST_cipher descriptors as EVP_CIPHER objects
 * cached in GOST_eng_cipher structures. */
EVP_CIPHER *GOST_eng_cipher_init(GOST_eng_cipher *c)
{
    if (c->evp_cipher)
        return c->evp_cipher;

    EVP_CIPHER *m = gost_evp_cipher_new(c->cipher);
    c->evp_cipher = m;
    return m;
}

void GOST_eng_cipher_deinit(GOST_eng_cipher *c)
{
    EVP_CIPHER_meth_free(c->evp_cipher);
    c->evp_cipher = NULL;
}

int GOST_eng_cipher_nid(const GOST_eng_cipher *c)
{
    return GOST_cipher_nid(c->cipher);
}

static GOST_eng_cipher *gost_eng_cipher_from_desc(GOST_cipher *cipher)
{
    struct gost_cipher_binding_st {
        GOST_cipher *cipher;
        GOST_eng_cipher *eng_cipher;
    };
    static struct gost_cipher_binding_st list[] = {
        { &Gost28147_89_cipher, &ENG_CIPHER_NAME(Gost28147_89_cipher) },
        { &Gost28147_89_cbc_cipher, &ENG_CIPHER_NAME(Gost28147_89_cbc_cipher) },
        { &Gost28147_89_cnt_cipher, &ENG_CIPHER_NAME(Gost28147_89_cnt_cipher) },
        { &Gost28147_89_cnt_12_cipher, &ENG_CIPHER_NAME(Gost28147_89_cnt_12_cipher) },
        { &magma_ctr_cipher, &ENG_CIPHER_NAME(magma_ctr_cipher) },
        { &magma_ctr_acpkm_cipher, &ENG_CIPHER_NAME(magma_ctr_acpkm_cipher) },
        { &magma_ctr_acpkm_omac_cipher, &ENG_CIPHER_NAME(magma_ctr_acpkm_omac_cipher) },
        { &magma_ecb_cipher, &ENG_CIPHER_NAME(magma_ecb_cipher) },
        { &magma_cbc_cipher, &ENG_CIPHER_NAME(magma_cbc_cipher) },
        { &magma_mgm_cipher, &ENG_CIPHER_NAME(magma_mgm_cipher) },
        { &grasshopper_ecb_cipher, &ENG_CIPHER_NAME(grasshopper_ecb_cipher) },
        { &grasshopper_cbc_cipher, &ENG_CIPHER_NAME(grasshopper_cbc_cipher) },
        { &grasshopper_cfb_cipher, &ENG_CIPHER_NAME(grasshopper_cfb_cipher) },
        { &grasshopper_ofb_cipher, &ENG_CIPHER_NAME(grasshopper_ofb_cipher) },
        { &grasshopper_ctr_cipher, &ENG_CIPHER_NAME(grasshopper_ctr_cipher) },
        { &grasshopper_mgm_cipher, &ENG_CIPHER_NAME(grasshopper_mgm_cipher) },
        { &grasshopper_ctr_acpkm_cipher, &ENG_CIPHER_NAME(grasshopper_ctr_acpkm_cipher) },
        { &grasshopper_ctr_acpkm_omac_cipher, &ENG_CIPHER_NAME(grasshopper_ctr_acpkm_omac_cipher) },
        { &magma_kexp15_cipher, &ENG_CIPHER_NAME(magma_kexp15_cipher) },
        { &kuznyechik_kexp15_cipher, &ENG_CIPHER_NAME(kuznyechik_kexp15_cipher) },
    };
    size_t i;

    for (i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (list[i].cipher == cipher)
            return list[i].eng_cipher;
    }
    return NULL;
}

EVP_CIPHER *GOST_init_cipher(GOST_cipher *c)
{
    GOST_eng_cipher *eng_cipher = gost_eng_cipher_from_desc(c);

    if (eng_cipher == NULL)
        return NULL;
    return GOST_eng_cipher_init(eng_cipher);
}

void GOST_deinit_cipher(GOST_cipher *c)
{
    /*
     * Legacy provider compatibility entrypoint. The actual EVP_CIPHER cache is
     * owned by GOST_eng_cipher and released during engine teardown.
     */
    (void)c;
}

static GOST_cipher *gost_cipher_from_nid(int nid)
{
    GOST_cipher *list[] = {
        &Gost28147_89_cipher,
        &Gost28147_89_cbc_cipher,
        &Gost28147_89_cnt_cipher,
        &Gost28147_89_cnt_12_cipher,
        &magma_ctr_cipher,
        &magma_ctr_acpkm_cipher,
        &magma_ctr_acpkm_omac_cipher,
        &magma_ecb_cipher,
        &magma_cbc_cipher,
        &magma_mgm_cipher,
        &grasshopper_ecb_cipher,
        &grasshopper_cbc_cipher,
        &grasshopper_cfb_cipher,
        &grasshopper_ofb_cipher,
        &grasshopper_ctr_cipher,
        &grasshopper_mgm_cipher,
        &grasshopper_ctr_acpkm_cipher,
        &grasshopper_ctr_acpkm_omac_cipher,
        &magma_kexp15_cipher,
        &kuznyechik_kexp15_cipher
    };
    size_t i;

    for (i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (GOST_cipher_nid(list[i]) == nid)
            return list[i];
    }
    return NULL;
}

static GOST_cipher_ctx *gost_engine_cipher_ctx(EVP_CIPHER_CTX *ctx)
{
    return EVP_CIPHER_CTX_get_cipher_data(ctx);
}

static GOST_cipher *gost_engine_cipher_desc(EVP_CIPHER_CTX *ctx, GOST_cipher_ctx *gctx)
{
    const EVP_CIPHER *cipher = EVP_CIPHER_CTX_cipher(ctx);
    const GOST_cipher *desc = GOST_cipher_ctx_cipher(gctx);

    if (desc != NULL)
        return (GOST_cipher *)desc;
    if (cipher == NULL)
        return NULL;

    return gost_cipher_from_nid(EVP_CIPHER_nid(cipher));
}

static void gost_engine_cipher_sync(EVP_CIPHER_CTX *ctx, GOST_cipher_ctx *gctx)
{
    int iv_len;

    if (ctx == NULL || gctx == NULL)
        return;

    iv_len = GOST_cipher_ctx_iv_length(gctx);
    if (iv_len > 0) {
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), GOST_cipher_ctx_iv_noconst(gctx),
               (size_t)iv_len);
        memcpy((unsigned char *)EVP_CIPHER_CTX_original_iv(ctx),
               GOST_cipher_ctx_original_iv(gctx), (size_t)iv_len);
    }
    EVP_CIPHER_CTX_set_num(ctx, GOST_cipher_ctx_num(gctx));
}

int gost_engine_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc)
{
    GOST_cipher_ctx *gctx = gost_engine_cipher_ctx(ctx);
    GOST_cipher *desc = gost_engine_cipher_desc(ctx, gctx);
    int ret;

    if (gctx == NULL || desc == NULL)
        return 0;

    ret = GOST_CipherInit_ex(gctx, desc, key, iv, enc);
    if (ret > 0)
        gost_engine_cipher_sync(ctx, gctx);
    return ret;
}

int gost_engine_cipher_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 const unsigned char *in, size_t inl)
{
    GOST_cipher_ctx *gctx = gost_engine_cipher_ctx(ctx);
    const GOST_cipher *desc;
    int ret;

    if (gctx == NULL)
        return 0;
    desc = GOST_cipher_ctx_cipher(gctx);
    if (desc == NULL || GOST_cipher_do_cipher_fn(desc) == NULL)
        return 1;

    ret = GOST_cipher_do_cipher_fn(desc)(gctx, out, in, inl);
    if (ret > 0)
        gost_engine_cipher_sync(ctx, gctx);
    return ret;
}

int gost_engine_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    GOST_cipher_ctx *gctx = gost_engine_cipher_ctx(ctx);

    if (gctx == NULL)
        return 0;

    return GOST_cipher_ctx_cleanup(gctx);
}

int gost_engine_cipher_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    GOST_cipher_ctx *gctx = gost_engine_cipher_ctx(ctx);
    int ret;

    if (gctx == NULL)
        return 0;
    if (type == EVP_CTRL_INIT)
        return 1;
    if (type == EVP_CTRL_COPY) {
        EVP_CIPHER_CTX *out = ptr;
        GOST_cipher_ctx *out_ctx;

        if (out == NULL)
            return 0;
        out_ctx = gost_engine_cipher_ctx(out);
        if (out_ctx == NULL)
            return 0;
        return GOST_cipher_ctx_copy(out_ctx, gctx);
    }

    ret = GOST_cipher_ctx_ctrl(gctx, type, arg, ptr);
    if (ret > 0)
        gost_engine_cipher_sync(ctx, gctx);
    return ret;
}

int gost_engine_cipher_set_asn1_parameters(EVP_CIPHER_CTX *ctx,
                                           ASN1_TYPE *params)
{
    GOST_cipher_ctx *gctx = gost_engine_cipher_ctx(ctx);
    const GOST_cipher *desc;

    if (gctx == NULL)
        return 0;
    desc = GOST_cipher_ctx_cipher(gctx);
    if (desc == NULL || GOST_cipher_set_asn1_parameters_fn(desc) == NULL)
        return 1;

    return GOST_cipher_set_asn1_parameters_fn(desc)(gctx, params);
}

int gost_engine_cipher_get_asn1_parameters(EVP_CIPHER_CTX *ctx,
                                           ASN1_TYPE *params)
{
    GOST_cipher_ctx *gctx = gost_engine_cipher_ctx(ctx);
    const GOST_cipher *desc;

    if (gctx == NULL)
        return 0;
    desc = GOST_cipher_ctx_cipher(gctx);
    if (desc == NULL || GOST_cipher_get_asn1_parameters_fn(desc) == NULL)
        return 1;

    return GOST_cipher_get_asn1_parameters_fn(desc)(gctx, params);
}

/* Define engine-exposed instances for all GOST ciphers */
#define DEF_CIPHER(name) \
    GOST_eng_cipher ENG_CIPHER_NAME(name) = { &name, NULL }

DEF_CIPHER(Gost28147_89_cipher);
DEF_CIPHER(Gost28147_89_cbc_cipher);
DEF_CIPHER(Gost28147_89_cnt_cipher);
DEF_CIPHER(Gost28147_89_cnt_12_cipher);
DEF_CIPHER(magma_ctr_cipher);
DEF_CIPHER(magma_ctr_acpkm_cipher);
DEF_CIPHER(magma_ctr_acpkm_omac_cipher);
DEF_CIPHER(magma_ecb_cipher);
DEF_CIPHER(magma_cbc_cipher);
DEF_CIPHER(magma_mgm_cipher);
DEF_CIPHER(grasshopper_ecb_cipher);
DEF_CIPHER(grasshopper_cbc_cipher);
DEF_CIPHER(grasshopper_cfb_cipher);
DEF_CIPHER(grasshopper_ofb_cipher);
DEF_CIPHER(grasshopper_ctr_cipher);
DEF_CIPHER(grasshopper_mgm_cipher);
DEF_CIPHER(grasshopper_ctr_acpkm_cipher);
DEF_CIPHER(grasshopper_ctr_acpkm_omac_cipher);
DEF_CIPHER(magma_kexp15_cipher);
DEF_CIPHER(kuznyechik_kexp15_cipher);
