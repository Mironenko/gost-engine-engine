#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "gost_lcl.h"
#include "gost_eng_cipher.h"

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

static EVP_CIPHER *GOST_init_cipher(GOST_cipher *c)
{
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

    EVP_CIPHER *cipher = NULL;
    flags |= EVP_CIPH_CUSTOM_COPY;

    if (!(cipher = EVP_CIPHER_meth_new(c->nid, block_size, TPL(c, key_len)))
        || !EVP_CIPHER_meth_set_iv_length(cipher, TPL(c, iv_len))
        || !EVP_CIPHER_meth_set_flags(cipher, flags)
        || !EVP_CIPHER_meth_set_init(cipher, gost_engine_cipher_init)
        || !EVP_CIPHER_meth_set_do_cipher(cipher, gost_engine_cipher_do_cipher)
        || !EVP_CIPHER_meth_set_cleanup(cipher, gost_engine_cipher_cleanup)
        || !EVP_CIPHER_meth_set_impl_ctx_size(cipher, (int)sizeof(GOST_cipher_ctx *))
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

    EVP_CIPHER *m = GOST_init_cipher(c->cipher);
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
        if (list[i]->nid == nid)
            return list[i];
    }
    return NULL;
}

static GOST_cipher_ctx **gost_engine_get_gctx_slot(EVP_CIPHER_CTX *ctx)
{
    return (GOST_cipher_ctx **)EVP_CIPHER_CTX_get_cipher_data(ctx);
}

static GOST_cipher_ctx *gost_engine_get_gctx(EVP_CIPHER_CTX *ctx)
{
    GOST_cipher_ctx **slot = gost_engine_get_gctx_slot(ctx);
    return slot != NULL ? *slot : NULL;
}

static int gost_engine_ensure_gctx(EVP_CIPHER_CTX *ctx)
{
    GOST_cipher_ctx **slot = gost_engine_get_gctx_slot(ctx);
    GOST_cipher_ctx *gctx;

    if (slot == NULL)
        return 0;
    if (*slot != NULL)
        return 1;

    gctx = GOST_cipher_ctx_new();
    if (gctx == NULL)
        return 0;
    *slot = gctx;
    return 1;
}

int gost_engine_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc)
{
    const EVP_CIPHER *cipher = EVP_CIPHER_CTX_cipher(ctx);
    GOST_cipher *desc;

    if (cipher == NULL)
        return 0;
    desc = gost_cipher_from_nid(EVP_CIPHER_nid(cipher));
    if (desc == NULL)
        return 0;
    if (!GOST_cipher_init(desc) || !gost_engine_ensure_gctx(ctx))
        return 0;
    return GOST_CipherInit_ex(gost_engine_get_gctx(ctx), desc, key, iv, enc);
}

int gost_engine_cipher_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 const unsigned char *in, size_t inl)
{
    int outl = 0;
    GOST_cipher_ctx *gctx = gost_engine_get_gctx(ctx);

    if (gctx == NULL)
        return 0;
    return GOST_CipherUpdate(gctx, out, &outl, in, (int)inl);
}

int gost_engine_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    GOST_cipher_ctx *gctx = gost_engine_get_gctx(ctx);

    if (gctx == NULL)
        return 1;
    *gost_engine_get_gctx_slot(ctx) = NULL;
    GOST_cipher_ctx_free(gctx);
    return 1;
}

int gost_engine_cipher_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    GOST_cipher_ctx *gctx = gost_engine_get_gctx(ctx);

    if (type == EVP_CTRL_INIT)
        return gost_engine_ensure_gctx(ctx);
    if (gctx == NULL)
        return 0;
    if (type == EVP_CTRL_COPY && ptr != NULL) {
        EVP_CIPHER_CTX *out = ptr;
        GOST_cipher_ctx **outslot = gost_engine_get_gctx_slot(out);
        GOST_cipher_ctx *outg;

        if (outslot == NULL)
            return 0;

        if (*outslot != NULL && *outslot != gctx)
            GOST_cipher_ctx_free(*outslot);

        outg = GOST_cipher_ctx_new();
        if (outg == NULL)
            return 0;

        *outslot = outg;
        return GOST_cipher_ctx_copy(outg, gctx);
    }
    return GOST_cipher_ctx_ctrl(gctx, type, arg, ptr);
}

int gost_engine_cipher_set_asn1_parameters(EVP_CIPHER_CTX *ctx,
                                           ASN1_TYPE *params)
{
    const EVP_CIPHER *cipher = EVP_CIPHER_CTX_cipher(ctx);
    GOST_cipher *desc;
    GOST_cipher_ctx *gctx = gost_engine_get_gctx(ctx);

    if (cipher == NULL || gctx == NULL)
        return 0;
    desc = gost_cipher_from_nid(EVP_CIPHER_nid(cipher));
    if (desc == NULL || desc->set_asn1_parameters == NULL)
        return 0;
    return desc->set_asn1_parameters(gctx, params);
}

int gost_engine_cipher_get_asn1_parameters(EVP_CIPHER_CTX *ctx,
                                           ASN1_TYPE *params)
{
    const EVP_CIPHER *cipher = EVP_CIPHER_CTX_cipher(ctx);
    GOST_cipher *desc;
    GOST_cipher_ctx *gctx = gost_engine_get_gctx(ctx);

    if (cipher == NULL || gctx == NULL)
        return 0;
    desc = gost_cipher_from_nid(EVP_CIPHER_nid(cipher));
    if (desc == NULL || desc->get_asn1_parameters == NULL)
        return 0;
    return desc->get_asn1_parameters(gctx, params);
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
