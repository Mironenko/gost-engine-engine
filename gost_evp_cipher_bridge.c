#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "gost_lcl.h"

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
