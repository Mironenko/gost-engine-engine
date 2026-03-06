#include <string.h>

#include <openssl/evp.h>

#include "gost_eng_digest.h"
#include "gost_mac_28147_89.h"
#include "gost_mac_3412_omac.h"
#include "gost_mac_3412_ctracpkm.h"
#include "e_gost_err.h"

/* implementation of GOST 34.11 hash function See gost_md.c*/
static int gost_digest_init(EVP_MD_CTX *ctx);
static int gost_digest_update(EVP_MD_CTX *ctx, const void *data,
                              size_t count);
static int gost_digest_final(EVP_MD_CTX *ctx, unsigned char *md);
static int gost_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
static int gost_digest_cleanup(EVP_MD_CTX *ctx);
static int gost_digest_ctrl(EVP_MD_CTX *ctx, int type, int arg, void *ptr);

static const GOST_mac* macs[] = {
    &Gost28147_89_mac,
    &Gost28147_89_mac_12,
    &magma_omac_mac,
    &grasshopper_omac_mac,
    &magma_ctracpkm_mac,
    &grasshopper_ctracpkm_mac
};

static const GOST_mac* get_mac(int nid) {
    size_t i = 0;
    for (; i < sizeof(macs)/sizeof(macs[0]); ++i){
        if (GET_MEMBER(GOST_mac, macs[i], nid) == nid) {
            return macs[i];
        }
    }
    return NULL;
}

static int gost_digest_init(EVP_MD_CTX *c)
{
    const EVP_MD *md = EVP_MD_CTX_get0_md(c);
    const GOST_mac *m = get_mac(EVP_MD_nid(md));
    GOST_mac_ctx *ctx = (GOST_mac_ctx*)EVP_MD_CTX_md_data(c);
    
    if (!ctx->cls) {
        ctx = GET_MEMBER(GOST_mac, m, placement_new)(m, ctx);
    }
    
    if (!ctx) {
        return 0;
    }

    return GOST_mac_ctx_init(ctx);
}

static int gost_digest_update(EVP_MD_CTX *c, const void *data, size_t count)
{
    GOST_mac_ctx *ctx = (GOST_mac_ctx*)EVP_MD_CTX_md_data(c);
    return GET_MEMBER(GOST_mac, ctx->cls, update)(ctx, data, count);
}

static int gost_digest_final(EVP_MD_CTX *c, unsigned char *md)
{
    GOST_mac_ctx *ctx = (GOST_mac_ctx*)EVP_MD_CTX_md_data(c);
    return GET_MEMBER(GOST_mac, ctx->cls, final)(ctx, md);
}

static int gost_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    GOST_mac_ctx *to_ctx = EVP_MD_CTX_md_data(to);
    GOST_mac_ctx *from_ctx = EVP_MD_CTX_md_data(from);

    if (!to_ctx || !from_ctx) {
        return 1;
    }

    size_t algctx_size = GET_MEMBER(GOST_mac, from_ctx->cls, algctx_size);
    to_ctx->algctx = OPENSSL_zalloc(algctx_size);
    if (!to_ctx->algctx) {
        return 0;
    }
    memcpy(to_ctx->algctx, from_ctx->algctx, algctx_size);
    int r = GET_MEMBER(GOST_mac, from_ctx->cls, copy)(to_ctx, from_ctx);
    if (r <= 0) {
        OPENSSL_free(to_ctx->algctx);
    }

    return r;
}

static int gost_digest_cleanup(EVP_MD_CTX *c)
{
    GOST_mac_ctx *ctx = (GOST_mac_ctx*)EVP_MD_CTX_md_data(c);
    if (!ctx) {
        return 0;
    }
    return GET_MEMBER(GOST_mac, ctx->cls, cleanup)(ctx);
}

static int gost_digest_ctrl(EVP_MD_CTX *c, int type, int arg, void *ptr)
{
    GOST_mac_ctx *ctx = (GOST_mac_ctx*)EVP_MD_CTX_md_data(c);
    if (!ctx->cls) {
        const EVP_MD *md = EVP_MD_CTX_get0_md(c);
        ctx->cls = get_mac(EVP_MD_nid(md));
        ctx = GET_MEMBER(GOST_mac, ctx->cls, placement_new)(ctx->cls, ctx);
    }
    if (!ctx) {
        return 0;
    }
    return GET_MEMBER(GOST_mac, ctx->cls, ctrl)(ctx, type, arg, ptr);
}

EVP_MD *GOST_eng_digest_init_from_mac(const GOST_mac *m)
{
    EVP_MD *md;
    if (!(md = EVP_MD_meth_new(GET_MEMBER(GOST_mac, m, nid), NID_undef))
        || !EVP_MD_meth_set_result_size(md, GET_MEMBER(GOST_mac, m, result_size))
        || !EVP_MD_meth_set_input_blocksize(md, GET_MEMBER(GOST_mac, m, input_blocksize))
        || !EVP_MD_meth_set_app_datasize(md, sizeof(GOST_mac_ctx))
        || !EVP_MD_meth_set_flags(md, GET_MEMBER(GOST_mac, m, flags))
        || !EVP_MD_meth_set_init(md, gost_digest_init)
        || !EVP_MD_meth_set_update(md, gost_digest_update)
        || !EVP_MD_meth_set_final(md, gost_digest_final)
        || !EVP_MD_meth_set_copy(md, gost_digest_copy)
        || !EVP_MD_meth_set_cleanup(md, gost_digest_cleanup)
        || !EVP_MD_meth_set_ctrl(md, gost_digest_ctrl)) {
        EVP_MD_meth_free(md);
        md = NULL;
    }
    GET_MEMBER(GOST_mac, m, static_init)(m);
    return md;
}

void GOST_eng_digest_deinit_from_mac(const GOST_mac *m)
{
    GET_MEMBER(GOST_mac, m, static_deinit)(m);
}
