/**********************************************************************
 *                          md_gost.c                                 *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *             Copyright (c) 2020 Vitaly Chikunov <vt@altlinux.org>   *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *       OpenSSL interface to GOST R 34.11-94 hash functions          *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
#include <string.h>

#include <openssl/evp.h>

#include "gost_digest_3411_94.h"
#include "gost_digest_3411_2012.h"
#include "e_gost_err.h"

/* implementation of GOST 34.11 hash function See gost_md.c*/
static int gost_digest_init(EVP_MD_CTX *ctx);
static int gost_digest_update(EVP_MD_CTX *ctx, const void *data,
                              size_t count);
static int gost_digest_final(EVP_MD_CTX *ctx, unsigned char *md);
static int gost_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
static int gost_digest_cleanup(EVP_MD_CTX *ctx);

struct digest_md_st {
    const GOST_digest* d;
    EVP_MD* md;
};

static const GOST_digest* digests[] = {
    &GostR3411_94_digest,
    &GostR3411_2012_256_digest,
    &GostR3411_2012_512_digest
};

static const GOST_digest* get_digest(int nid) {
    size_t i = 0;
    for (; i < sizeof(digests)/sizeof(digests[0]); ++i){
        if (GET_MEMBER(GOST_digest, digests[i], nid) == nid) {
            return digests[i];
        }
    }
    return NULL;
}

static int gost_digest_init(EVP_MD_CTX *c)
{
    const EVP_MD *md = EVP_MD_CTX_get0_md(c);
    const GOST_digest *d = get_digest(EVP_MD_nid(md));
    GOST_digest_ctx *ctx = (GOST_digest_ctx*)EVP_MD_CTX_md_data(c);
    
    if (!ctx->cls) {
        ctx = GET_MEMBER(GOST_digest, d, placement_new)(d, ctx);
    }
    
    if (!ctx) {
        return 0;
    }

    return GET_MEMBER(GOST_digest, d, init)(ctx);
}

static int gost_digest_update(EVP_MD_CTX *c, const void *data, size_t count)
{
    GOST_digest_ctx *ctx = (GOST_digest_ctx*)EVP_MD_CTX_md_data(c);
    return GET_MEMBER(GOST_digest, ctx->cls, update)(ctx, data, count);
}

static int gost_digest_final(EVP_MD_CTX *c, unsigned char *md)
{
    GOST_digest_ctx *ctx = (GOST_digest_ctx*)EVP_MD_CTX_md_data(c);
    return GET_MEMBER(GOST_digest, ctx->cls, final)(ctx, md);
}

static int gost_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    GOST_digest_ctx *to_ctx = EVP_MD_CTX_md_data(to);
    GOST_digest_ctx *from_ctx = EVP_MD_CTX_md_data(from);

    size_t algctx_size = GET_MEMBER(GOST_digest, from_ctx->cls, algctx_size);
    to_ctx->algctx = OPENSSL_zalloc(algctx_size);
    if (!to_ctx->algctx) {
        return 0;
    }
    memcpy(to_ctx->algctx, from_ctx->algctx, algctx_size);
    int r = GET_MEMBER(GOST_digest, from_ctx->cls, copy)(to_ctx, from_ctx);
    if (r <= 0) {
        OPENSSL_free(to_ctx->algctx);
    }

    return r;
}

static int gost_digest_cleanup(EVP_MD_CTX *c)
{
    GOST_digest_ctx *ctx = (GOST_digest_ctx*)EVP_MD_CTX_md_data(c);
    return GET_MEMBER(GOST_digest, ctx->cls, cleanup)(ctx);
}

static EVP_MD *GOST_init_digest_new(const GOST_digest *d);

EVP_MD *GOST_init_digest_94() {
    return GOST_init_digest_new(&GostR3411_94_digest);
}

EVP_MD *GOST_init_digest_2012_256() {
    return GOST_init_digest_new(&GostR3411_2012_256_digest);
}

EVP_MD *GOST_init_digest_2012_512() {
    return GOST_init_digest_new(&GostR3411_2012_512_digest);
}

static EVP_MD *GOST_init_digest_new(const GOST_digest *d)
{
    EVP_MD *md;
    if (!(md = EVP_MD_meth_new(GET_MEMBER(GOST_digest, d, nid), NID_undef))
        || !EVP_MD_meth_set_result_size(md, GET_MEMBER(GOST_digest, d, result_size))
        || !EVP_MD_meth_set_input_blocksize(md, GET_MEMBER(GOST_digest, d, input_blocksize))
        || !EVP_MD_meth_set_app_datasize(md, sizeof(GOST_digest_ctx))
        || !EVP_MD_meth_set_flags(md, GET_MEMBER(GOST_digest, d, flags))
        || !EVP_MD_meth_set_init(md, gost_digest_init)
        || !EVP_MD_meth_set_update(md, gost_digest_update)
        || !EVP_MD_meth_set_final(md, gost_digest_final)
        || !EVP_MD_meth_set_copy(md, gost_digest_copy)
        || !EVP_MD_meth_set_cleanup(md, gost_digest_cleanup)
        || !EVP_MD_meth_set_ctrl(md, NULL)) {
        EVP_MD_meth_free(md);
        md = NULL;
    }
    GET_MEMBER(GOST_digest, d, static_init)(d);
    return md;
}

void GOST_deinit_digest_new(GOST_digest *d)
{
    GET_MEMBER(GOST_digest, d, static_deinit)(d);
}
