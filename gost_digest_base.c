#include <openssl/evp.h>

#include "gost_digest_base.h"

static void gost_digest_static_init(GOST_digest* d);
static void gost_digest_static_deinit(const GOST_digest* d);

static GOST_digest_ctx* gost_digest_new(const GOST_digest* d);
static void gost_digest_free(GOST_digest_ctx* vctx);

const GOST_digest GostR3411_digest_base = {
    INIT_MEMBER(static_init, gost_digest_static_init),
    INIT_MEMBER(static_deinit, gost_digest_static_deinit),
    INIT_MEMBER(new, gost_digest_new),
    INIT_MEMBER(free, gost_digest_free),
};

static GOST_digest_ctx* gost_digest_new(const GOST_digest *d)
{
    GOST_digest_ctx *ctx = (GOST_digest_ctx*)OPENSSL_zalloc(sizeof(GOST_digest_ctx));
    if (!ctx)
        return ctx;

    ctx->cls = d;
    ctx->algctx = OPENSSL_zalloc(GET_MEMBER(GOST_digest, d, algctx_size));
    if (!ctx->algctx) {
        OPENSSL_free(ctx);
        ctx = NULL;
    }

    return ctx;
}

void gost_digest_free(GOST_digest_ctx *ctx)
{
    if (!ctx)
        return;

    OPENSSL_free(ctx->algctx);
    OPENSSL_free(ctx);
}

static void gost_digest_static_init(GOST_digest* d) {
    RESOLVE_MEMBER(GOST_digest, d, nid);
    RESOLVE_MEMBER(GOST_digest, d, alias);
    RESOLVE_MEMBER(GOST_digest, d, result_size);
    RESOLVE_MEMBER(GOST_digest, d, input_blocksize);
    RESOLVE_MEMBER(GOST_digest, d, flags);
    RESOLVE_MEMBER(GOST_digest, d, micalg);
    RESOLVE_MEMBER(GOST_digest, d, algctx_size);

    RESOLVE_MEMBER(GOST_digest, d, new);
    RESOLVE_MEMBER(GOST_digest, d, free);
    RESOLVE_MEMBER(GOST_digest, d, init);
    RESOLVE_MEMBER(GOST_digest, d, update);
    RESOLVE_MEMBER(GOST_digest, d, final);
    RESOLVE_MEMBER(GOST_digest, d, copy);
    RESOLVE_MEMBER(GOST_digest, d, cleanup);
    RESOLVE_MEMBER(GOST_digest, d, ctrl);

    if (GET_MEMBER(GOST_digest, d, alias))
        EVP_add_digest_alias(OBJ_nid2sn(GET_MEMBER(GOST_digest, d, nid)), GET_MEMBER(GOST_digest, d, alias));
}

static void gost_digest_static_deinit(const GOST_digest* d) {
    if (GET_MEMBER(GOST_digest, d, alias))
        EVP_delete_digest_alias(GET_MEMBER(GOST_digest, d, alias));
}
