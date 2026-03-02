 #include <openssl/crypto.h>

#include "gost_mac_base.h"

static void gost_mac_static_init(const GOST_mac* m);
static void gost_mac_static_deinit(const GOST_mac* m);

static GOST_mac_ctx* gost_mac_new(const GOST_mac* m);
static void gost_mac_free(GOST_mac_ctx* ctx);

const GOST_mac Gost_mac_base = {
    INIT_MEMBER(static_init, gost_mac_static_init),
    INIT_MEMBER(static_deinit, gost_mac_static_deinit),
    INIT_MEMBER(new, gost_mac_new),
    INIT_MEMBER(free, gost_mac_free),
};

static GOST_mac_ctx* gost_mac_new(const GOST_mac *m)
{
    GOST_mac_ctx *ctx = (GOST_mac_ctx*)OPENSSL_zalloc(sizeof(GOST_mac_ctx));
    if (!ctx)
        return ctx;

    ctx->cls = m;
    ctx->algctx = OPENSSL_zalloc(GET_MEMBER(GOST_mac, m, algctx_size));
    if (!ctx->algctx) {
        OPENSSL_free(ctx);
        ctx = NULL;
    }

    return ctx;
}

void gost_mac_free(GOST_mac_ctx *ctx)
{
    if (!ctx)
        return;

    OPENSSL_free(ctx->algctx);
    OPENSSL_free(ctx);
}

static void gost_mac_static_init(const GOST_mac* m) {
}

static void gost_mac_static_deinit(const GOST_mac* m) {
}
