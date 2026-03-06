#include "gost_mac.h"
#include <openssl/evp.h>

void* GOST_mac_ctx_data(const GOST_mac_ctx* ctx) {
	return ctx->algctx;
}

void GOST_mac_ctx_set_flags(GOST_mac_ctx *ctx, int flags)
{
    ctx->flags |= flags;
}

int GOST_mac_ctx_test_flags(const GOST_mac_ctx *ctx, int flags)
{
    return (ctx->flags & flags);
}

int GOST_mac_ctx_init(GOST_mac_ctx *ctx) {
    if (GOST_mac_ctx_test_flags(ctx, EVP_MD_CTX_FLAG_NO_INIT)) {
        return 1;
    }

    return GET_MEMBER(GOST_mac, ctx->cls, init)(ctx);
}
