#include "gost_mac.h"

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