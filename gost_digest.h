#pragma once

#include <stddef.h>
#include <stdint.h>

#include "utils_inheritance.h"

struct gost_digest_new_st;
typedef struct gost_digest_new_st GOST_digest;

struct gost_digest_ctx_st;
typedef struct gost_digest_ctx_st GOST_digest_ctx;

typedef GOST_digest_ctx* (gost_digest_st_new_fn)(const GOST_digest *);
typedef GOST_digest_ctx* (gost_digest_st_placement_new_fn)(const GOST_digest *, void *);
typedef void (gost_digest_st_free_fn)(GOST_digest_ctx *);

typedef int (gost_digest_st_init_fn)(GOST_digest_ctx *ctx);
typedef int (gost_digest_st_update_fn)(GOST_digest_ctx *ctx, const void *data, size_t count);
typedef int (gost_digest_st_final_fn)(GOST_digest_ctx *ctx, unsigned char *md);
typedef int (gost_digest_st_copy_fn)(GOST_digest_ctx *to, const GOST_digest_ctx *from);
typedef int (gost_digest_st_cleanup_fn)(GOST_digest_ctx *ctx);
typedef int (gost_digest_st_ctrl_fn)(GOST_digest_ctx *ctx, int cmd, int p1, void *p2);

typedef void (gost_digest_st_static_init_fn)(const GOST_digest *);
typedef void (gost_digest_st_static_deinit_fn)(const GOST_digest *);

struct gost_digest_new_st {
    DECL_BASE(const GOST_digest);

    DECL_MEMBER(int, nid);
    DECL_MEMBER(const char *, alias);
    DECL_MEMBER(int, result_size);
    DECL_MEMBER(int, input_blocksize);
    DECL_MEMBER(int, flags);
    DECL_MEMBER(const char *, micalg);
    DECL_MEMBER(size_t, algctx_size);

    DECL_MEMBER(gost_digest_st_new_fn *, new);
    DECL_MEMBER(gost_digest_st_placement_new_fn *, placement_new);
    DECL_MEMBER(gost_digest_st_free_fn *, free);
    DECL_MEMBER(gost_digest_st_init_fn *, init);
    DECL_MEMBER(gost_digest_st_update_fn *, update);
    DECL_MEMBER(gost_digest_st_final_fn *, final);
    DECL_MEMBER(gost_digest_st_copy_fn *, copy);
    DECL_MEMBER(gost_digest_st_cleanup_fn *, cleanup);
    DECL_MEMBER(gost_digest_st_ctrl_fn *, ctrl);

    DECL_MEMBER(gost_digest_st_static_init_fn *, static_init);
    DECL_MEMBER(gost_digest_st_static_deinit_fn *, static_deinit);
};

IMPL_MEMBER_ACCESSOR(GOST_digest, int, nid);
IMPL_MEMBER_ACCESSOR(GOST_digest, const char *, alias);
IMPL_MEMBER_ACCESSOR(GOST_digest, int, result_size);
IMPL_MEMBER_ACCESSOR(GOST_digest, int, input_blocksize);
IMPL_MEMBER_ACCESSOR(GOST_digest, int, flags);
IMPL_MEMBER_ACCESSOR(GOST_digest, const char *, micalg);
IMPL_MEMBER_ACCESSOR(GOST_digest, size_t, algctx_size);

IMPL_MEMBER_ACCESSOR(GOST_digest, gost_digest_st_new_fn *, new);
IMPL_MEMBER_ACCESSOR(GOST_digest, gost_digest_st_placement_new_fn *, placement_new);
IMPL_MEMBER_ACCESSOR(GOST_digest, gost_digest_st_free_fn *, free);
IMPL_MEMBER_ACCESSOR(GOST_digest, gost_digest_st_init_fn *, init);
IMPL_MEMBER_ACCESSOR(GOST_digest, gost_digest_st_update_fn *, update);
IMPL_MEMBER_ACCESSOR(GOST_digest, gost_digest_st_final_fn *, final);
IMPL_MEMBER_ACCESSOR(GOST_digest, gost_digest_st_copy_fn *, copy);
IMPL_MEMBER_ACCESSOR(GOST_digest, gost_digest_st_cleanup_fn *, cleanup);
IMPL_MEMBER_ACCESSOR(GOST_digest, gost_digest_st_ctrl_fn *, ctrl);

IMPL_MEMBER_ACCESSOR(GOST_digest, gost_digest_st_static_init_fn *, static_init);
IMPL_MEMBER_ACCESSOR(GOST_digest, gost_digest_st_static_deinit_fn *, static_deinit);

struct gost_digest_ctx_st {
    const GOST_digest* cls;
    void* algctx;
};

void* GOST_digest_ctx_data(const GOST_digest_ctx* ctx);
