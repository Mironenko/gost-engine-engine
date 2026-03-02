#pragma once

#include <stdint.h>
#include <stddef.h>

#include <openssl/evp.h>

#include "utils_inheritance.h"

struct gost_mac_st;
typedef struct gost_mac_st GOST_mac;

struct gost_mac_ctx_st;
typedef struct gost_mac_ctx_st GOST_mac_ctx;

typedef GOST_mac_ctx* (gost_mac_st_new_fn)(const GOST_mac *);
typedef void (gost_mac_st_free_fn)(GOST_mac_ctx *);

typedef int (gost_mac_st_init_fn)(GOST_mac_ctx *ctx);
typedef int (gost_mac_st_update_fn)(GOST_mac_ctx *ctx, const void *data, size_t count);
typedef int (gost_mac_st_final_fn)(GOST_mac_ctx *ctx, unsigned char *md);
typedef int (gost_mac_st_copy_fn)(GOST_mac_ctx *to, const GOST_mac_ctx *from);
typedef int (gost_mac_st_cleanup_fn)(GOST_mac_ctx *ctx);
typedef int (gost_mac_st_ctrl_fn)(GOST_mac_ctx *ctx, int cmd, int p1, void *p2);

typedef void (gost_mac_st_static_init_fn)(const GOST_mac *);
typedef void (gost_mac_st_static_deinit_fn)(const GOST_mac *);

struct gost_mac_st {
    DECL_BASE(const GOST_mac);

    DECL_MEMBER(int, nid);
    DECL_MEMBER(int, result_size);
    DECL_MEMBER(int, input_blocksize);
    DECL_MEMBER(int, flags);
    DECL_MEMBER(size_t, algctx_size);

    DECL_MEMBER(gost_mac_st_new_fn *, new);
    DECL_MEMBER(gost_mac_st_free_fn *, free);

    DECL_MEMBER(gost_mac_st_init_fn *, init);
    DECL_MEMBER(gost_mac_st_update_fn *, update);
    DECL_MEMBER(gost_mac_st_final_fn *, final);
    DECL_MEMBER(gost_mac_st_copy_fn *, copy);
    DECL_MEMBER(gost_mac_st_cleanup_fn *, cleanup);
    DECL_MEMBER(gost_mac_st_ctrl_fn *, ctrl);

    DECL_MEMBER(gost_mac_st_static_init_fn *, static_init);
    DECL_MEMBER(gost_mac_st_static_deinit_fn *, static_deinit);
};

IMPL_MEMBER_ACCESSOR(GOST_mac, int, nid);
IMPL_MEMBER_ACCESSOR(GOST_mac, int, result_size);
IMPL_MEMBER_ACCESSOR(GOST_mac, int, input_blocksize);
IMPL_MEMBER_ACCESSOR(GOST_mac, int, flags);
IMPL_MEMBER_ACCESSOR(GOST_mac, size_t, algctx_size);

IMPL_MEMBER_ACCESSOR(GOST_mac, gost_mac_st_new_fn *, new);
IMPL_MEMBER_ACCESSOR(GOST_mac, gost_mac_st_free_fn *, free);

IMPL_MEMBER_ACCESSOR(GOST_mac, gost_mac_st_init_fn *, init);
IMPL_MEMBER_ACCESSOR(GOST_mac, gost_mac_st_update_fn *, update);
IMPL_MEMBER_ACCESSOR(GOST_mac, gost_mac_st_final_fn *, final);
IMPL_MEMBER_ACCESSOR(GOST_mac, gost_mac_st_copy_fn *, copy);
IMPL_MEMBER_ACCESSOR(GOST_mac, gost_mac_st_cleanup_fn *, cleanup);
IMPL_MEMBER_ACCESSOR(GOST_mac, gost_mac_st_ctrl_fn *, ctrl);

IMPL_MEMBER_ACCESSOR(GOST_mac, gost_mac_st_static_init_fn *, static_init);
IMPL_MEMBER_ACCESSOR(GOST_mac, gost_mac_st_static_deinit_fn *, static_deinit);

struct gost_mac_ctx_st {
    const GOST_mac *cls;
    void *algctx;
    unsigned long flags;
};

#define EVP_MD_CTRL_KEY_LEN (EVP_MD_CTRL_ALG_CTRL+3)
#define EVP_MD_CTRL_SET_KEY (EVP_MD_CTRL_ALG_CTRL+4)

// GOST_MAC_CTX* GOST_MAC_CTX_new(const GOST_MAC *mac);
// void GOST_MAC_CTX_free(GOST_MAC_CTX *ctx);
// GOST_MAC_CTX *GOST_MAC_CTX_dup(const GOST_MAC_CTX *src);
// GOST_MAC_CTX *GOST_MAC_CTX_get0_mac(EVP_MAC_CTX *ctx);
// int GOST_MAC_CTX_init(GOST_MAC_CTX *ctx);
// int GOST_MAC_CTX_update(GOST_MAC_CTX *ctx, const unsigned char *data, size_t datalen);
// int GOST_MAC_CTX_update(GOST_MAC_CTX *ctx, const unsigned char *data, size_t datalen);


void* GOST_mac_ctx_data(const GOST_mac_ctx*);
void GOST_mac_ctx_set_flags(GOST_mac_ctx *ctx, int flags);
int GOST_mac_ctx_test_flags(const GOST_mac_ctx *ctx, int flags);

struct gost_mac_key {
    int mac_param_nid;
    unsigned char key[32];
    short int mac_size;
};
