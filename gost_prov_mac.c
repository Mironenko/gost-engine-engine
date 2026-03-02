/**********************************************************************
 *               gost_prov_mac.c - Initialize all macs                *
 *                                                                    *
 *      Copyright (c) 2021 Richard Levitte <richard@levitte.org>      *
 *     This file is distributed under the same license as OpenSSL     *
 *                                                                    *
 *          OpenSSL provider interface to GOST mac functions          *
 *                Requires OpenSSL 3.0 for compilation                *
 **********************************************************************/

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include "gost_prov.h"
#include "gost_mac_28147_89.h"
#include "gost_mac_3412_omac.h"
#include "gost_mac_3412_ctracpkm.h"

/*
 * Forward declarations of all generic OSSL_DISPATCH functions, to make sure
 * they are correctly defined further down.  For the algorithm specific ones
 * MAKE_FUNCTIONS() does it for us.
 */

static OSSL_FUNC_mac_dupctx_fn mac_dupctx;
static OSSL_FUNC_mac_freectx_fn mac_freectx;
static OSSL_FUNC_mac_init_fn mac_init;
static OSSL_FUNC_mac_update_fn mac_update;
static OSSL_FUNC_mac_final_fn mac_final;
static OSSL_FUNC_mac_get_ctx_params_fn mac_get_ctx_params;
static OSSL_FUNC_mac_set_ctx_params_fn mac_set_ctx_params;

struct gost_prov_mac_desc_st {
    const GOST_mac *mac_desc;
    size_t initial_mac_size;
};
typedef struct gost_prov_mac_desc_st GOST_DESC;

struct gost_prov_mac_ctx_st {
    /* Provider context */
    PROV_CTX *provctx;
    const GOST_DESC *descriptor;

    /* Output MAC size */
    size_t mac_size;
    /* XOF mode, where applicable */
    int xof_mode;

    const GOST_mac *mac;
    GOST_mac_ctx *mac_ctx;
};
typedef struct gost_prov_mac_ctx_st GOST_CTX;

static void mac_freectx(void *vgctx)
{
    GOST_CTX *gctx = vgctx;
    if (!gctx)
        return;

    GET_MEMBER(GOST_mac, gctx->mac, free)(gctx->mac_ctx);
    OPENSSL_free(gctx);
}

static GOST_CTX *mac_newctx(void *provctx, const GOST_DESC *descriptor)
{
    GOST_CTX *gctx = NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->provctx = provctx;
        gctx->descriptor = descriptor;
        gctx->mac = gctx->descriptor->mac_desc;
        gctx->mac_size = descriptor->initial_mac_size;
        gctx->mac_ctx = GET_MEMBER(GOST_mac, gctx->mac, new)(gctx->mac);

        if (gctx->mac_ctx == NULL
            || GET_MEMBER(GOST_mac, gctx->mac, init)(gctx->mac_ctx) <= 0) {
            mac_freectx(gctx);
            gctx = NULL;
        }
    }
    return gctx;
}

static void *mac_dupctx(void *vsrc)
{
    GOST_CTX *src = vsrc;
    GOST_CTX *dst =
        mac_newctx(src->provctx, src->descriptor);

    if (dst != NULL)
        GET_MEMBER(GOST_mac, src->mac, copy)(dst->mac_ctx, src->mac_ctx);
    return dst;
}

static int mac_init(void *mctx, const unsigned char *key,
                    size_t keylen, const OSSL_PARAM params[])
{
    GOST_CTX *gctx = mctx;

    return mac_set_ctx_params(gctx, params)
        && (key == NULL
            || GET_MEMBER(GOST_mac, gctx->mac, ctrl)(gctx->mac_ctx, EVP_MD_CTRL_SET_KEY,
                                                     (int)keylen, (void *)key) > 0);
}

static int mac_update(void *mctx, const unsigned char *in, size_t inl)
{
    GOST_CTX *gctx = mctx;

    return GET_MEMBER(GOST_mac, gctx->mac, update)(gctx->mac_ctx, in, inl) > 0;
}

static int mac_final(void *mctx, unsigned char *out, size_t *outl,
                     size_t outsize)
{
    GOST_CTX *gctx = mctx;
    int ret = 1;

    if (out != NULL) {
        if (outsize < gctx->mac_size)
            return 0;

        GET_MEMBER(GOST_mac, gctx->mac, ctrl)(gctx->mac_ctx, EVP_MD_CTRL_XOF_LEN, gctx->mac_size, NULL);
        ret = GET_MEMBER(GOST_mac, gctx->mac, final)(gctx->mac_ctx, out);
    }

    if (outl != NULL)
        *outl = (size_t)gctx->mac_size;

    return ret;
}

static const OSSL_PARAM *mac_gettable_params(void *provctx,
                                             const GOST_DESC * descriptor)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t("size", NULL),
        OSSL_PARAM_size_t("keylen", NULL),
        OSSL_PARAM_END
    };

    return params;
}

static const OSSL_PARAM *mac_gettable_ctx_params(void *mctx, void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t("size", NULL),
        OSSL_PARAM_size_t("keylen", NULL),
        OSSL_PARAM_END
    };

    return params;
}

static const OSSL_PARAM *mac_settable_ctx_params(void *mctx, void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t("size", NULL),
        OSSL_PARAM_octet_string("key", NULL, 0),
        OSSL_PARAM_END
    };

    return params;
}

static int mac_get_params(const GOST_DESC * descriptor, OSSL_PARAM params[])
{
    OSSL_PARAM *p = NULL;

    if (((p = OSSL_PARAM_locate(params, "size")) != NULL
         && !OSSL_PARAM_set_size_t(p, descriptor->initial_mac_size))
        || ((p = OSSL_PARAM_locate(params, "keylen")) != NULL
            && !OSSL_PARAM_set_size_t(p, 32)))
        return 0;
    return 1;
}

static int mac_get_ctx_params(void *mctx, OSSL_PARAM params[])
{
    GOST_CTX *gctx = mctx;
    OSSL_PARAM *p = NULL;

    if ((p = OSSL_PARAM_locate(params, "size")) != NULL
        && !OSSL_PARAM_set_size_t(p, gctx->mac_size))
        return 0;

    if ((p = OSSL_PARAM_locate(params, "keylen")) != NULL) {
        unsigned int len = 0;

        if (GET_MEMBER(GOST_mac, gctx->mac, ctrl)(gctx->mac_ctx, EVP_MD_CTRL_KEY_LEN, 0, &len) <= 0
            || !OSSL_PARAM_set_size_t(p, len))
            return 0;
    }

    if ((p = OSSL_PARAM_locate(params, "xof")) != NULL
        && (!(GET_MEMBER(GOST_mac, gctx->mac, flags) & EVP_MD_FLAG_XOF)
            || !OSSL_PARAM_set_int(p, gctx->xof_mode)))
        return 0;

    return 1;
}

static int mac_set_ctx_params(void *mctx, const OSSL_PARAM params[])
{
    GOST_CTX *gctx = mctx;
    const OSSL_PARAM *p = NULL;

    if ((p = OSSL_PARAM_locate_const(params, "size")) != NULL
        && !OSSL_PARAM_get_size_t(p, &gctx->mac_size))
        return 0;
    if ((p = OSSL_PARAM_locate_const(params, "key")) != NULL) {
        const unsigned char *key = NULL;
        size_t keylen = 0;
        int ret;

        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&key, &keylen))
            return 0;

        ret = GET_MEMBER(GOST_mac, gctx->mac, ctrl)(gctx->mac_ctx, EVP_MD_CTRL_SET_KEY,
                                                    (int)keylen, (void *)key);
        if (ret <= 0 && ret != -2)
            return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, "xof")) != NULL
        && (!(GET_MEMBER(GOST_mac, gctx->mac, flags) & EVP_MD_FLAG_XOF)
            || !OSSL_PARAM_get_int(p, &gctx->xof_mode)))
        return 0;
    if ((p = OSSL_PARAM_locate_const(params, "key-mesh")) != NULL) {
        size_t key_mesh = 0;
        int i_cipher_key_mesh = 0, *p_cipher_key_mesh = NULL;

        if (!OSSL_PARAM_get_size_t(p, &key_mesh))
            return 0;

        if ((p = OSSL_PARAM_locate_const(params, "cipher-key-mesh")) != NULL) {
            size_t cipher_key_mesh = 0;

            if (!OSSL_PARAM_get_size_t(p, &cipher_key_mesh)) {
                return 0;
            } else {
                i_cipher_key_mesh = (int)cipher_key_mesh;
                p_cipher_key_mesh = &i_cipher_key_mesh;
            }
        }

        if (GET_MEMBER(GOST_mac, gctx->mac, ctrl)(gctx->mac_ctx, EVP_CTRL_KEY_MESH,
                                                  key_mesh, p_cipher_key_mesh) <= 0)
            return 0;
    }
    return 1;
}

typedef void (*fptr_t)(void);
#define MAKE_FUNCTIONS(name, macsize)                                   \
    const GOST_DESC name##_desc = {                                     \
        &name,                                                          \
        macsize,                                                        \
    };                                                                  \
    static OSSL_FUNC_mac_newctx_fn name##_newctx;                       \
    static void *name##_newctx(void *provctx)                           \
    {                                                                   \
        return mac_newctx(provctx, &name##_desc);                       \
    }                                                                   \
    static OSSL_FUNC_mac_gettable_params_fn name##_gettable_params;     \
    static const OSSL_PARAM *name##_gettable_params(void *provctx)      \
    {                                                                   \
        return mac_gettable_params(provctx, &name##_desc);              \
    }                                                                   \
    static OSSL_FUNC_mac_get_params_fn name##_get_params;               \
    static int name##_get_params(OSSL_PARAM *params)                    \
    {                                                                   \
        return mac_get_params(&name##_desc, params);                    \
    }                                                                   \
    static const OSSL_DISPATCH name##_functions[] = {                   \
        { OSSL_FUNC_MAC_GETTABLE_PARAMS,                                \
          (fptr_t)name##_gettable_params },                             \
        { OSSL_FUNC_MAC_GET_PARAMS, (fptr_t)name##_get_params },        \
        { OSSL_FUNC_MAC_NEWCTX, (fptr_t)name##_newctx },                \
        { OSSL_FUNC_MAC_DUPCTX, (fptr_t)mac_dupctx },                   \
        { OSSL_FUNC_MAC_FREECTX, (fptr_t)mac_freectx },                 \
        { OSSL_FUNC_MAC_INIT, (fptr_t)mac_init },                       \
        { OSSL_FUNC_MAC_UPDATE, (fptr_t)mac_update },                   \
        { OSSL_FUNC_MAC_FINAL, (fptr_t)mac_final },                     \
        { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,                            \
          (fptr_t)mac_gettable_ctx_params },                            \
        { OSSL_FUNC_MAC_GET_CTX_PARAMS, (fptr_t)mac_get_ctx_params },   \
        { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,                            \
          (fptr_t)mac_settable_ctx_params },                            \
        { OSSL_FUNC_MAC_SET_CTX_PARAMS, (fptr_t)mac_set_ctx_params },   \
    }

MAKE_FUNCTIONS(Gost28147_89_mac, 4);
MAKE_FUNCTIONS(Gost28147_89_mac_12, 4);
MAKE_FUNCTIONS(magma_omac_mac, 8);
MAKE_FUNCTIONS(grasshopper_omac_mac, 16);
MAKE_FUNCTIONS(grasshopper_ctracpkm_mac, 16);
MAKE_FUNCTIONS(magma_ctracpkm_mac, 8);

/* The OSSL_ALGORITHM for the provider's operation query function */
const OSSL_ALGORITHM GOST_prov_macs[] = {
    { SN_id_Gost28147_89_MAC ":1.2.643.2.2.22", NULL,
      Gost28147_89_mac_functions, "GOST 28147-89 MAC" },
    { SN_gost_mac_12, NULL, Gost28147_89_mac_12_functions },
    { SN_magma_mac, NULL, magma_omac_mac_functions },
    { SN_grasshopper_mac, NULL, grasshopper_omac_mac_functions },
    { SN_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac
      ":1.2.643.7.1.1.5.2.2", NULL,
      grasshopper_ctracpkm_mac_functions },
    { SN_id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac
      ":1.2.643.7.1.1.5.1.2", NULL, magma_ctracpkm_mac_functions },
    { NULL , NULL, NULL }
};
