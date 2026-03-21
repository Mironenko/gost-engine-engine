/**********************************************************************
 *             gost_prov_crypt.c - Initialize all ciphers             *
 *                                                                    *
 *      Copyright (c) 2021 Richard Levitte <richard@levitte.org>      *
 *     This file is distributed under the same license as OpenSSL     *
 *                                                                    *
 *         OpenSSL provider interface to GOST cipher functions        *
 *                Requires OpenSSL 3.0 for compilation                *
 **********************************************************************/

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include "gost_prov.h"
#include "gost_cipher_ctx_prov.h"
#include "gost_lcl.h"

/*
 * This definitions are added in the patch to OpenSSL 3.4.2 version to support
 * GOST TLS 1.3. Definitions below must be removed when the patch is added to
 * OpenSSL upstream.
 */
#ifndef OSSL_CIPHER_PARAM_TLSTREE
# if defined(_MSC_VER)
#  pragma message("Gost-engine is built against not fully supported version of OpenSSL. \
OSSL_CIPHER_PARAM_TLSTREE definition in OpenSSL is expected.")
# else
#  warning "Gost-engine is built against not fully supported version of OpenSSL. \
OSSL_CIPHER_PARAM_TLSTREE definition in OpenSSL is expected. TLSTREE is not supported by \
the provider for cipher operations."
# endif
# define OSSL_CIPHER_PARAM_TLSTREE "tlstree"
#endif

#ifndef OSSL_CIPHER_PARAM_TLSTREE_MODE
# if defined(_MSC_VER)
#  pragma message("Gost-engine is built against not fully supported version of OpenSSL. \
OSSL_CIPHER_PARAM_TLSTREE_MODE definition in OpenSSL is expected.")
# else
#  warning "Gost-engine is built against not fully supported version of OpenSSL. \
OSSL_CIPHER_PARAM_TLSTREE_MODE definition in OpenSSL is expected. TLSTREE modes are not supported by \
the provider for encryption/decryption operations. ."
# endif
# define OSSL_CIPHER_PARAM_TLSTREE_MODE "tlstree_mode"
#endif

/*
 * Forward declarations of all generic OSSL_DISPATCH functions, to make sure
 * they are correctly defined further down.  For the algorithm specific ones
 * MAKE_FUNCTIONS() does it for us.
 */

static OSSL_FUNC_cipher_dupctx_fn cipher_dupctx;
static OSSL_FUNC_cipher_freectx_fn cipher_freectx;
static OSSL_FUNC_cipher_get_ctx_params_fn cipher_get_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn cipher_set_ctx_params;
static OSSL_FUNC_cipher_encrypt_init_fn cipher_encrypt_init;
static OSSL_FUNC_cipher_decrypt_init_fn cipher_decrypt_init;
static OSSL_FUNC_cipher_update_fn cipher_update;
static OSSL_FUNC_cipher_final_fn cipher_final;

struct gost_prov_crypt_ctx_st {
    PROV_CTX *provctx;
    GOST_cipher *descriptor;
    GOST_cipher_ctx *cctx;
};
typedef struct gost_prov_crypt_ctx_st GOST_CTX;

static void cipher_freectx(void *vgctx)
{
    GOST_CTX *gctx = vgctx;

    if (gctx == NULL)
        return;
    GOST_cipher_ctx_free(gctx->cctx);
    OPENSSL_free(gctx);
}

static GOST_CTX *cipher_newctx(void *provctx, GOST_cipher *descriptor)
{
    GOST_CTX *gctx = OPENSSL_zalloc(sizeof(*gctx));

    if (gctx == NULL)
        return NULL;
    gctx->provctx = provctx;
    gctx->descriptor = descriptor;
    if (!GOST_cipher_init(descriptor)) {
        cipher_freectx(gctx);
        return NULL;
    }
    gctx->cctx = GOST_cipher_ctx_new();
    if (gctx->cctx == NULL) {
        cipher_freectx(gctx);
        return NULL;
    }
    return gctx;
}

static void *cipher_dupctx(void *vsrc)
{
    GOST_CTX *src = vsrc;
    GOST_CTX *dst = cipher_newctx(src->provctx, src->descriptor);

    if (dst != NULL && !GOST_cipher_ctx_copy(dst->cctx, src->cctx)) {
        cipher_freectx(dst);
        dst = NULL;
    }
    return dst;
}

static int cipher_get_params(const GOST_cipher *c, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if (((p = OSSL_PARAM_locate(params, "blocksize")) != NULL
         && !OSSL_PARAM_set_size_t(p, (size_t)GOST_cipher_block_size(c)))
        || ((p = OSSL_PARAM_locate(params, "ivlen")) != NULL
            && !OSSL_PARAM_set_size_t(p, (size_t)GOST_cipher_iv_length(c)))
        || ((p = OSSL_PARAM_locate(params, "keylen")) != NULL
            && !OSSL_PARAM_set_size_t(p, (size_t)GOST_cipher_key_length(c)))
        || ((p = OSSL_PARAM_locate(params, "mode")) != NULL
            && !OSSL_PARAM_set_uint(p, (unsigned int)GOST_cipher_mode(c)))
        || ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD)) != NULL
            && !OSSL_PARAM_set_int(p,
                                   GOST_cipher_nid(c) == magma_mgm_cipher.nid
                                   || GOST_cipher_nid(c) == grasshopper_mgm_cipher.nid)))
        return 0;
    return 1;
}

static int cipher_get_ctx_params(void *vgctx, OSSL_PARAM params[])
{
    GOST_CTX *gctx = vgctx;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL) {
        if (!OSSL_PARAM_set_size_t(p,
                (size_t)GOST_cipher_key_length(gctx->descriptor)))
            return 0;
    }
    if (((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV)) != NULL)
        && !OSSL_PARAM_set_octet_ptr(p,
                GOST_cipher_ctx_iv(gctx->cctx),
                (size_t)GOST_cipher_ctx_iv_length(gctx->cctx))
        && !OSSL_PARAM_set_octet_string(p,
                GOST_cipher_ctx_iv(gctx->cctx),
                (size_t)GOST_cipher_ctx_iv_length(gctx->cctx))) {
        return 0;
    }
    if (((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV)) != NULL)
        && !OSSL_PARAM_set_octet_ptr(p,
                GOST_cipher_ctx_iv(gctx->cctx),
                (size_t)GOST_cipher_ctx_iv_length(gctx->cctx))
        && !OSSL_PARAM_set_octet_string(p,
                GOST_cipher_ctx_iv(gctx->cctx),
                (size_t)GOST_cipher_ctx_iv_length(gctx->cctx))) {
        return 0;
    }
    return 1;
}

static int cipher_set_ctx_params(void *vgctx, const OSSL_PARAM params[])
{
    GOST_CTX *gctx = vgctx;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, "padding")) != NULL) {
        unsigned int pad = 0;
        if (!OSSL_PARAM_get_uint(p, &pad)
            || !GOST_cipher_ctx_set_padding(gctx->cctx, (int)pad))
            return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, "key-mesh")) != NULL) {
        size_t key_mesh = 0;
        if (!OSSL_PARAM_get_size_t(p, &key_mesh)
            || GOST_cipher_ctx_ctrl(gctx->cctx, EVP_CTRL_KEY_MESH,
                                    (int)key_mesh, NULL) <= 0)
            return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG)) != NULL) {
        unsigned char tag[1024];
        void *val = tag;
        size_t taglen = 0;
        if (!OSSL_PARAM_get_octet_string(p, &val, sizeof(tag), &taglen)
            || GOST_cipher_ctx_ctrl(gctx->cctx, EVP_CTRL_AEAD_SET_TAG,
                                    (int)taglen, tag) <= 0)
            return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN)) != NULL) {
        size_t ivlen = 0;
        if (!OSSL_PARAM_get_size_t(p, &ivlen)
            || GOST_cipher_ctx_ctrl(gctx->cctx, EVP_CTRL_AEAD_SET_IVLEN,
                                    (int)ivlen, NULL) <= 0)
            return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLSTREE)) != NULL) {
        const void *val = NULL;
        size_t arg = 0;
        if (!OSSL_PARAM_get_octet_string_ptr(p, &val, &arg)
            || GOST_cipher_ctx_ctrl(gctx->cctx, EVP_CTRL_TLSTREE,
                                    (int)arg, (void *)val) <= 0)
            return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLSTREE_MODE)) != NULL) {
        const void *val = NULL;
        size_t arg = 0;
        if (!OSSL_PARAM_get_octet_string_ptr(p, &val, &arg)
            || GOST_cipher_ctx_ctrl(gctx->cctx, EVP_CTRL_SET_TLSTREE_PARAMS,
                                    (int)arg, (void *)val) <= 0)
            return 0;
    }
    return 1;
}

static int cipher_encrypt_init(void *vgctx,
                               const unsigned char *key, size_t keylen,
                               const unsigned char *iv, size_t ivlen,
                               const OSSL_PARAM params[])
{
    GOST_CTX *gctx = vgctx;

    if (!cipher_set_ctx_params(vgctx, params)
        || keylen > (size_t)GOST_cipher_key_length(gctx->descriptor)
        || ivlen > (size_t)GOST_cipher_iv_length(gctx->descriptor))
        return 0;
    return GOST_CipherInit_ex(gctx->cctx, gctx->descriptor, key, iv, 1);
}

static int cipher_decrypt_init(void *vgctx,
                               const unsigned char *key, size_t keylen,
                               const unsigned char *iv, size_t ivlen,
                               const OSSL_PARAM params[])
{
    GOST_CTX *gctx = vgctx;

    if (!cipher_set_ctx_params(vgctx, params)
        || keylen > (size_t)GOST_cipher_key_length(gctx->descriptor)
        || ivlen > (size_t)GOST_cipher_iv_length(gctx->descriptor))
        return 0;
    return GOST_CipherInit_ex(gctx->cctx, gctx->descriptor, key, iv, 0);
}

static int cipher_update(void *vgctx,
                         unsigned char *out, size_t *outl, size_t outsize,
                         const unsigned char *in, size_t inl)
{
    GOST_CTX *gctx = vgctx;
    int int_outl = 0;

    if (out == NULL && outsize != 0)
        return 0;
    if (!GOST_CipherUpdate(gctx->cctx, out, &int_outl, in, (int)inl))
        return 0;
    if (outl != NULL)
        *outl = (size_t)int_outl;
    return 1;
}

static int cipher_final(void *vgctx,
                        unsigned char *out, size_t *outl, size_t outsize)
{
    GOST_CTX *gctx = vgctx;
    int int_outl = 0;

    if (!GOST_CipherFinal(gctx->cctx, out, &int_outl))
        return 0;
    if (outl != NULL)
        *outl = (size_t)int_outl;
    return 1;
}

typedef void (*fptr_t)(void);
#define MAKE_FUNCTIONS(name)                                            \
    static OSSL_FUNC_cipher_get_params_fn name##_get_params;            \
    static int name##_get_params(OSSL_PARAM *params)                    \
    {                                                                   \
        GOST_cipher_init(&name);                                        \
        return cipher_get_params(&name, params);                        \
    }                                                                   \
    static OSSL_FUNC_cipher_newctx_fn name##_newctx;                    \
    static void *name##_newctx(void *provctx)                           \
    {                                                                   \
        return cipher_newctx(provctx, &name);                           \
    }                                                                   \
    static const OSSL_DISPATCH name##_functions[] = {                   \
        { OSSL_FUNC_CIPHER_GET_PARAMS, (fptr_t)name##_get_params },     \
        { OSSL_FUNC_CIPHER_NEWCTX, (fptr_t)name##_newctx },             \
        { OSSL_FUNC_CIPHER_DUPCTX, (fptr_t)cipher_dupctx },             \
        { OSSL_FUNC_CIPHER_FREECTX, (fptr_t)cipher_freectx },           \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (fptr_t)cipher_get_ctx_params }, \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (fptr_t)cipher_set_ctx_params }, \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (fptr_t)cipher_encrypt_init }, \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (fptr_t)cipher_decrypt_init }, \
        { OSSL_FUNC_CIPHER_UPDATE, (fptr_t)cipher_update },             \
        { OSSL_FUNC_CIPHER_FINAL, (fptr_t)cipher_final },               \
        { 0, NULL },                                                    \
    }

MAKE_FUNCTIONS(Gost28147_89_cipher);
MAKE_FUNCTIONS(Gost28147_89_cnt_cipher);
MAKE_FUNCTIONS(Gost28147_89_cnt_12_cipher);
MAKE_FUNCTIONS(Gost28147_89_cbc_cipher);
MAKE_FUNCTIONS(grasshopper_ecb_cipher);
MAKE_FUNCTIONS(grasshopper_cbc_cipher);
MAKE_FUNCTIONS(grasshopper_cfb_cipher);
MAKE_FUNCTIONS(grasshopper_ofb_cipher);
MAKE_FUNCTIONS(grasshopper_ctr_cipher);
MAKE_FUNCTIONS(magma_cbc_cipher);
MAKE_FUNCTIONS(magma_ctr_cipher);
MAKE_FUNCTIONS(magma_ctr_acpkm_cipher);
MAKE_FUNCTIONS(magma_ctr_acpkm_omac_cipher);
MAKE_FUNCTIONS(magma_mgm_cipher);
MAKE_FUNCTIONS(grasshopper_ctr_acpkm_cipher);
MAKE_FUNCTIONS(grasshopper_ctr_acpkm_omac_cipher);
MAKE_FUNCTIONS(grasshopper_mgm_cipher);

const OSSL_ALGORITHM GOST_prov_ciphers[] = {
    { SN_id_Gost28147_89 ":gost89:GOST 28147-89:1.2.643.2.2.21", NULL,
      Gost28147_89_cipher_functions },
    { SN_gost89_cnt, NULL, Gost28147_89_cnt_cipher_functions },
    { SN_gost89_cnt_12, NULL, Gost28147_89_cnt_12_cipher_functions },
    { SN_gost89_cbc, NULL, Gost28147_89_cbc_cipher_functions },
    { SN_grasshopper_ecb, NULL, grasshopper_ecb_cipher_functions },
    { SN_grasshopper_cbc, NULL, grasshopper_cbc_cipher_functions },
    { SN_grasshopper_cfb, NULL, grasshopper_cfb_cipher_functions },
    { SN_grasshopper_ofb, NULL, grasshopper_ofb_cipher_functions },
    { SN_grasshopper_ctr, NULL, grasshopper_ctr_cipher_functions },
    { SN_magma_cbc, NULL, magma_cbc_cipher_functions },
    { SN_magma_ctr, NULL, magma_ctr_cipher_functions },
    { SN_magma_ctr_acpkm ":1.2.643.7.1.1.5.1.1", NULL,
      magma_ctr_acpkm_cipher_functions },
    { SN_magma_ctr_acpkm_omac ":1.2.643.7.1.1.5.1.2", NULL,
      magma_ctr_acpkm_omac_cipher_functions },
    { "magma-mgm", NULL, magma_mgm_cipher_functions },
    { SN_kuznyechik_ctr_acpkm ":1.2.643.7.1.1.5.2.1", NULL,
      grasshopper_ctr_acpkm_cipher_functions },
    { SN_kuznyechik_ctr_acpkm_omac ":1.2.643.7.1.1.5.2.2", NULL,
      grasshopper_ctr_acpkm_omac_cipher_functions },
    { "kuznyechik-mgm", NULL, grasshopper_mgm_cipher_functions },
#if 0                           /* Not yet implemented */
    { SN_magma_kexp15 ":1.2.643.7.1.1.7.1.1", NULL,
      magma_kexp15_cipher_functions },
    { SN_kuznyechik_kexp15 ":1.2.643.7.1.1.7.2.1", NULL,
      kuznyechik_kexp15_cipher_functions },
#endif
    { NULL , NULL, NULL }
};

void GOST_prov_deinit_ciphers(void) {
}
