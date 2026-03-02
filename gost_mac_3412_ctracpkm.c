/*
 * Copyright (C) 2018,2020 Vitaly Chikunov <vt@altlinux.org>. All Rights Reserved.
 * Copyright (c) 2010 The OpenSSL Project.  All rights reserved.
 *
 * Contents licensed under the terms of the OpenSSL license
 * See https://www.openssl.org/source/license.html for details
 */
#include <string.h>
#include <openssl/cmac.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "e_gost_err.h" 
#include "gost_grasshopper.h"
#include "gost_cmac_acpkm.h"
#include "gost_mac_base.h"

/*
 * End of CMAC code from crypto/cmac/cmac.c with ACPKM tweaks
 */

typedef struct omac_acpkm_ctx {
    CMAC_ACPKM_CTX *cmac_ctx;
    size_t dgst_size;
    const char *cipher_name;
    int key_set;
} OMAC_ACPKM_CTX;

#define MAX_GOST_OMAC_ACPKM_SIZE 16

static int omac_acpkm_init(GOST_mac_ctx *ctx, const char *cipher_name)
{
    OMAC_ACPKM_CTX *c = GOST_mac_ctx_data(ctx);
    memset(c, 0, sizeof(OMAC_ACPKM_CTX));
    c->cipher_name = cipher_name;
    c->key_set = 0;

    switch (OBJ_txt2nid(cipher_name)) {
    case NID_grasshopper_cbc:
        c->dgst_size = 16;
        break;
    case NID_magma_cbc:
        c->dgst_size = 8;
        break;
    }

    return 1;
}

static int grasshopper_omac_acpkm_init(GOST_mac_ctx *ctx)
{
    return omac_acpkm_init(ctx, SN_grasshopper_cbc);
}

static int magma_omac_acpkm_init(GOST_mac_ctx *ctx)
{
    return omac_acpkm_init(ctx, SN_magma_cbc);
}

static int omac_acpkm_imit_update(GOST_mac_ctx *ctx, const void *data,
                                  size_t count)
{
    OMAC_ACPKM_CTX *c = GOST_mac_ctx_data(ctx);
    if (!c->key_set) {
        GOSTerr(GOST_F_OMAC_ACPKM_IMIT_UPDATE, GOST_R_MAC_KEY_NOT_SET);
        return 0;
    }

    return CMAC_ACPKM_Update(c->cmac_ctx, data, count);
}

static int omac_acpkm_imit_final(GOST_mac_ctx *ctx, unsigned char *md)
{
    OMAC_ACPKM_CTX *c = GOST_mac_ctx_data(ctx);
    unsigned char mac[MAX_GOST_OMAC_ACPKM_SIZE];
    size_t mac_size = sizeof(mac);
    int ret;

    if (!c->key_set) {
        GOSTerr(GOST_F_OMAC_ACPKM_IMIT_FINAL, GOST_R_MAC_KEY_NOT_SET);
        return 0;
    }

    ret = CMAC_ACPKM_Final(c->cmac_ctx, mac, &mac_size);

    memcpy(md, mac, c->dgst_size);
    return ret;
}

static int omac_acpkm_imit_copy(GOST_mac_ctx *to, const GOST_mac_ctx *from)
{
    OMAC_ACPKM_CTX *c_to = GOST_mac_ctx_data(to);
    const OMAC_ACPKM_CTX *c_from = GOST_mac_ctx_data(from);

    if (c_from && c_to) {
        c_to->dgst_size = c_from->dgst_size;
        c_to->cipher_name = c_from->cipher_name;
        c_to->key_set = c_from->key_set;
    } else {
        return 0;
    }
    if (!c_from->cmac_ctx) {
        if (c_to->cmac_ctx) {
            CMAC_ACPKM_CTX_free(c_to->cmac_ctx);
            c_to->cmac_ctx = NULL;
        }
        return 1;
    }
    if ((c_to->cmac_ctx == c_from->cmac_ctx) || (c_to->cmac_ctx == NULL))  {
        c_to->cmac_ctx = CMAC_ACPKM_CTX_new();
    }

    return (c_to->cmac_ctx) ? CMAC_ACPKM_CTX_copy(c_to->cmac_ctx, c_from->cmac_ctx) : 0;
}

/* Clean up imit ctx */
static int omac_acpkm_imit_cleanup(GOST_mac_ctx *ctx)
{
    OMAC_ACPKM_CTX *c = GOST_mac_ctx_data(ctx);

    if (c) {
        CMAC_ACPKM_CTX_free(c->cmac_ctx);
        memset(GOST_mac_ctx_data(ctx), 0, sizeof(OMAC_ACPKM_CTX));
    }
    return 1;
}

static int omac_acpkm_key(OMAC_ACPKM_CTX *c, const EVP_CIPHER *cipher,
                          const unsigned char *key, size_t key_size)
{
    int ret = 0;

    c->cmac_ctx = CMAC_ACPKM_CTX_new();
    if (c->cmac_ctx == NULL) {
        GOSTerr(GOST_F_OMAC_ACPKM_KEY, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    ret = CMAC_ACPKM_Init(c->cmac_ctx, key, key_size, cipher);
    if (ret > 0) {
        c->key_set = 1;
    }
    return 1;
}

static int omac_acpkm_imit_ctrl(GOST_mac_ctx *ctx, int type, int arg, void *ptr)
{
    switch (type) {
    case EVP_MD_CTRL_KEY_LEN:
        *((unsigned int *)(ptr)) = 32;
        return 1;
    case EVP_MD_CTRL_SET_KEY:
        {
            OMAC_ACPKM_CTX *c = GOST_mac_ctx_data(ctx);
            EVP_CIPHER *cipher = NULL;
            int ret = 0;

            if (c->cipher_name == NULL) {
                if (GET_MEMBER(GOST_mac, ctx->cls, nid) == NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac)
                    c->cipher_name = SN_grasshopper_cbc;
                else if (GET_MEMBER(GOST_mac, ctx->cls, nid) == NID_id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac)
                    c->cipher_name = SN_magma_cbc;
            }
            if ((cipher =
                 (EVP_CIPHER *)EVP_get_cipherbyname(c->cipher_name)) == NULL
                && (cipher =
                    EVP_CIPHER_fetch(NULL, c->cipher_name, NULL)) == NULL) {
                GOSTerr(GOST_F_OMAC_ACPKM_IMIT_CTRL, GOST_R_CIPHER_NOT_FOUND);
            }
            if (GET_MEMBER(GOST_mac, ctx->cls, init)(ctx) <= 0) {
                GOSTerr(GOST_F_OMAC_ACPKM_IMIT_CTRL, GOST_R_MAC_KEY_NOT_SET);
                goto set_key_end;
            }
            GOST_mac_ctx_set_flags(ctx, EVP_MD_CTX_FLAG_NO_INIT);
            if (c->key_set) {
                GOSTerr(GOST_F_OMAC_ACPKM_IMIT_CTRL, GOST_R_BAD_ORDER);
                goto set_key_end;
            }
            if (arg == 0) {
                struct gost_mac_key *key = (struct gost_mac_key *)ptr;
                ret = omac_acpkm_key(c, cipher, key->key, 32);
                goto set_key_end;
            } else if (arg == 32) {
                ret = omac_acpkm_key(c, cipher, ptr, 32);
                goto set_key_end;
            }
            GOSTerr(GOST_F_OMAC_ACPKM_IMIT_CTRL, GOST_R_INVALID_MAC_KEY_SIZE);
          set_key_end:
            EVP_CIPHER_free(cipher);
            return ret;
        }
    case EVP_CTRL_KEY_MESH:
        {
            OMAC_ACPKM_CTX *c = GOST_mac_ctx_data(ctx);
            if (!arg || (arg % GET_MEMBER(GOST_mac, ctx->cls, input_blocksize)))
                return -1;
            c->cmac_ctx->section_size = arg;
            if (ptr && *(int *)ptr) {
                const EVP_CIPHER *cipher;
                if ((cipher = EVP_CIPHER_CTX_cipher(c->cmac_ctx->actx)) == NULL) {
                    return 0;
                }

                /* Set parameter T */
                if (EVP_CIPHER_get0_provider(cipher) == NULL) {
                    if (!EVP_CIPHER_CTX_ctrl(c->cmac_ctx->actx, EVP_CTRL_KEY_MESH,
                                             *(int *)ptr, NULL))
                        return 0;
                } else {
                    size_t cipher_key_mesh = (size_t)*(int *)ptr;
                    OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END };
                    params[0] = OSSL_PARAM_construct_size_t("key-mesh",
                                                            &cipher_key_mesh);
                    if (!EVP_CIPHER_CTX_set_params(c->cmac_ctx->actx, params))
                        return 0;
                }
            }
            return 1;
        }
    case EVP_MD_CTRL_XOF_LEN:   /* Supported in OpenSSL */
        {
            OMAC_ACPKM_CTX *c = GOST_mac_ctx_data(ctx);
            switch (OBJ_txt2nid(c->cipher_name)) {
            case NID_grasshopper_cbc:
                if (arg < 1 || arg > 16) {
                    GOSTerr(GOST_F_OMAC_ACPKM_IMIT_CTRL, GOST_R_INVALID_MAC_SIZE);
                    return 0;
                }
                c->dgst_size = arg;
                break;
            case NID_magma_cbc:
                if (arg < 1 || arg > 8) {
                    GOSTerr(GOST_F_OMAC_ACPKM_IMIT_CTRL, GOST_R_INVALID_MAC_SIZE);
                    return 0;
                }
                c->dgst_size = arg;
                break;
            default:
                return 0;
            }
            return 1;
        }

    default:
        return 0;
    }
}

static GOST_mac Gost_ctracpkm_mac_base = {
    INIT_MEMBER(base, &Gost_mac_base),

    INIT_MEMBER(flags, EVP_MD_FLAG_XOF),
    INIT_MEMBER(algctx_size, sizeof(OMAC_ACPKM_CTX)),

    INIT_MEMBER(update, omac_acpkm_imit_update),
    INIT_MEMBER(final, omac_acpkm_imit_final),
    INIT_MEMBER(copy, omac_acpkm_imit_copy),
    INIT_MEMBER(cleanup, omac_acpkm_imit_cleanup),
    INIT_MEMBER(ctrl, omac_acpkm_imit_ctrl),
};

const GOST_mac grasshopper_ctracpkm_mac = {
    INIT_MEMBER(base, &Gost_ctracpkm_mac_base),

    INIT_MEMBER(nid, NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac),
    INIT_MEMBER(result_size, MAX_GOST_OMAC_ACPKM_SIZE),
    INIT_MEMBER(input_blocksize, GRASSHOPPER_BLOCK_SIZE),

    INIT_MEMBER(init, grasshopper_omac_acpkm_init),
};

const GOST_mac magma_ctracpkm_mac = {
    INIT_MEMBER(base, &Gost_ctracpkm_mac_base),

    INIT_MEMBER(nid, NID_id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac),
    INIT_MEMBER(result_size, 8),
    INIT_MEMBER(input_blocksize, 8),

    INIT_MEMBER(init, magma_omac_acpkm_init),
};
