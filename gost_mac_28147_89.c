#include <assert.h>
#include <string.h>

// #include <openssl/evp.h>
#include <openssl/objects.h>


#include "gost_mac.h"
#include "gost_mac_base.h"
#include "gost_mac_28147_89.h"
#include "gost89.h"
#include "e_gost_err.h"

static GOST_mac_ctx* gost_mac_new(const GOST_mac *cls);

static int gost_imit_init_cpa(GOST_mac_ctx *ctx);
static int gost_imit_init_cp_12(GOST_mac_ctx *ctx);
static int gost_imit_update(GOST_mac_ctx *ctx, const void *data,
                            size_t count);
static int gost_imit_final(GOST_mac_ctx *ctx, unsigned char *md);
static int gost_imit_copy(GOST_mac_ctx *to, const GOST_mac_ctx *from);
static int gost_imit_cleanup(GOST_mac_ctx *ctx);
static int gost_imit_ctrl(GOST_mac_ctx *ctx, int cmd, int p1, void *p2);

struct ossl_gost_imit_ctx {
    gost_ctx cctx;
    unsigned char buffer[8];
    unsigned char partial_block[8];
    unsigned int count;
    int key_meshing;
    int bytes_left;
    int key_set;
    int dgst_size;
};

static GOST_mac Gost28147_89_mac_base = {
    INIT_MEMBER(base, &Gost_mac_base),

    INIT_MEMBER(result_size, 4),
    INIT_MEMBER(input_blocksize, 8),
    INIT_MEMBER(flags, EVP_MD_FLAG_XOF),
    INIT_MEMBER(algctx_size, sizeof(struct ossl_gost_imit_ctx)),

    INIT_MEMBER(update, gost_imit_update),
    INIT_MEMBER(final, gost_imit_final),
    INIT_MEMBER(copy, gost_imit_copy),
    INIT_MEMBER(cleanup, gost_imit_cleanup),
    INIT_MEMBER(ctrl, gost_imit_ctrl),
};

const GOST_mac Gost28147_89_mac = {
	INIT_MEMBER(base, &Gost28147_89_mac_base),

	INIT_MEMBER(nid, NID_id_Gost28147_89_MAC),

    INIT_MEMBER(init, gost_imit_init_cpa),
};

const GOST_mac Gost28147_89_mac_12 = {
	INIT_MEMBER(base, &Gost28147_89_mac_base),

	INIT_MEMBER(nid, NID_gost_mac_12),

    INIT_MEMBER(init, gost_imit_init_cp_12),
};

static int gost_imit_init(GOST_mac_ctx *ctx, gost_subst_block * block)
{
    if (GOST_mac_ctx_test_flags(ctx, EVP_MD_CTX_FLAG_NO_INIT)) {
        return 1;
    }
    struct ossl_gost_imit_ctx *c = GOST_mac_ctx_data(ctx);
    memset(c->buffer, 0, sizeof(c->buffer));
    memset(c->partial_block, 0, sizeof(c->partial_block));
    c->count = 0;
    c->bytes_left = 0;
    c->key_meshing = 1;
    c->dgst_size = 4;
    gost_init(&(c->cctx), block);
    return 1;
}

static int gost_imit_init_cpa(GOST_mac_ctx *ctx)
{
    return gost_imit_init(ctx, &Gost28147_CryptoProParamSetA);
}

static int gost_imit_init_cp_12(GOST_mac_ctx *ctx)
{
    return gost_imit_init(ctx, &Gost28147_TC26ParamSetZ);
}


static void mac_block_mesh(struct ossl_gost_imit_ctx *c,
                           const unsigned char *data)
{
    /*
     * We are using NULL for iv because CryptoPro doesn't interpret
     * internal state of MAC algorithm as iv during keymeshing (but does
     * initialize internal state from iv in key transport
     */
    assert(c->count % 8 == 0 && c->count <= 1024);
    if (c->key_meshing && c->count == 1024) {
        cryptopro_key_meshing(&(c->cctx), NULL);
    }
    mac_block(&(c->cctx), c->buffer, data);
    c->count = c->count % 1024 + 8;
}

static int gost_imit_update(GOST_mac_ctx *ctx, const void *data, size_t count)
{
    struct ossl_gost_imit_ctx *c = GOST_mac_ctx_data(ctx);
    const unsigned char *p = data;
    size_t bytes = count;
    if (!(c->key_set)) {
        GOSTerr(GOST_F_GOST_IMIT_UPDATE, GOST_R_MAC_KEY_NOT_SET);
        return 0;
    }
    if (c->bytes_left) {
        size_t i;
        for (i = c->bytes_left; i < 8 && bytes > 0; bytes--, i++, p++) {
            c->partial_block[i] = *p;
        }
        if (i == 8) {
            mac_block_mesh(c, c->partial_block);
        } else {
            c->bytes_left = i;
            return 1;
        }
    }
    while (bytes > 8) {
        mac_block_mesh(c, p);
        p += 8;
        bytes -= 8;
    }
    if (bytes > 0) {
        memcpy(c->partial_block, p, bytes);
    }
    c->bytes_left = bytes;
    return 1;
}

static int gost_imit_final(GOST_mac_ctx *ctx, unsigned char *md)
{
    struct ossl_gost_imit_ctx *c = GOST_mac_ctx_data(ctx);
    if (!c->key_set) {
        GOSTerr(GOST_F_GOST_IMIT_FINAL, GOST_R_MAC_KEY_NOT_SET);
        return 0;
    }
    if (c->count == 0 && c->bytes_left) {
        unsigned char buffer[8];
        memset(buffer, 0, 8);
        gost_imit_update(ctx, buffer, 8);
    }
    if (c->bytes_left) {
        int i;
        for (i = c->bytes_left; i < 8; i++) {
            c->partial_block[i] = 0;
        }
        mac_block_mesh(c, c->partial_block);
    }
    get_mac(c->buffer, 8 * c->dgst_size, md);
    return 1;
}

static int gost_imit_ctrl(GOST_mac_ctx *ctx, int type, int arg, void *ptr)
{
    switch (type) {
    case EVP_MD_CTRL_KEY_LEN:
        *((unsigned int *)(ptr)) = 32;
        return 1;
    case EVP_MD_CTRL_SET_KEY:
        {
            struct ossl_gost_imit_ctx *gost_imit_ctx = GOST_mac_ctx_data(ctx);

            if (GET_MEMBER(GOST_mac, ctx->cls, init) (ctx) <= 0) {
                GOSTerr(GOST_F_GOST_IMIT_CTRL, GOST_R_MAC_KEY_NOT_SET);
                return 0;
            }
            GOST_mac_ctx_set_flags(ctx, EVP_MD_CTX_FLAG_NO_INIT);

            if (arg == 0) {
                return 0;
                // This part is engine-specific
                /*
                struct gost_mac_key *key = (struct gost_mac_key *)ptr;
                if (key->mac_param_nid != NID_undef) {
                    const struct gost_cipher_info *param =
                        get_encryption_params(OBJ_nid2obj(key->mac_param_nid));
                    if (param == NULL) {
                        GOSTerr(GOST_F_GOST_IMIT_CTRL,
                                GOST_R_INVALID_MAC_PARAMS);
                        return 0;
                    }
                    gost_init(&(gost_imit_ctx->cctx), param->sblock);
                }
                gost_key(&(gost_imit_ctx->cctx), key->key);
                gost_imit_ctx->key_set = 1;

                return 1;
                */
            } else if (arg == 32) {
                gost_key(&(gost_imit_ctx->cctx), ptr);
                gost_imit_ctx->key_set = 1;
                return 1;
            }
            GOSTerr(GOST_F_GOST_IMIT_CTRL, GOST_R_INVALID_MAC_KEY_SIZE);
            return 0;
        }
    case EVP_MD_CTRL_XOF_LEN:
        {
            struct ossl_gost_imit_ctx *c = GOST_mac_ctx_data(ctx);
            if (arg < 1 || arg > 8) {
                GOSTerr(GOST_F_GOST_IMIT_CTRL, GOST_R_INVALID_MAC_SIZE);
                return 0;
            }
            c->dgst_size = arg;
            return 1;
        }

    default:
        return 0;
    }
}

static int gost_imit_copy(GOST_mac_ctx *to, const GOST_mac_ctx *from)
{
    if (GOST_mac_ctx_data(to) && GOST_mac_ctx_data(from)) {
        memcpy(GOST_mac_ctx_data(to), GOST_mac_ctx_data(from),
               sizeof(struct ossl_gost_imit_ctx));
    }
    return 1;
}

/* Clean up imit ctx */
static int gost_imit_cleanup(GOST_mac_ctx *ctx)
{
    OPENSSL_cleanse(GOST_mac_ctx_data(ctx), sizeof(struct ossl_gost_imit_ctx));
    return 1;
}