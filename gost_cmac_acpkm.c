#include "string.h"

#include <openssl/evp.h>

#include "e_gost_err.h"
#include "gost_cmac_acpkm.h"

static unsigned char zero_iv[ACPKM_T_MAX];

/* Make temporary keys K1 and K2 */

static void make_kn(unsigned char *k1, unsigned char *l, int bl)
{
    int i;
    /* Shift block to left, including carry */
    for (i = 0; i < bl; i++) {
        k1[i] = l[i] << 1;
        if (i < bl - 1 && l[i + 1] & 0x80)
            k1[i] |= 1;
    }
    /* If MSB set fixup with R */
    if (l[0] & 0x80)
        k1[bl - 1] ^= bl == 16 ? 0x87 : 0x1b;
}

/*
 * CMAC code from crypto/cmac/cmac.c with ACPKM tweaks
 */
CMAC_ACPKM_CTX *CMAC_ACPKM_CTX_new(void)
{
    CMAC_ACPKM_CTX *ctx;
    ctx = OPENSSL_zalloc(sizeof(CMAC_ACPKM_CTX));
    if (!ctx)
        return NULL;
    ctx->cctx = EVP_CIPHER_CTX_new();
    if (ctx->cctx == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }
    ctx->actx = EVP_CIPHER_CTX_new();
    if (ctx->actx == NULL) {
        EVP_CIPHER_CTX_free(ctx->cctx);
        OPENSSL_free(ctx);
        return NULL;
    }
    ctx->nlast_block = -1;
    ctx->num = 0;
    ctx->section_size = 4096; /* recommended value for Kuznyechik */
    return ctx;
}

void CMAC_ACPKM_CTX_cleanup(CMAC_ACPKM_CTX *ctx)
{
    EVP_CIPHER_CTX_cleanup(ctx->cctx);
    EVP_CIPHER_CTX_cleanup(ctx->actx);
    OPENSSL_cleanse(ctx->tbl, EVP_MAX_BLOCK_LENGTH);
    OPENSSL_cleanse(ctx->km, ACPKM_T_MAX);
    OPENSSL_cleanse(ctx->last_block, EVP_MAX_BLOCK_LENGTH);
    ctx->nlast_block = -1;
}

void CMAC_ACPKM_CTX_free(CMAC_ACPKM_CTX *ctx)
{
    if (!ctx)
        return;
    CMAC_ACPKM_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx->cctx);
    EVP_CIPHER_free(ctx->acpkm);
    EVP_CIPHER_CTX_free(ctx->actx);
    OPENSSL_free(ctx);
}

int CMAC_ACPKM_CTX_copy(CMAC_ACPKM_CTX *out, const CMAC_ACPKM_CTX *in)
{
    int bl;
    if (in->nlast_block == -1)
        return 0;
    if (!EVP_CIPHER_CTX_copy(out->cctx, in->cctx))
        return 0;
    if (!EVP_CIPHER_up_ref(in->acpkm))
        return 0;
    out->acpkm = in->acpkm;
    if (!EVP_CIPHER_CTX_copy(out->actx, in->actx))
        return 0;
    bl = EVP_CIPHER_CTX_block_size(in->cctx);
    memcpy(out->km, in->km, ACPKM_T_MAX);
    memcpy(out->tbl, in->tbl, bl);
    memcpy(out->last_block, in->last_block, bl);
    out->nlast_block = in->nlast_block;
    out->section_size = in->section_size;
    out->num = in->num;
    return 1;
}

static EVP_CIPHER* get_cipher(const char* cipher_name) {
    EVP_CIPHER* cipher = NULL;
    cipher = (EVP_CIPHER *)EVP_get_cipherbyname(cipher_name);
    if (cipher)
        return cipher;

    cipher = EVP_CIPHER_fetch(NULL, cipher_name, NULL);
    return cipher;
}

int CMAC_ACPKM_Init(CMAC_ACPKM_CTX *ctx, const void *key, size_t keylen,
                           const EVP_CIPHER *cipher)
{
    /* All zeros means restart */
    if (!key && !cipher && keylen == 0) {
        /* Not initialised */
        if (ctx->nlast_block == -1)
            return 0;
        if (!EVP_EncryptInit_ex(ctx->cctx, NULL, NULL, NULL, zero_iv))
            return 0;
        memset(ctx->tbl, 0, EVP_CIPHER_CTX_block_size(ctx->cctx));
        ctx->nlast_block = 0;
        /* No restart for ACPKM */
        return 1;
    }
    /* Initialise context */
    if (cipher) {
        if (!EVP_EncryptInit_ex(ctx->cctx, cipher, NULL, NULL, NULL))
            return 0;
        /* Unfortunately, EVP_CIPHER_is_a is bugged for an engine, EVP_CIPHER_nid is bugged for a provider. */
        if (EVP_CIPHER_nid(cipher) == NID_undef) {
            /* Looks like a provider */
            if (EVP_CIPHER_is_a(cipher, SN_magma_cbc))
                ctx->acpkm = get_cipher(SN_magma_ctr_acpkm);
            else if (EVP_CIPHER_is_a(cipher, SN_grasshopper_cbc))
                ctx->acpkm = get_cipher(SN_kuznyechik_ctr_acpkm);
        }
        else {
            /* Looks like an engine */
            if (EVP_CIPHER_nid(cipher) == NID_magma_cbc)
                ctx->acpkm = get_cipher(SN_magma_ctr_acpkm);
            else if (EVP_CIPHER_nid(cipher) == NID_grasshopper_cbc)
                ctx->acpkm = get_cipher(SN_kuznyechik_ctr_acpkm);
        }

        if (ctx->acpkm == NULL)
            return 0;

        if (!EVP_EncryptInit_ex(ctx->actx, ctx->acpkm, NULL, NULL, NULL))
            return 0;
    }
    /* Non-NULL key means initialisation is complete */
    if (key) {
        unsigned char acpkm_iv[EVP_MAX_BLOCK_LENGTH];
        int block_size, key_len;

        /* Initialize CTR for ACPKM-Master */
        if (!EVP_CIPHER_CTX_cipher(ctx->actx))
            return 0;
        /* block size of ACPKM cipher could be 1, but,
         * cbc cipher is same with correct block_size */
        block_size = EVP_CIPHER_CTX_block_size(ctx->cctx);
        /* Wide IV = 1^{n/2} || 0,
         * where a^r denotes the string that consists of r 'a' bits */
        memset(acpkm_iv, 0xff, block_size / 2);
        memset(acpkm_iv + block_size / 2, 0, block_size / 2);
        if (!EVP_EncryptInit_ex(ctx->actx, NULL, NULL, key, acpkm_iv))
            return 0;
        /* EVP_CIPHER key_len may be different from EVP_CIPHER_CTX key_len */
        key_len = EVP_CIPHER_key_length(EVP_CIPHER_CTX_cipher(ctx->actx));

        /* Generate first key material (K^1 || K^1_1) */
        if (!EVP_Cipher(ctx->actx, ctx->km, zero_iv, key_len + block_size))
            return 0;

        /* Initialize cbc for CMAC */
        if (!EVP_CIPHER_CTX_cipher(ctx->cctx) ||
            !EVP_CIPHER_CTX_set_key_length(ctx->cctx, key_len))
            return 0;
        /* set CBC key to K^1 */
        if (!EVP_EncryptInit_ex(ctx->cctx, NULL, NULL, ctx->km, zero_iv))
            return 0;
        ctx->nlast_block = 0;
    }
    return 1;
}

/* Encrypt zeros with master key
 * to generate T*-sized key material */
static int CMAC_ACPKM_Master(CMAC_ACPKM_CTX *ctx)
{
    return EVP_Cipher(ctx->actx, ctx->km, zero_iv,
        EVP_CIPHER_key_length(EVP_CIPHER_CTX_cipher(ctx->actx)) +
        EVP_CIPHER_CTX_block_size(ctx->cctx));
}

static int CMAC_ACPKM_Mesh(CMAC_ACPKM_CTX *ctx)
{
    if (ctx->num < ctx->section_size)
        return 1;
    ctx->num = 0;
    if (!CMAC_ACPKM_Master(ctx))
        return 0;
    /* Restart cbc with new key */
    if (!EVP_EncryptInit_ex(ctx->cctx, NULL, NULL, ctx->km,
            EVP_CIPHER_CTX_iv(ctx->cctx)))
        return 0;
    return 1;
}

int CMAC_ACPKM_Update(CMAC_ACPKM_CTX *ctx, const void *in, size_t dlen)
{
    const unsigned char *data = in;
    size_t bl;
    if (ctx->nlast_block == -1)
        return 0;
    if (dlen == 0)
        return 1;
    bl = EVP_CIPHER_CTX_block_size(ctx->cctx);
    /* Copy into partial block if we need to */
    if (ctx->nlast_block > 0) {
        size_t nleft;
        nleft = bl - ctx->nlast_block;
        if (dlen < nleft)
            nleft = dlen;
        memcpy(ctx->last_block + ctx->nlast_block, data, nleft);
        dlen -= nleft;
        ctx->nlast_block += nleft;
        /* If no more to process return */
        if (dlen == 0)
            return 1;
        data += nleft;
        /* Else not final block so encrypt it */
        if (!CMAC_ACPKM_Mesh(ctx))
            return 0;
        if (!EVP_Cipher(ctx->cctx, ctx->tbl, ctx->last_block, bl))
            return 0;
        ctx->num += bl;
    }
    /* Encrypt all but one of the complete blocks left */
    while (dlen > bl) {
        if (!CMAC_ACPKM_Mesh(ctx))
            return 0;
        if (!EVP_Cipher(ctx->cctx, ctx->tbl, data, bl))
            return 0;
        dlen -= bl;
        data += bl;
        ctx->num += bl;
    }
    /* Copy any data left to last block buffer */
    memcpy(ctx->last_block, data, dlen);
    ctx->nlast_block = dlen;
    return 1;

}

/* Return value is propagated to EVP_DigestFinal_ex */
int CMAC_ACPKM_Final(CMAC_ACPKM_CTX *ctx, unsigned char *out,
                     size_t *poutlen)
{
    int i, bl, lb, key_len;
    unsigned char *k1, k2[EVP_MAX_BLOCK_LENGTH];
    if (ctx->nlast_block == -1)
        return 0;
    bl = EVP_CIPHER_CTX_block_size(ctx->cctx);
    if (bl != 8 && bl != 16) {
        GOSTerr(GOST_F_OMAC_ACPKM_IMIT_FINAL, GOST_R_INVALID_MAC_PARAMS);
        return 0;
    }
    *poutlen = (size_t) bl;
    if (!out)
        return 1;
    lb = ctx->nlast_block;

    if (!CMAC_ACPKM_Mesh(ctx))
        return 0;
    key_len = EVP_CIPHER_key_length(EVP_CIPHER_CTX_cipher(ctx->actx));
    /* Keys k1 and k2 */
    k1 = ctx->km + key_len;
    make_kn(k2, ctx->km + key_len, bl);

    /* Is last block complete? */
    if (lb == bl) {
        for (i = 0; i < bl; i++)
            out[i] = ctx->last_block[i] ^ k1[i];
    } else {
        ctx->last_block[lb] = 0x80;
        if (bl - lb > 1)
            memset(ctx->last_block + lb + 1, 0, bl - lb - 1);
        for (i = 0; i < bl; i++)
            out[i] = ctx->last_block[i] ^ k2[i];
    }
    OPENSSL_cleanse(k1, bl);
    OPENSSL_cleanse(k2, bl);
    OPENSSL_cleanse(ctx->km, ACPKM_T_MAX);
    if (!EVP_Cipher(ctx->cctx, out, out, bl)) {
        OPENSSL_cleanse(out, bl);
        return 0;
    }
    return 1;
}