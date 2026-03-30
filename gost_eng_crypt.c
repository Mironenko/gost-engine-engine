#include <assert.h>
#include <string.h>
#include "gost89.h"
#include <openssl/err.h>
#include <openssl/rand.h>
#include "e_gost_err.h"
#include "gost_lcl.h"
#include "gost_eng_crypt.h"
#include "gost_gost2015.h"
#include "gost_tls12_additional.h"

/*
 * Single level template accessor.
 * Note: that you cannot template 0 value.
 */
#define TPL(st,field) ( \
    ((st)->field) ? ((st)->field) : TPL_VAL(st,field) \
)

#define TPL_VAL(st,field) ( \
    ((st)->template ? (st)->template->field : 0) \
)

EVP_CIPHER *GOST_init_cipher(GOST_cipher *c)
{
    if (c->cipher)
        return c->cipher;

    /* Some sanity checking. */
    int flags = c->flags | TPL_VAL(c, flags);
    int block_size = TPL(c, block_size);
    switch (flags & EVP_CIPH_MODE) {
    case EVP_CIPH_CBC_MODE:
    case EVP_CIPH_ECB_MODE:
    case EVP_CIPH_WRAP_MODE:
        OPENSSL_assert(block_size != 1);
        OPENSSL_assert(!(flags & EVP_CIPH_NO_PADDING));
        break;
    default:
        OPENSSL_assert(block_size == 1);
        OPENSSL_assert(flags & EVP_CIPH_NO_PADDING);
    }

    if (TPL(c, iv_len))
        OPENSSL_assert(flags & EVP_CIPH_CUSTOM_IV);
    else
        OPENSSL_assert(!(flags & EVP_CIPH_CUSTOM_IV));

    EVP_CIPHER *cipher;
    if (!(cipher = EVP_CIPHER_meth_new(c->nid, block_size, TPL(c, key_len)))
        || !EVP_CIPHER_meth_set_iv_length(cipher, TPL(c, iv_len))
        || !EVP_CIPHER_meth_set_flags(cipher, flags)
        || !EVP_CIPHER_meth_set_init(cipher, TPL(c, init))
        || !EVP_CIPHER_meth_set_do_cipher(cipher, TPL(c, do_cipher))
        || !EVP_CIPHER_meth_set_cleanup(cipher, TPL(c, cleanup))
        || !EVP_CIPHER_meth_set_impl_ctx_size(cipher, TPL(c, ctx_size))
        || !EVP_CIPHER_meth_set_set_asn1_params(cipher, TPL(c, set_asn1_parameters))
        || !EVP_CIPHER_meth_set_get_asn1_params(cipher, TPL(c, get_asn1_parameters))
        || !EVP_CIPHER_meth_set_ctrl(cipher, TPL(c, ctrl))) {
        EVP_CIPHER_meth_free(cipher);
        cipher = NULL;
    }
    c->cipher = cipher;
    return c->cipher;
}

void GOST_deinit_cipher(GOST_cipher *c)
{
    if (c->cipher) {
        EVP_CIPHER_meth_free(c->cipher);
        c->cipher = NULL;
    }
}
