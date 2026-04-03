#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>

#define T(e) \
    if (!(e)) { \
        ERR_print_errors_fp(stderr); \
        OpenSSLDie(__FILE__, __LINE__, #e); \
    }

static int export_cb(const OSSL_PARAM params[], void *arg)
{
    const OSSL_PARAM *p;
    const void *raw = NULL;
    size_t raw_len = 0;
    unsigned char **out = arg;

    p = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_RAW_BYTES);
    if (p == NULL)
        return 0;
    if (!OSSL_PARAM_get_octet_string_ptr(p, &raw, &raw_len))
        return 0;

    *out = OPENSSL_memdup(raw, raw_len);
    return *out != NULL;
}

int main(void)
{
    static const unsigned char key[32] = {
        0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff,
    };
    static const unsigned char iv[4] = { 0x12,0x34,0x56,0x78 };
    static const unsigned char pt[32] = {
        0x92,0xde,0xf0,0x6b,0x3c,0x13,0x0a,0x59,0xdb,0x54,0xc7,0x04,0xf8,0x18,0x9d,0x20,
        0x4a,0x98,0xfb,0x2e,0x67,0xa8,0x02,0x4c,0x89,0x12,0x40,0x9b,0x17,0xb5,0x7e,0x41,
    };
    static const unsigned char exp[32] = {
        0x4e,0x98,0x11,0x0c,0x97,0xb7,0xb9,0x3c,0x3e,0x25,0x0d,0x93,0xd6,0xe8,0x5d,0x69,
        0x13,0x6d,0x86,0x88,0x07,0xb2,0xdb,0xef,0x56,0x8e,0xb6,0x80,0xab,0x52,0xa1,0x2d,
    };
    EVP_SKEY *skey = NULL;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    unsigned char out[sizeof(pt)];
    unsigned char *exported = NULL;
    size_t outl = 0;
    int tmplen = 0;

    OPENSSL_add_all_algorithms_conf();
    T(OSSL_PROVIDER_available(NULL, "gostprov"));

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_SKEY_PARAM_RAW_BYTES,
                                                  (void *)key, sizeof(key));
    params[1] = OSSL_PARAM_construct_end();

    T((skey = EVP_SKEY_import(NULL, "magma", NULL,
                              OSSL_SKEYMGMT_SELECT_SECRET_KEY, params)) != NULL);
    T(EVP_SKEY_is_a(skey, "magma"));
    T(EVP_SKEY_export(skey, OSSL_SKEYMGMT_SELECT_SECRET_KEY, export_cb, &exported));
    T(exported != NULL && memcmp(exported, key, sizeof(key)) == 0);

    T((cipher = EVP_CIPHER_fetch(NULL, SN_magma_ctr, NULL)) != NULL);
    T((ctx = EVP_CIPHER_CTX_new()) != NULL);
    T(EVP_CipherInit_SKEY(ctx, cipher, skey, iv, sizeof(iv), 1, NULL));
    T(EVP_CIPHER_CTX_set_padding(ctx, 0));
    T(EVP_CipherUpdate(ctx, out, (int *)&outl, pt, sizeof(pt)));
    T(EVP_CipherFinal_ex(ctx, out + outl, &tmplen));
    T(outl == sizeof(pt));
    T(memcmp(out, exp, sizeof(exp)) == 0);

    OPENSSL_free(exported);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    EVP_SKEY_free(skey);
    return 0;
}
