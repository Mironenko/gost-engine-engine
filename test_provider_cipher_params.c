#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <string.h>
#include <stdio.h>

static const unsigned char k_grasshopper_key[32] = {
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
};

static const unsigned char k_magma_key[32] = {
    0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
    0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff,
};

static const unsigned char k_plaintext_ctr[] = {
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,
    0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,0x11,
};

static const unsigned char k_expected_ctr[] = {
    0xf1,0x95,0xd8,0xbe,0xc1,0x0e,0xd1,0xdb,0xd5,0x7b,0x5f,0xa2,0x40,0xbd,0xa1,0xb8,
    0x85,0xee,0xe7,0x33,0xf6,0xa1,0x3e,0x5d,0xf3,0x3c,0xe4,0xb3,0x3c,0x45,0xde,0xe4,
    0xa5,0xea,0xe8,0x8b,0xe6,0x35,0x6e,0xd3,0xd5,0xe8,0x77,0xf1,0x35,0x64,0xa3,0xa5,
    0xcb,0x91,0xfa,0xb1,0xf2,0x0c,0xba,0xb6,0xd1,0xc6,0xd1,0x58,0x20,0xbd,0xba,0x73,
};

static const unsigned char k_iv_ctr[] = {
    0x12,0x34,0x56,0x78,0x90,0xab,0xce,0xf0
};

static const unsigned char k_gh_nonce[16] = {
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88
};

static const unsigned char k_gh_aad[41] = {
    0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
    0xea,0x05,0x05,0x05,0x05,0x05,0x05,0x05,0x05
};

static const unsigned char k_gh_plaintext[67] = {
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,
    0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,0x11,
    0xaa,0xbb,0xcc
};

static const unsigned char k_gh_ciphertext[67] = {
    0xa9,0x75,0x7b,0x81,0x47,0x95,0x6e,0x90,0x55,0xb8,0xa3,0x3d,0xe8,0x9f,0x42,0xfc,
    0x80,0x75,0xd2,0x21,0x2b,0xf9,0xfd,0x5b,0xd3,0xf7,0x06,0x9a,0xad,0xc1,0x6b,0x39,
    0x49,0x7a,0xb1,0x59,0x15,0xa6,0xba,0x85,0x93,0x6b,0x5d,0x0e,0xa9,0xf6,0x85,0x1c,
    0xc6,0x0c,0x14,0xd4,0xd3,0xf8,0x83,0xd0,0xab,0x94,0x42,0x06,0x95,0xc7,0x6d,0xeb,
    0x2c,0x75,0x52
};

static const unsigned char k_gh_tag[16] = {
    0xcf,0x5d,0x65,0x6f,0x40,0xc3,0x4f,0x5c,0x46,0xe8,0xbb,0x0e,0x29,0xfc,0xdb,0x4c
};

static int failf(const char *msg)
{
    fprintf(stderr, "FAIL: %s\n", msg);
    ERR_print_errors_fp(stderr);
    return 0;
}

#define CHECK(expr) \
    do { \
        if (!(expr)) { \
            failf(#expr); \
            goto cleanup; \
        } \
    } while (0)
#define CHECK_BUF_EQ(lhs, rhs, len, msg) \
    do { \
        if (memcmp((lhs), (rhs), (len)) != 0) { \
            failf(msg); \
            goto cleanup; \
        } \
    } while (0)

static int get_iv_params(EVP_CIPHER_CTX *ctx,
                         unsigned char *iv, size_t iv_size,
                         unsigned char *updated_iv, size_t updated_iv_size)
{
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_IV, iv, iv_size),
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV,
                                          updated_iv, updated_iv_size),
        OSSL_PARAM_END
    };

    if (!EVP_CIPHER_CTX_get_params(ctx, params))
        return 0;
    ERR_clear_error();
    return 1;
}

static int get_updated_iv(EVP_CIPHER_CTX *ctx,
                          unsigned char *updated_iv, size_t updated_iv_size)
{
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV,
                                          updated_iv, updated_iv_size),
        OSSL_PARAM_END
    };

    if (!EVP_CIPHER_CTX_get_params(ctx, params))
        return 0;
    ERR_clear_error();
    return 1;
}

static int test_alg_id_roundtrip(void)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER_CTX *ctx2 = NULL;
    EVP_CIPHER_CTX *ctx_bad = NULL;
    unsigned char alg_id[256];
    unsigned char iv[8] = { 0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef };
    unsigned char iv2[8] = { 0xde,0xad,0xbe,0xef,0x01,0x23,0x45,0x67 };
    unsigned char invalid_alg_id[1] = { 0xff };
    unsigned char got_iv[sizeof(iv)];
    unsigned char got_updated_iv[sizeof(iv)];
    OSSL_PARAM get_alg_id[] = {
        OSSL_PARAM_construct_octet_string("alg_id_param", alg_id, sizeof(alg_id)),
        OSSL_PARAM_END
    };
    int ok = 0;

    cipher = EVP_CIPHER_fetch(NULL, SN_magma_cbc, NULL);
    if (cipher == NULL)
        return failf("EVP_CIPHER_fetch(NULL, SN_magma_cbc, NULL)");

    ctx = EVP_CIPHER_CTX_new();
    ctx2 = EVP_CIPHER_CTX_new();
    ctx_bad = EVP_CIPHER_CTX_new();
    CHECK(ctx != NULL);
    CHECK(ctx2 != NULL);
    CHECK(ctx_bad != NULL);
    CHECK(EVP_EncryptInit_ex2(ctx, cipher, k_magma_key, iv, NULL));
    CHECK(EVP_CIPHER_CTX_get_params(ctx, get_alg_id));
    CHECK(get_alg_id[0].return_size > 0);

    CHECK(get_iv_params(ctx, got_iv, sizeof(got_iv),
                        got_updated_iv, sizeof(got_updated_iv)));
    CHECK_BUF_EQ(got_iv, iv, sizeof(iv), "OSSL_CIPHER_PARAM_IV mismatch");
    CHECK_BUF_EQ(got_updated_iv, iv, sizeof(iv),
                 "OSSL_CIPHER_PARAM_UPDATED_IV mismatch");

    CHECK(EVP_EncryptInit_ex2(ctx2, cipher, k_magma_key, iv2, NULL));
    {
        OSSL_PARAM set_alg_id[] = {
            OSSL_PARAM_construct_octet_string("alg_id_param", alg_id,
                                              get_alg_id[0].return_size),
            OSSL_PARAM_END
        };

        CHECK(EVP_CIPHER_CTX_set_params(ctx2, set_alg_id));
    }
    CHECK(EVP_EncryptInit_ex2(ctx_bad, cipher, k_magma_key, iv2, NULL));
    {
        OSSL_PARAM set_invalid_alg_id[] = {
            OSSL_PARAM_construct_octet_string("alg_id_param", invalid_alg_id,
                                              sizeof(invalid_alg_id)),
            OSSL_PARAM_END
        };

        CHECK(!EVP_CIPHER_CTX_set_params(ctx_bad, set_invalid_alg_id));
    }

    ok = 1;
cleanup:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_CTX_free(ctx2);
    EVP_CIPHER_CTX_free(ctx_bad);
    EVP_CIPHER_free(cipher);
    return ok;
}

static int test_dupctx_stateful_ctr(void)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER_CTX *dup = NULL;
    unsigned char prefix_out[23];
    unsigned char suffix_out[sizeof(k_plaintext_ctr) - sizeof(prefix_out)];
    unsigned char suffix_dup[sizeof(k_plaintext_ctr) - sizeof(prefix_out)];
    unsigned char updated_iv[sizeof(k_iv_ctr)];
    unsigned char updated_iv_dup[sizeof(k_iv_ctr)];
    int prefix_len = 0;
    int suffix_len = 0;
    int suffix_dup_len = 0;
    int final_len = 0;
    int final_dup_len = 0;
    int ok = 0;

    cipher = EVP_CIPHER_fetch(NULL, SN_grasshopper_ctr, NULL);
    if (cipher == NULL)
        return failf("EVP_CIPHER_fetch(NULL, SN_grasshopper_ctr, NULL)");

    ctx = EVP_CIPHER_CTX_new();
    CHECK(ctx != NULL);
    CHECK(EVP_EncryptInit_ex2(ctx, cipher, k_grasshopper_key, k_iv_ctr, NULL));
    CHECK(EVP_EncryptUpdate(ctx, prefix_out, &prefix_len,
                            k_plaintext_ctr, sizeof(prefix_out)));
    CHECK(prefix_len == (int)sizeof(prefix_out));
    CHECK_BUF_EQ(prefix_out, k_expected_ctr, sizeof(prefix_out),
                 "prefix CTR output mismatch");

    dup = EVP_CIPHER_CTX_dup(ctx);
    CHECK(dup != NULL);

    CHECK(EVP_EncryptUpdate(ctx, suffix_out, &suffix_len,
                            k_plaintext_ctr + sizeof(prefix_out),
                            sizeof(k_plaintext_ctr) - sizeof(prefix_out)));
    CHECK(EVP_EncryptUpdate(dup, suffix_dup, &suffix_dup_len,
                            k_plaintext_ctr + sizeof(prefix_out),
                            sizeof(k_plaintext_ctr) - sizeof(prefix_out)));
    CHECK(EVP_EncryptFinal_ex(ctx, suffix_out + suffix_len, &final_len));
    CHECK(EVP_EncryptFinal_ex(dup, suffix_dup + suffix_dup_len, &final_dup_len));
    CHECK(suffix_len == suffix_dup_len);
    CHECK(final_len == final_dup_len);
    CHECK_BUF_EQ(suffix_out, suffix_dup, (size_t)(suffix_len + final_len),
                 "duplicated CTR ctx diverged");
    CHECK_BUF_EQ(suffix_out, k_expected_ctr + sizeof(prefix_out),
                 sizeof(k_expected_ctr) - sizeof(prefix_out),
                 "suffix CTR output mismatch");

    CHECK(get_updated_iv(ctx, updated_iv, sizeof(updated_iv)));
    CHECK(get_updated_iv(dup, updated_iv_dup, sizeof(updated_iv_dup)));
    CHECK_BUF_EQ(updated_iv, updated_iv_dup, sizeof(updated_iv),
                 "duplicated CTR ctx updated IV mismatch");

    ok = 1;
cleanup:
    EVP_CIPHER_CTX_free(dup);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ok;
}

static int test_mgm_tag_params(void)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *enc = NULL;
    EVP_CIPHER_CTX *dec = NULL;
    unsigned char ciphertext[sizeof(k_gh_plaintext)];
    unsigned char plaintext[sizeof(k_gh_plaintext)];
    unsigned char tag[sizeof(k_gh_tag)];
    int aad_len = 0;
    int out_len = 0;
    int final_len = 0;
    int ok = 0;

    cipher = EVP_CIPHER_fetch(NULL, "kuznyechik-mgm", NULL);
    if (cipher == NULL) {
#ifdef TLS13_PATCHED_OPENSSL
        return failf("EVP_CIPHER_fetch(NULL, \"kuznyechik-mgm\", NULL)");
#else
        fprintf(stderr, "SKIP: kuznyechik-mgm is unavailable in this OpenSSL build\n");
        return 1;
#endif
    }

    enc = EVP_CIPHER_CTX_new();
    dec = EVP_CIPHER_CTX_new();
    CHECK(enc != NULL);
    CHECK(dec != NULL);

    CHECK(EVP_EncryptInit_ex2(enc, cipher, k_grasshopper_key, k_gh_nonce, NULL));
    CHECK(EVP_EncryptUpdate(enc, NULL, &aad_len, k_gh_aad, sizeof(k_gh_aad)));
    CHECK(EVP_EncryptUpdate(enc, ciphertext, &out_len,
                            k_gh_plaintext, sizeof(k_gh_plaintext)));
    CHECK(EVP_EncryptFinal_ex(enc, ciphertext + out_len, &final_len));
    CHECK(out_len == (int)sizeof(k_gh_plaintext));
    CHECK(final_len == 0);
    CHECK_BUF_EQ(ciphertext, k_gh_ciphertext, sizeof(ciphertext),
                 "MGM ciphertext mismatch");
    {
        OSSL_PARAM get_tag[] = {
            OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                              tag, sizeof(tag)),
            OSSL_PARAM_END
        };

        CHECK(EVP_CIPHER_CTX_get_params(enc, get_tag));
    }
    CHECK_BUF_EQ(tag, k_gh_tag, sizeof(tag), "MGM AEAD tag mismatch");

    CHECK(EVP_DecryptInit_ex2(dec, cipher, k_grasshopper_key, k_gh_nonce, NULL));
    CHECK(EVP_DecryptUpdate(dec, NULL, &aad_len, k_gh_aad, sizeof(k_gh_aad)));
    CHECK(EVP_DecryptUpdate(dec, plaintext, &out_len,
                            k_gh_ciphertext, sizeof(k_gh_ciphertext)));
    {
        OSSL_PARAM set_tag[] = {
            OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                              tag, sizeof(tag)),
            OSSL_PARAM_END
        };

        CHECK(EVP_CIPHER_CTX_set_params(dec, set_tag));
    }
    CHECK(EVP_DecryptFinal_ex(dec, plaintext + out_len, &final_len));
    CHECK(out_len == (int)sizeof(k_gh_plaintext));
    CHECK(final_len == 0);
    CHECK_BUF_EQ(plaintext, k_gh_plaintext, sizeof(plaintext),
                 "MGM plaintext mismatch");

    ok = 1;
cleanup:
    EVP_CIPHER_CTX_free(enc);
    EVP_CIPHER_CTX_free(dec);
    EVP_CIPHER_free(cipher);
    return ok;
}

int main(void)
{
    OPENSSL_add_all_algorithms_conf();

    if (!test_alg_id_roundtrip())
        return 1;
    if (!test_dupctx_stateful_ctr())
        return 1;
    if (!test_mgm_tag_params())
        return 1;

    printf("provider cipher params tests passed\n");
    return 0;
}
