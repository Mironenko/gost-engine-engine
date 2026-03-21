#pragma once

#include <openssl/evp.h>

#include "gost_cipher.h"

#define GOST_CIPHER_CTX_BUF_SIZE (EVP_MAX_BLOCK_LENGTH * 2)

/* New GOST cipher context structure */
struct gost_cipher_ctx_st {
    const GOST_cipher *cipher;   /* cipher descriptor */
    unsigned char *buf;          /* mode-specific working buffer */
    int buf_len;                 /* number of bytes in partial block buffer */
    int final_used;              /* final block flag */
    int block_mask;              /* block_size - 1 */
    int encrypt;                 /* encrypt flag (1) or decrypt (0) */
    unsigned char final[EVP_MAX_BLOCK_LENGTH]; /* final block buffer */
    int flags;                   /* cipher flags */
    unsigned char iv[EVP_MAX_IV_LENGTH];    /* initialization vector */
    unsigned char original_iv[EVP_MAX_IV_LENGTH]; /* original IV */
    int iv_len;                  /* IV length */
    unsigned char key[EVP_MAX_KEY_LENGTH];  /* key */
    int key_len;                 /* key length */
    int num;                     /* mode-specific counter */
    void *app_data;              /* application data */
    void *cipher_data;           /* cipher-specific data (e.g., ossl_gost_cipher_ctx) */
};