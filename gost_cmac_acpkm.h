#pragma once

#include <openssl/evp.h>

#define ACPKM_T_MAX (EVP_MAX_KEY_LENGTH + EVP_MAX_BLOCK_LENGTH)

struct CMAC_ACPKM_CTX_st {
    /* Cipher context to use */
    EVP_CIPHER_CTX *cctx;
    /* CTR-ACPKM cipher */
    EVP_CIPHER* acpkm;
    EVP_CIPHER_CTX *actx;
    unsigned char km[ACPKM_T_MAX]; /* Key material */
    /* Temporary block */
    unsigned char tbl[EVP_MAX_BLOCK_LENGTH];
    /* Last (possibly partial) block */
    unsigned char last_block[EVP_MAX_BLOCK_LENGTH];
    /* Number of bytes in last block: -1 means context not initialised */
    int nlast_block;
    unsigned int section_size; /* N */
    unsigned int num; /* processed bytes until section_size */
};

typedef struct CMAC_ACPKM_CTX_st CMAC_ACPKM_CTX;

CMAC_ACPKM_CTX *CMAC_ACPKM_CTX_new(void);
void CMAC_ACPKM_CTX_cleanup(CMAC_ACPKM_CTX *ctx);
void CMAC_ACPKM_CTX_free(CMAC_ACPKM_CTX *ctx);
int CMAC_ACPKM_CTX_copy(CMAC_ACPKM_CTX *out, const CMAC_ACPKM_CTX *in);
int CMAC_ACPKM_Init(CMAC_ACPKM_CTX *ctx, const void *key, size_t keylen,
                    const EVP_CIPHER *cipher);
int CMAC_ACPKM_Update(CMAC_ACPKM_CTX *ctx, const void *in, size_t dlen);
int CMAC_ACPKM_Final(CMAC_ACPKM_CTX *ctx, unsigned char *out,
                     size_t *poutlen);
