#pragma once

#include <openssl/evp.h>

#include "gost_cipher.h"

struct gost_cipher_ctx_st {
    const GOST_cipher *cipher;   /* cipher descriptor */
    EVP_CIPHER_CTX *cctx;        /* underlying EVP context */
};