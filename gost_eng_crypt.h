#ifndef GOST_ENG_CRYPT_H
#define GOST_ENG_CRYPT_H

#include <openssl/evp.h>
#include <openssl/types.h>

#include "gost_lcl.h"

EVP_CIPHER *GOST_init_cipher(GOST_cipher *c);
void GOST_deinit_cipher(GOST_cipher *c);

EVP_MD *GOST_init_digest(GOST_digest *d);
void GOST_deinit_digest(GOST_digest *d);

#endif
