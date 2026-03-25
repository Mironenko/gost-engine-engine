#ifndef GOST_ENG_MD_H
#define GOST_ENG_MD_H

#include <openssl/evp.h>
#include <openssl/types.h>

#include "gost_lcl.h"

EVP_MD *GOST_init_digest(GOST_digest *d);
void GOST_deinit_digest(GOST_digest *d);

#endif
