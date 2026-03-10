#ifndef GOST_ENG_PMETH_H
#define GOST_ENG_PMETH_H

#include <openssl/evp.h>

int register_pmeth_gost(int id, EVP_PKEY_METHOD **pmeth, int flags);

#endif /* GOST_ENG_PMETH_H */