#ifndef GOST_ENG_PMETH_H
#define GOST_ENG_PMETH_H

#include <openssl/evp.h>

int register_pmeth_gost(int id, EVP_PKEY_METHOD **pmeth, int flags);
int pkey_gost_mac_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value);
int pkey_gost_mac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
int pkey_gost_omac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2, size_t max_size);

#endif /* GOST_ENG_PMETH_H */
