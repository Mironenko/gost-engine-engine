#pragma once

#include <openssl/evp.h>
#include "gost_digest.h"
#include "gost_mac.h"

EVP_MD *GOST_eng_digest_init_from_digest(const GOST_digest*);
EVP_MD *GOST_eng_digest_init_from_mac(const GOST_mac*);
void GOST_eng_digest_deinit_from_digest(const GOST_digest*);
void GOST_eng_digest_deinit_from_mac(const GOST_mac*);

typedef struct gost_eng_digest_st GOST_eng_digest;
struct gost_eng_digest_st {
    const GOST_digest *d;
    const GOST_mac *m;
    EVP_MD *digest;
};

EVP_MD *GOST_eng_digest_init(GOST_eng_digest *d);
void GOST_eng_digest_deinit(GOST_eng_digest *d);
int GOST_eng_digest_nid(const GOST_eng_digest *digest);

extern GOST_eng_digest GostR3411_94_eng_digest;
extern GOST_eng_digest GostR3411_2012_256_eng_digest;
extern GOST_eng_digest GostR3411_2012_512_eng_digest;
extern GOST_eng_digest Gost28147_89_MAC_eng_digest;
extern GOST_eng_digest Gost28147_89_mac_12_eng_digest;
extern GOST_eng_digest magma_mac_eng_digest;
extern GOST_eng_digest grasshopper_mac_eng_digest;
extern GOST_eng_digest magma_ctracpkm_omac_eng_digest;
extern GOST_eng_digest kuznyechik_ctracpkm_omac_eng_digest;
