#include "gost_lcl.h"
#include "e_gost_err.h"

#include "gost_eng_digest.h"
#include "gost_digest_3411_94.h"
#include "gost_digest_3411_2012.h"
#include "gost_mac_28147_89.h"
#include "gost_mac_3412_omac.h"
#include "gost_mac_3412_ctracpkm.h"

GOST_eng_digest GostR3411_94_eng_digest = {
    .d = &GostR3411_94_digest,
};

GOST_eng_digest GostR3411_2012_256_eng_digest = {
    .d = &GostR3411_2012_256_digest,
};

GOST_eng_digest GostR3411_2012_512_eng_digest = {
    .d = &GostR3411_2012_512_digest,
};

GOST_eng_digest Gost28147_89_MAC_eng_digest = {
    .m = &Gost28147_89_mac,
};

GOST_eng_digest Gost28147_89_mac_12_eng_digest = {
    .m = &Gost28147_89_mac_12,
};

GOST_eng_digest magma_mac_eng_digest = {
    .m = &magma_omac_mac,
};

GOST_eng_digest grasshopper_mac_eng_digest = {
    .m = &grasshopper_omac_mac,
};

GOST_eng_digest magma_ctracpkm_omac_eng_digest = {
    .m = &magma_ctracpkm_mac,
};

GOST_eng_digest kuznyechik_ctracpkm_omac_eng_digest = {
    .m = &grasshopper_ctracpkm_mac,
};

EVP_MD *GOST_eng_digest_init_from_digest(const GOST_digest*);
EVP_MD *GOST_eng_digest_init_from_mac(const GOST_mac*);
void GOST_eng_digest_deinit_from_digest(const GOST_digest*);
void GOST_eng_digest_deinit_from_mac(const GOST_mac*);

int GOST_eng_digest_nid(const GOST_eng_digest *digest) {
    if (digest->d) {
        return GET_MEMBER(GOST_digest, digest->d, nid);
    } else if (digest->m) {
        return GET_MEMBER(GOST_mac, digest->m, nid);
    } else {
        return NID_undef;
    }
}

EVP_MD *GOST_eng_digest_init(GOST_eng_digest *digest)
{
    if (digest->digest)
        return digest->digest;

    EVP_MD *md = NULL;
    if (digest->d) {
        md = GOST_eng_digest_init_from_digest(digest->d);
    } else if (digest->m) {
        md = GOST_eng_digest_init_from_mac(digest->m);
    }

    digest->digest = md;
    return md;
}

void GOST_eng_digest_deinit(GOST_eng_digest *digest)
{
    if (digest->d) {
        GOST_eng_digest_deinit_from_digest(digest->d);
    } else if (digest->m) {
        GOST_eng_digest_deinit_from_mac(digest->m);
    }
    EVP_MD_meth_free(digest->digest);
    digest->digest = NULL;
}
