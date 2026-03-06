/**********************************************************************
 *                          md_gost.c                                 *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *             Copyright (c) 2020 Vitaly Chikunov <vt@altlinux.org>   *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *       OpenSSL interface to GOST R 34.11-94 hash functions          *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
#include <string.h>
#include "gost_lcl.h"
#include "e_gost_err.h"

/*
 * Single level template accessor.
 * Note: that you cannot template 0 value.
 */
#define TPL(st,field) ( \
    ((st)->field) ? ((st)->field) : TPL_VAL(st,field) \
)

#define TPL_VAL(st,field) ( \
    ((st)->template ? (st)->template->field : 0) \
)

EVP_MD *GOST_init_digest_94();
EVP_MD *GOST_init_digest_2012_256();
EVP_MD *GOST_init_digest_2012_512();

EVP_MD *GOST_init_digest(GOST_digest *d)
{
    if (d->digest)
        return d->digest;

    EVP_MD *md;

    if (d == &GostR3411_94_digest_legacy) {
        md = GOST_init_digest_94();
    } else if (d == &GostR3411_2012_256_digest_legacy) {
        md = GOST_init_digest_2012_256();
    } else if (d == &GostR3411_2012_512_digest_legacy) {
        md = GOST_init_digest_2012_512();
    }
    else if (!(md = EVP_MD_meth_new(d->nid, NID_undef))
        || !EVP_MD_meth_set_result_size(md, TPL(d, result_size))
        || !EVP_MD_meth_set_input_blocksize(md, TPL(d, input_blocksize))
        || !EVP_MD_meth_set_app_datasize(md, TPL(d, app_datasize))
        || !EVP_MD_meth_set_flags(md, d->flags | TPL_VAL(d, flags))
        || !EVP_MD_meth_set_init(md, TPL(d, init))
        || !EVP_MD_meth_set_update(md, TPL(d, update))
        || !EVP_MD_meth_set_final(md, TPL(d, final))
        || !EVP_MD_meth_set_copy(md, TPL(d, copy))
        || !EVP_MD_meth_set_cleanup(md, TPL(d, cleanup))
        || !EVP_MD_meth_set_ctrl(md, TPL(d, ctrl))) {
        EVP_MD_meth_free(md);
        md = NULL;
    }
    if (md && d->alias)
        EVP_add_digest_alias(EVP_MD_name(md), d->alias);
    d->digest = md;
    return md;
}

void GOST_deinit_digest(GOST_digest *d)
{
    if (d->alias)
        EVP_delete_digest_alias(d->alias);
    EVP_MD_meth_free(d->digest);
    d->digest = NULL;
}

/* vim: set expandtab cinoptions=\:0,l1,t0,g0,(0 sw=4 : */
