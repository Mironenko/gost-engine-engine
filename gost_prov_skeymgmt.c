#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include "gost_prov.h"
#include "gost_lcl.h"

#if defined(OSSL_OP_SKEYMGMT)

typedef void (*fptr_t)(void);

static void gost_skey_free(void *keydata)
{
    GOST_SKEY *skey = keydata;

    if (skey == NULL)
        return;
    OPENSSL_clear_free(skey->raw_bytes, skey->raw_bytes_len);
    OPENSSL_free(skey->key_id);
    OPENSSL_free(skey);
}

static GOST_SKEY *gost_skey_new(GOST_SKEY_TYPE type, const unsigned char *raw,
                                size_t raw_len)
{
    GOST_SKEY *skey = NULL;
    const char *name = gost_skey_type_name(type);
    size_t key_id_len;

    if ((skey = OPENSSL_zalloc(sizeof(*skey))) == NULL)
        return NULL;

    skey->type = type;
    skey->raw_bytes_len = raw_len;
    if ((skey->raw_bytes = OPENSSL_memdup(raw, raw_len)) == NULL)
        goto err;

    key_id_len = strlen(name) + 32;
    if ((skey->key_id = OPENSSL_zalloc(key_id_len)) == NULL)
        goto err;
    BIO_snprintf(skey->key_id, key_id_len, "%s:%lu", name,
                 (unsigned long)raw_len);
    return skey;

err:
    gost_skey_free(skey);
    return NULL;
}

static GOST_SKEY_TYPE algname_to_type(const char *algname)
{
    if (algname == NULL)
        return GOST_SKEY_TYPE_GENERIC;
    if (OPENSSL_strcasecmp(algname, "magma") == 0)
        return GOST_SKEY_TYPE_MAGMA;
    if (OPENSSL_strcasecmp(algname, "grasshopper") == 0)
        return GOST_SKEY_TYPE_GRASSHOPPER;
    if (OPENSSL_strcasecmp(algname, "gost89") == 0)
        return GOST_SKEY_TYPE_GOST89;
    return GOST_SKEY_TYPE_GENERIC;
}

static int expected_key_len(GOST_SKEY_TYPE type)
{
    switch (type) {
    case GOST_SKEY_TYPE_GOST89:
    case GOST_SKEY_TYPE_MAGMA:
    case GOST_SKEY_TYPE_GRASSHOPPER:
        return 32;
    default:
        return 0;
    }
}

struct gost_skey_import_st {
    const OSSL_PARAM *raw_bytes;
};

static int gost_skey_import_decoder(const OSSL_PARAM params[],
                                    struct gost_skey_import_st *out)
{
    out->raw_bytes = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_RAW_BYTES);
    return out->raw_bytes != NULL;
}

static void *gost_skey_import(void *provctx, int selection,
                              const OSSL_PARAM params[], const char *algname)
{
    struct gost_skey_import_st in;
    GOST_SKEY_TYPE type = algname_to_type(algname);

    if ((selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY) == 0)
        return NULL;
    if (!gost_skey_import_decoder(params, &in)
        || in.raw_bytes->data_type != OSSL_PARAM_OCTET_STRING)
        return NULL;
    if (expected_key_len(type) > 0
        && in.raw_bytes->data_size != (size_t)expected_key_len(type))
        return NULL;
    return gost_skey_new(type, in.raw_bytes->data, in.raw_bytes->data_size);
}

static int gost_skey_export(void *keydata, int selection,
                            OSSL_CALLBACK *param_callback, void *cbarg)
{
    GOST_SKEY *skey = keydata;
    OSSL_PARAM params[2];

    if (skey == NULL || (selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY) == 0)
        return 0;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_SKEY_PARAM_RAW_BYTES,
                                                  skey->raw_bytes,
                                                  skey->raw_bytes_len);
    params[1] = OSSL_PARAM_construct_end();
    return param_callback(params, cbarg);
}

static void *gost_skey_generate(void *provctx, const OSSL_PARAM params[],
                                const char *algname)
{
    GOST_SKEY_TYPE type = algname_to_type(algname);
    unsigned char raw[32];
    int keylen = expected_key_len(type);

    if (keylen <= 0)
        return NULL;
    if (RAND_bytes_ex(((PROV_CTX *)provctx)->libctx, raw, keylen, 0) <= 0)
        return NULL;
    return gost_skey_new(type, raw, (size_t)keylen);
}

static const OSSL_PARAM *gost_skey_imp_settable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SKEY_PARAM_RAW_BYTES, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

static const OSSL_PARAM *gost_skey_gen_settable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END
    };
    return params;
}

static const char *gost_skey_get_key_id(void *keydata)
{
    GOST_SKEY *skey = keydata;
    return skey != NULL ? skey->key_id : NULL;
}

#define MAKE_SKEYMGMT(name)                                                   \
    static OSSL_FUNC_skeymgmt_import_fn name##_skey_import;                   \
    static void *name##_skey_import(void *provctx, int selection,             \
                                    const OSSL_PARAM params[])                \
    {                                                                         \
        return gost_skey_import(provctx, selection, params, #name);          \
    }                                                                         \
    static OSSL_FUNC_skeymgmt_generate_fn name##_skey_generate;               \
    static void *name##_skey_generate(void *provctx, const OSSL_PARAM params[]) \
    {                                                                         \
        return gost_skey_generate(provctx, params, #name);                   \
    }                                                                         \
    static const OSSL_DISPATCH name##_skeymgmt_functions[] = {               \
        { OSSL_FUNC_SKEYMGMT_FREE, (fptr_t)gost_skey_free },                 \
        { OSSL_FUNC_SKEYMGMT_IMPORT, (fptr_t)name##_skey_import },           \
        { OSSL_FUNC_SKEYMGMT_EXPORT, (fptr_t)gost_skey_export },             \
        { OSSL_FUNC_SKEYMGMT_GENERATE, (fptr_t)name##_skey_generate },       \
        { OSSL_FUNC_SKEYMGMT_GET_KEY_ID, (fptr_t)gost_skey_get_key_id },     \
        { OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS,                            \
          (fptr_t)gost_skey_imp_settable_params },                           \
        { OSSL_FUNC_SKEYMGMT_GEN_SETTABLE_PARAMS,                            \
          (fptr_t)gost_skey_gen_settable_params },                           \
        OSSL_DISPATCH_END                                                    \
    }

MAKE_SKEYMGMT(gost89);
MAKE_SKEYMGMT(magma);
MAKE_SKEYMGMT(grasshopper);

const OSSL_ALGORITHM GOST_prov_skeymgmt[] = {
    { "gost89", NULL, gost89_skeymgmt_functions, "GOST 28147-89 secret key management" },
    { "magma", NULL, magma_skeymgmt_functions, "Magma secret key management" },
    { "grasshopper", NULL, grasshopper_skeymgmt_functions, "Grasshopper secret key management" },
    { NULL, NULL, NULL, NULL }
};

#endif
