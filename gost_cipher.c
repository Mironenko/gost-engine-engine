#include "gost_cipher.h"
#include "gost_cipher_ctx.h"

#define TPL(st, field) (((st)->field) ? ((st)->field) : TPL_VAL(st, field))
#define TPL_VAL(st, field) ((st)->template ? (st)->template->field : 0)

int GOST_cipher_init(GOST_cipher *c)
{
    if (c == NULL)
        return 0;

    if (c->block_size == 0)
        c->block_size = TPL_VAL(c, block_size);
    if (c->key_len == 0)
        c->key_len = TPL_VAL(c, key_len);
    if (c->iv_len == 0)
        c->iv_len = TPL_VAL(c, iv_len);
    c->flags |= TPL_VAL(c, flags);
    if (c->init == NULL)
        c->init = TPL_VAL(c, init);
    if (c->do_cipher == NULL)
        c->do_cipher = TPL_VAL(c, do_cipher);
    if (c->cleanup == NULL)
        c->cleanup = TPL_VAL(c, cleanup);
    if (c->ctx_size == 0)
        c->ctx_size = TPL_VAL(c, ctx_size);
    if (c->set_asn1_parameters == NULL)
        c->set_asn1_parameters = TPL_VAL(c, set_asn1_parameters);
    if (c->get_asn1_parameters == NULL)
        c->get_asn1_parameters = TPL_VAL(c, get_asn1_parameters);
    if (c->ctrl == NULL)
        c->ctrl = TPL_VAL(c, ctrl);
    if (c->static_init == NULL)
        c->static_init = TPL_VAL(c, static_init);
    if (c->static_deinit == NULL)
        c->static_deinit = TPL_VAL(c, static_deinit);

    if (c->static_init != NULL)
        return c->static_init(c);

    return 1;
}

int GOST_cipher_deinit(GOST_cipher *c)
{
    if (c == NULL)
        return 0;
    if (c->static_deinit != NULL)
        return c->static_deinit(c);
    return 1;
}

int GOST_cipher_create_nid(GOST_cipher *c, const char *sn, const char *ln)
{
    int nid;
    ASN1_OBJECT *obj;

    if (c == NULL || sn == NULL || ln == NULL)
        return 0;

    if (c->nid != NID_undef)
        return 1;

    nid = OBJ_sn2nid(sn);
    if (nid != NID_undef) {
        c->nid = nid;
        return 1;
    }

    nid = OBJ_new_nid(1);
    obj = ASN1_OBJECT_create(nid, NULL, 0, sn, ln);
    if (obj == NULL || OBJ_add_object(obj) == NID_undef) {
        ASN1_OBJECT_free(obj);
        return 0;
    }

    c->nid = nid;
    c->data = obj;
    return 1;
}

int GOST_cipher_free_nid(GOST_cipher *c)
{
    if (c == NULL)
        return 0;

    if (c->data != NULL) {
        ASN1_OBJECT_free(c->data);
        c->data = NULL;
    }
    c->nid = NID_undef;
    return 1;
}

int GOST_cipher_type(const GOST_cipher *c)
{
    return c != NULL ? c->nid : NID_undef;
}

int GOST_cipher_nid(const GOST_cipher *c)
{
    return GOST_cipher_type(c);
}

int GOST_cipher_flags(const GOST_cipher *c)
{
    return c != NULL ? c->flags : 0;
}

int GOST_cipher_key_length(const GOST_cipher *c)
{
    return c != NULL ? c->key_len : 0;
}

int GOST_cipher_iv_length(const GOST_cipher *c)
{
    return c != NULL ? c->iv_len : 0;
}

int GOST_cipher_block_size(const GOST_cipher *c)
{
    return c != NULL ? c->block_size : 0;
}

int GOST_cipher_mode(const GOST_cipher *c)
{
    return c != NULL ? (c->flags & EVP_CIPH_MODE) : 0;
}

int GOST_cipher_ctx_size(const GOST_cipher *c)
{
    return c != NULL ? c->ctx_size : 0;
}

int (*GOST_cipher_init_fn(const GOST_cipher *c))(GOST_cipher_ctx *ctx,
                                                 const unsigned char *key,
                                                 const unsigned char *iv,
                                                 int enc)
{
    return c != NULL ? c->init : NULL;
}

int (*GOST_cipher_do_cipher_fn(const GOST_cipher *c))(GOST_cipher_ctx *ctx,
                                                      unsigned char *out,
                                                      const unsigned char *in,
                                                      size_t inl)
{
    return c != NULL ? c->do_cipher : NULL;
}

int (*GOST_cipher_cleanup_fn(const GOST_cipher *c))(GOST_cipher_ctx *ctx)
{
    return c != NULL ? c->cleanup : NULL;
}

int (*GOST_cipher_ctrl_fn(const GOST_cipher *c))(GOST_cipher_ctx *ctx,
                                                 int type, int arg,
                                                 void *ptr)
{
    return c != NULL ? c->ctrl : NULL;
}