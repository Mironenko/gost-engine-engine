#include <openssl/evp.h>
#include <openssl/objects.h>

#include "gost_lcl.h"
#include "gost_pmeth.h"
#include "gost_eng_pmeth.h"

int register_pmeth_gost(int id, EVP_PKEY_METHOD **pmeth, int flags)
{
    *pmeth = EVP_PKEY_meth_new(id, flags);
    if (!*pmeth)
        return 0;

    switch (id) {
    case NID_id_GostR3410_2001:
    case NID_id_GostR3410_2001DH:
        EVP_PKEY_meth_set_ctrl(*pmeth,
                               pkey_gost_ctrl, pkey_gost_ec_ctrl_str_256);
        EVP_PKEY_meth_set_sign(*pmeth, NULL, pkey_gost_ec_cp_sign);
        EVP_PKEY_meth_set_verify(*pmeth, NULL, pkey_gost_ec_cp_verify);
        EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_gost2001cp_keygen);
        EVP_PKEY_meth_set_encrypt(*pmeth,
                                  pkey_gost_encrypt_init,
                                  pkey_gost_encrypt);
        EVP_PKEY_meth_set_decrypt(*pmeth, NULL, pkey_gost_decrypt);
        EVP_PKEY_meth_set_derive(*pmeth,
                                 pkey_gost_derive_init, pkey_gost_ec_derive);
        EVP_PKEY_meth_set_paramgen(*pmeth, pkey_gost_paramgen_init,
                                   pkey_gost2001_paramgen);
        EVP_PKEY_meth_set_check(*pmeth, pkey_gost_check);
        EVP_PKEY_meth_set_public_check(*pmeth, pkey_gost_check);
        break;

    case NID_id_GostR3410_2012_256:
        EVP_PKEY_meth_set_ctrl(*pmeth,
                               pkey_gost_ctrl, pkey_gost_ec_ctrl_str_256);
        EVP_PKEY_meth_set_sign(*pmeth, NULL, pkey_gost_ec_cp_sign);
        EVP_PKEY_meth_set_verify(*pmeth, NULL, pkey_gost_ec_cp_verify);
        EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_gost2012cp_keygen);
        EVP_PKEY_meth_set_encrypt(*pmeth,
                                  pkey_gost_encrypt_init,
                                  pkey_gost_encrypt);
        EVP_PKEY_meth_set_decrypt(*pmeth, NULL, pkey_gost_decrypt);
        EVP_PKEY_meth_set_derive(*pmeth,
                                 pkey_gost_derive_init, pkey_gost_ec_derive);
        EVP_PKEY_meth_set_paramgen(*pmeth,
                                   pkey_gost_paramgen_init,
                                   pkey_gost2012_paramgen);
        EVP_PKEY_meth_set_check(*pmeth, pkey_gost_check);
        EVP_PKEY_meth_set_public_check(*pmeth, pkey_gost_check);
        break;

    case NID_id_GostR3410_2012_512:
        EVP_PKEY_meth_set_ctrl(*pmeth,
                               pkey_gost_ctrl, pkey_gost_ec_ctrl_str_512);
        EVP_PKEY_meth_set_sign(*pmeth, NULL, pkey_gost_ec_cp_sign);
        EVP_PKEY_meth_set_verify(*pmeth, NULL, pkey_gost_ec_cp_verify);
        EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_gost2012cp_keygen);
        EVP_PKEY_meth_set_encrypt(*pmeth,
                                  pkey_gost_encrypt_init,
                                  pkey_gost_encrypt);
        EVP_PKEY_meth_set_decrypt(*pmeth, NULL, pkey_gost_decrypt);
        EVP_PKEY_meth_set_derive(*pmeth,
                                 pkey_gost_derive_init, pkey_gost_ec_derive);
        EVP_PKEY_meth_set_paramgen(*pmeth,
                                   pkey_gost_paramgen_init,
                                   pkey_gost2012_paramgen);
        EVP_PKEY_meth_set_check(*pmeth, pkey_gost_check);
        EVP_PKEY_meth_set_public_check(*pmeth, pkey_gost_check);
        break;

    case NID_id_Gost28147_89_MAC:
        EVP_PKEY_meth_set_ctrl(*pmeth, pkey_gost_mac_ctrl,
                               pkey_gost_mac_ctrl_str);
        EVP_PKEY_meth_set_signctx(*pmeth, pkey_gost_mac_signctx_init,
                                  pkey_gost_mac_signctx);
        EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_gost_mac_keygen);
        EVP_PKEY_meth_set_init(*pmeth, pkey_gost_mac_init);
        EVP_PKEY_meth_set_cleanup(*pmeth, pkey_gost_mac_cleanup);
        EVP_PKEY_meth_set_copy(*pmeth, pkey_gost_mac_copy);
        return 1;

    case NID_gost_mac_12:
        EVP_PKEY_meth_set_ctrl(*pmeth, pkey_gost_mac_ctrl,
                               pkey_gost_mac_ctrl_str);
        EVP_PKEY_meth_set_signctx(*pmeth, pkey_gost_mac_signctx_init,
                                  pkey_gost_mac_signctx);
        EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_gost_mac_keygen_12);
        EVP_PKEY_meth_set_init(*pmeth, pkey_gost_mac_init);
        EVP_PKEY_meth_set_cleanup(*pmeth, pkey_gost_mac_cleanup);
        EVP_PKEY_meth_set_copy(*pmeth, pkey_gost_mac_copy);
        return 1;

    case NID_magma_mac:
    case NID_id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac:  /* FIXME beldmit */
        EVP_PKEY_meth_set_ctrl(*pmeth, pkey_gost_magma_mac_ctrl,
                               pkey_gost_magma_mac_ctrl_str);
        EVP_PKEY_meth_set_signctx(*pmeth, pkey_gost_magma_mac_signctx_init,
                                  pkey_gost_mac_signctx);
        EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_gost_magma_mac_keygen);
        EVP_PKEY_meth_set_init(*pmeth, pkey_gost_magma_mac_init);
        EVP_PKEY_meth_set_cleanup(*pmeth, pkey_gost_mac_cleanup);
        EVP_PKEY_meth_set_copy(*pmeth, pkey_gost_mac_copy);
        return 1;

    case NID_grasshopper_mac:
    case NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac: /* FIXME beldmit */
        EVP_PKEY_meth_set_ctrl(*pmeth, pkey_gost_grasshopper_mac_ctrl,
                               pkey_gost_grasshopper_mac_ctrl_str);
        EVP_PKEY_meth_set_signctx(*pmeth, pkey_gost_grasshopper_mac_signctx_init,
                                  pkey_gost_mac_signctx);
        EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_gost_grasshopper_mac_keygen);
        EVP_PKEY_meth_set_init(*pmeth, pkey_gost_grasshopper_mac_init);
        EVP_PKEY_meth_set_cleanup(*pmeth, pkey_gost_mac_cleanup);
        EVP_PKEY_meth_set_copy(*pmeth, pkey_gost_mac_copy);
        return 1;

    default:                   /* Unsupported method */
        return 0;
    }

    EVP_PKEY_meth_set_init(*pmeth, pkey_gost_init);
    EVP_PKEY_meth_set_cleanup(*pmeth, pkey_gost_cleanup);
    EVP_PKEY_meth_set_copy(*pmeth, pkey_gost_copy);

    return 1;
}