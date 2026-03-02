#pragma once

#include <stddef.h>

int gost_kdftree2012_256(unsigned char *keyout, size_t keyout_len,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *label, size_t label_len,
                         const unsigned char *seed, size_t seed_len,
                         const size_t representation);

int gost_tlstree_magma_cbc(const unsigned char *in, unsigned char *out,
                           const unsigned char *tlsseq, int mode);
int gost_tlstree_grasshopper_cbc(const unsigned char *in, unsigned char *out,
                           const unsigned char *tlsseq, int mode);
int gost_tlstree_magma_mgm(const unsigned char *in, unsigned char *out,
                           const unsigned char *tlsseq, int mode);
int gost_tlstree_grasshopper_mgm(const unsigned char *in, unsigned char *out,
                           const unsigned char *tlsseq, int mode);

#define TLSTREE_MODE_NONE                                  0
#define TLSTREE_MODE_S                                     1
#define TLSTREE_MODE_L                                     2