#include "gost_cipher_details.h"

#include <string.h>

static int gost_cipher_provider_padblock(unsigned char *buf, size_t buflen,
                                         size_t blocksize)
{
    unsigned char pad = (unsigned char)(blocksize - buflen);

    memset(buf + buflen, pad, blocksize - buflen);
    return 1;
}

static int gost_cipher_provider_unpadblock(unsigned char *buf, size_t *buflen,
                                           size_t blocksize)
{
    size_t len = *buflen;
    size_t pad;
    size_t i;

    if (len != blocksize)
        return 0;

    pad = buf[blocksize - 1];
    if (pad == 0 || pad > blocksize)
        return 0;
    for (i = 0; i < pad; i++) {
        if (buf[--len] != pad)
            return 0;
    }

    *buflen = len;
    return 1;
}

int GOST_cipher_ctx_provider_update(GOST_cipher_ctx *ctx,
                                    unsigned char *out, size_t *outl,
                                    size_t outsize,
                                    const unsigned char *in, size_t inl)
{
    int (*do_cipher)(GOST_cipher_ctx *ctx, unsigned char *out,
                     const unsigned char *in, size_t inl);
    size_t outlint = 0;
    size_t blksz;
    size_t nextblocks;
    int ret;
    int pad;

    if (outl != NULL)
        *outl = 0;

    if (ctx == NULL || ctx->cipher == NULL)
        return 0;

    do_cipher = GOST_cipher_do_cipher_fn(ctx->cipher);
    if (do_cipher == NULL)
        return 0;

    if ((GOST_cipher_flags(ctx->cipher) & EVP_CIPH_FLAG_CUSTOM_CIPHER) != 0) {
        ret = do_cipher(ctx, out, in, inl);
        if (ret < 0 || (size_t)ret > outsize)
            return 0;
        if (outl != NULL)
            *outl = (size_t)ret;
        return 1;
    }

    if (inl == 0)
        return 1;

    blksz = (size_t)GOST_cipher_block_size(ctx->cipher);
    if (blksz == 1) {
        if (outsize < inl || !do_cipher(ctx, out, in, inl))
            return 0;
        if (outl != NULL)
            *outl = inl;
        return 1;
    }

    pad = (ctx->flags & EVP_CIPH_NO_PADDING) == 0;
    if (ctx->buf_len != 0) {
        size_t copied = blksz - (size_t)ctx->buf_len;

        if (copied > inl)
            copied = inl;
        memcpy(ctx->buf + ctx->buf_len, in, copied);
        ctx->buf_len += (int)copied;
        in += copied;
        inl -= copied;
    }

    if ((size_t)ctx->buf_len == blksz && (ctx->encrypt || inl > 0 || !pad)) {
        if (outsize < blksz || !do_cipher(ctx, out, ctx->buf, blksz))
            return 0;
        ctx->buf_len = 0;
        outlint = blksz;
        out += blksz;
        outsize -= blksz;
    }

    nextblocks = inl - (inl % blksz);
    if (nextblocks > 0) {
        if (!ctx->encrypt && pad && nextblocks == inl) {
            if (inl < blksz)
                return 0;
            nextblocks -= blksz;
        }
        if (outsize < nextblocks)
            return 0;
    }

    if (nextblocks > 0) {
        if (!do_cipher(ctx, out, in, nextblocks))
            return 0;
        out += nextblocks;
        outsize -= nextblocks;
        outlint += nextblocks;
        in += nextblocks;
        inl -= nextblocks;
    }

    if (inl != 0) {
        if ((size_t)ctx->buf_len + inl > blksz)
            return 0;
        memcpy(ctx->buf + ctx->buf_len, in, inl);
        ctx->buf_len += (int)inl;
    }

    if (outl != NULL)
        *outl = outlint;
    return 1;
}

int GOST_cipher_ctx_provider_final(GOST_cipher_ctx *ctx,
                                   unsigned char *out, size_t *outl,
                                   size_t outsize)
{
    int (*do_cipher)(GOST_cipher_ctx *ctx, unsigned char *out,
                     const unsigned char *in, size_t inl);
    size_t blksz;
    size_t buflen;
    int ret;
    int pad;

    if (outl != NULL)
        *outl = 0;

    if (ctx == NULL || ctx->cipher == NULL)
        return 0;

    do_cipher = GOST_cipher_do_cipher_fn(ctx->cipher);
    if (do_cipher == NULL)
        return 0;

    if ((GOST_cipher_flags(ctx->cipher) & EVP_CIPH_FLAG_CUSTOM_CIPHER) != 0) {
        ret = do_cipher(ctx, out, NULL, 0);
        if (ret < 0 || (size_t)ret > outsize)
            return 0;
        if (outl != NULL)
            *outl = (size_t)ret;
        return 1;
    }

    blksz = (size_t)GOST_cipher_block_size(ctx->cipher);
    if (blksz == 1)
        return 1;

    pad = (ctx->flags & EVP_CIPH_NO_PADDING) == 0;
    buflen = (size_t)ctx->buf_len;

    if (ctx->encrypt) {
        if (pad) {
            gost_cipher_provider_padblock(ctx->buf, buflen, blksz);
            buflen = blksz;
        } else if (buflen == 0) {
            return 1;
        } else if (buflen != blksz) {
            return 0;
        }

        if (outsize < blksz || !do_cipher(ctx, out, ctx->buf, blksz))
            return 0;
        ctx->buf_len = 0;
        if (outl != NULL)
            *outl = blksz;
        return 1;
    }

    if (buflen != blksz) {
        if (buflen == 0 && !pad)
            return 1;
        return 0;
    }

    if (!do_cipher(ctx, ctx->buf, ctx->buf, blksz))
        return 0;

    if (pad && !gost_cipher_provider_unpadblock(ctx->buf, &buflen, blksz))
        return 0;
    if (outsize < buflen)
        return 0;
    if (buflen > 0)
        memcpy(out, ctx->buf, buflen);

    ctx->buf_len = 0;
    if (outl != NULL)
        *outl = buflen;
    return 1;
}
