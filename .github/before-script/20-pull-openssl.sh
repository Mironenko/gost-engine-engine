#!/bin/bash -efux

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")

source "${SCRIPT_DIR}/../config.sh"

cd "$SCRIPT_DIR/../../"

git clone --depth 1 -b $OPENSSL_BRANCH https://github.com/openssl/openssl.git
if [ "${PATCH_OPENSSL}" == "1" ]; then
    if [ "${OPENSSL_BRANCH}" == "master" ]; then
        git apply patches/openssl4-tls1.3.patch
    else
        git apply patches/openssl-tls1.3.patch
        git apply patches/openssl-asn1_item_verify_ctx.patch
        git apply patches/openssl-get_digestbynid.patch
    fi
fi