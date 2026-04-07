#!/bin/bash -efux

source $(dirname "${BASH_SOURCE[0]}")/config.sh

PATH=$OPENSSL_INSTALL_PREFIX/bin:$PATH
GOST_ENABLE_LEGACY=${GOST_ENABLE_LEGACY:-OFF}

mkdir -p build
cd build
cmake -DTLS13_PATCHED_OPENSSL=$PATCH_OPENSSL -DOPENSSL_ROOT_DIR=$OPENSSL_INSTALL_PREFIX \
    -DOPENSSL_ENGINES_DIR=$OPENSSL_INSTALL_PREFIX/engines ${ASAN-} \
    -DGOST_ENABLE_LEGACY=$GOST_ENABLE_LEGACY  ..
make
make test CTEST_OUTPUT_ON_FAILURE=1
if [ -z "${ASAN-}" ]; then
    if [ "$GOST_ENABLE_LEGACY" = "ON" ]; then
        make tcl_tests_engine
    fi
    make tcl_tests_provider
fi
