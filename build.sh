#!/bin/bash

BIN_PATH=$(readlink -f "$0")
ROOT_DIR=$(dirname $BIN_PATH)

set -euxo pipefail

if ! [ -x "$(command -v llvm-config)"  ]; then
    echo "Please install clang-10"
    exit 1
fi

PREFIX=${PREFIX:-${ROOT_DIR}/install/}

cargo build
cargo build --release

rm -rf ${PREFIX}
mkdir -p ${PREFIX}
mkdir -p ${PREFIX}/lib
cp target/release/*.a ${PREFIX}/lib

rm -rf build
mkdir -p build
cd build
cmake -DCMAKE_INSTALL_PREFIX=${PREFIX} -DCMAKE_BUILD_TYPE=Release ..
make # VERBOSE=1 
make install # VERBOSE=1