#!/bin/bash

set -e

pushd `dirname $0` > /dev/null
P="`pwd`/.."
popd > /dev/null

cd "$P"
go install ./... 2> /dev/null || true
make clean

# Build debug version of Envoy
make -C envoy debug
# Compile with deadlock detection during runtime tests. See GH-1654.
LOCKDEBUG=1 CILIUM_DISABLE_ENVOY_BUILD=1 make
