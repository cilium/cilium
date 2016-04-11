#!/bin/bash

set -e

pushd `dirname $0` > /dev/null
P="`pwd`/.."
popd > /dev/null

cd "$P"
godep go install ./... 2> /dev/null || true
make clean
make
make tests
