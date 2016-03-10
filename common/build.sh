#!/bin/bash

set -e

pushd `dirname $0` > /dev/null
P="`pwd`/.."
popd > /dev/null

cd "$P"
make
make tests
