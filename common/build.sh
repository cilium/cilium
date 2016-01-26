#!/bin/bash

pushd `dirname $0` > /dev/null
P="`pwd`/.."
popd > /dev/null

cd "$P"
make clean
make
