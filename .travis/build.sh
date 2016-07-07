#!/bin/bash

set -o errexit

export CFLAGS="-Werror"
export CGO_CFLAGS="-DCI_BUILD"

make
make -B tests

exit 0
