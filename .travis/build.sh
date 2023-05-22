#!/usr/bin/env bash

set -o errexit

export CFLAGS="-Werror"

make -j 2 --quiet
make integration-tests --quiet

exit 0
