#!/bin/bash

set -o errexit

export CFLAGS="-Werror"
export CGO_CFLAGS="-DCI_BUILD"

make

exit 0
