#!/bin/bash

set -o errexit

export CFLAGS="-Werror"
export CGO_CFLAGS="-DCI_BUILD"
export CLANG="clang-10"
export LLC="llc-10"

make unit-tests

$HOME/gopath/bin/goveralls -coverprofile=coverage-all.out -service=travis-ci || true

exit 0
