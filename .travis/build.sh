#!/bin/bash

set -o errexit

export CFLAGS="-Werror"
export CGO_CFLAGS="-DCI_BUILD"

make unit-tests

$HOME/gopath/bin/goveralls -coverprofile=coverage-all.out -service=travis-ci || true

exit 0
