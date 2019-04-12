#!/bin/bash

set -o errexit

llc --version

export CFLAGS="-Werror"
export CGO_CFLAGS="-DCI_BUILD"

dep check
make unit-tests

$HOME/gopath/bin/goveralls -coverprofile=coverage-all.out -service=travis-ci || true

exit 0
