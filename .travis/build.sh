#!/bin/bash

set -o errexit

export CFLAGS="-Werror"

# make -j 2
make start-kvstores

$HOME/gopath/bin/goveralls -coverprofile=coverage-all.out -service=travis-ci || true

exit 0
