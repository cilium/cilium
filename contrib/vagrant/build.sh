#!/usr/bin/env bash

set -e

pushd `dirname $0` > /dev/null
P="`pwd`/../.."
popd > /dev/null

cd "$P"
go install ./... 2> /dev/null || true
if [ -n "${MAKECLEAN}" ]; then
    make clean
fi

# Compile with deadlock detection during runtime tests. See GH-1654.
LOCKDEBUG=1 make
