#!/usr/bin/env bash

set -o errexit

export CFLAGS="-Werror"

# Travis kills builds that don't generate any output for 10 minutes.
# Set V=0 here to get GO/CHECK/CC lines, --quiet to hide long clang invocations.
V=0 make -j 2 --quiet

# Run with default verbosity here since this builds all Go code by running
# 'go vet' and all integration tests. At least one line of output is generated
# after each Go package is built and tested.
make integration-tests

exit 0
