#!/usr/bin/env bash

# check-assert-deep-equals.sh checks whether DeepEquals checker from
# pkg/checker is used every time instead of the checker from gopkg.in/check.v1.
# If not, it returns an error. Cilium implements its own DeepEquals checker
# which gives a more detailed trace when the assertion fails.

set -eu

if grep -IPRns 'c.Assert\(.*, (check\.)?DeepEquals, .*\)' \
        --exclude-dir={.git,_build,vendor} \
        --include=*.go; then
    echo "Found tests which use DeepEquals checker imported from check.v1."
    echo "Cilium implements its own DeepEquals checker which can be imported from:"
    echo -e "\tgithub.com/cilium/cilium/pkg/checker"
    echo "It gives a more detailed trace when the assertion fails."
    exit 1
fi
