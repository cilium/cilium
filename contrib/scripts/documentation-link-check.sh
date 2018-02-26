#!/usr/bin/env bash

set -ex

DOC_DIR=../Documentation
LINKCHECK_OUTPUT=$DOC_DIR/_build/linkcheck/output.txt

if [ -z $LINKCHECK ]; then
  echo "Skipping linkcheck, run with LINKCHECK=1 to enable"
  exit 0
fi

make -C $DOC_DIR clean || true
make -C $DOC_DIR linkcheck || true

if grep "Not Found for url" $LINKCHECK_OUTPUT; then
  exit 1
fi

# TODO: also check the README.md
test_succeeded "${TEST_NAME}"
