#!/usr/bin/env bash

DOC_DIR=../Documentation
LINKCHECK_OUTPUT=$DOC_DIR/_build/linkcheck/output.txt

make -C $DOC_DIR clean || true
make -C $DOC_DIR linkcheck || true

if grep "Not Found for url" $LINKCHECK_OUTPUT; then
  exit 1
fi

# TODO: also check the README.md
