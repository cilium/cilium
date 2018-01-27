#!/bin/bash

set -e

DOCS_DIR=./Documentation
OLD_DIR=${DOCS_DIR}/cmdref
TMP_DIR=`mktemp -d`

make CMDREFDIR=${TMP_DIR} -C ${DOCS_DIR} cmdref

if ! diff -x '*.rst' -r ${OLD_DIR} ${TMP_DIR}; then
  # echo is used here intentional to avoid the splat when running from top
  # level directory.
  echo "Detected a difference in the cmdref directory"
  echo "diff -r: `diff -r ${OLD_DIR} ${TMP_DIR}`"
  echo "Please rerun 'make -C Documentation cmdref' and commit your changes"
  exit 1
fi
