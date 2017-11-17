#!/bin/bash

# We need to include the helper file so that it makes sure we are using the
# locally compiled Cilium binary.
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
set -ex

# Running this script should work both from CI and while building Cilium.
DOCS_DIR=${dir}/../Documentation
OLD_DIR=${DOCS_DIR}/cmdref
TMP_DIR=`mktemp -d`

make CMDREFDIR=${TMP_DIR} -C ${DOCS_DIR} cmdref

if ! diff -r ${OLD_DIR} ${TMP_DIR}; then
  # echo is used here intentional to avoid the splat when running from top
  # level directory.
  echo "Detected a difference in the cmdref directory"
  echo "diff -r: `diff -r ${OLD_DIR} ${TMP_DIR}`"
  echo "Please rerun 'make -C Documentation cmdref' and commit your changes"
  exit
fi
