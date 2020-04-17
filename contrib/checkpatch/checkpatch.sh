#!/bin/bash

if ! command -v git > /dev/null ; then
    exit 0
fi

SCRIPT_DIR="$(dirname $(realpath $0))"
CHECKPATCH="$SCRIPT_DIR/checkpatch.pl"
OPTIONS="--quiet --no-tree --strict --show-types"
IGNORES=""

# Script is in contrib/checkpatch/
cd "$SCRIPT_DIR/../../"
git diff -- bpf 2>/dev/null | $CHECKPATCH $OPTIONS $IGNORES
