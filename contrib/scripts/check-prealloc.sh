#!/usr/bin/env bash

set -e
set -o pipefail

allocs="$(prealloc ./... 2>&1)"

if [ -n "$allocs" ]; then
	echo "Found slice declarations that could potentially be preallocated:"
	echo "$allocs"
	exit 1
fi

exit 0
