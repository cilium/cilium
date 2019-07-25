#!/usr/bin/env bash

SHA_PATH="daemon/bpf.sha"
MAKE=${MAKE:-"make"}
if [ ! -e "$SHA_PATH" ]; then
	echo "Could not locate bpf.sha. Are you in the right directory?" >&2
	exit 1
fi

echo "GO_BINDATA_SHA1SUM=01234567890abcdef78901234567890abcdef789" > "$SHA_PATH"
echo "BPF_FILES=../bpf/.gitignore" >> "$SHA_PATH"
${MAKE} -C daemon apply-bindata
${MAKE} -C daemon apply-bindata
