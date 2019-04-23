#!/usr/bin/env bash

set -e
set -o pipefail

if find ./daemon/bindata.go ; then
  diff="$(find . ! \( -path './contrib' -prune \) \
        ! \( -path './vendor' -prune \) \
        ! \( -path './.git' -prune \) \
        ! \( -path '*.validate.go' -prune \) \
        ! -samefile ./daemon/bindata.go \
        -type f -name '*.go' -print0 \
                | xargs -0 gofmt -d -l -s )"
else 
  diff="$(find . ! \( -path './contrib' -prune \) \
        ! \( -path './vendor' -prune \) \
        ! \( -path './.git' -prune \) \
        ! \( -path '*.validate.go' -prune \) \
        -type f -name '*.go' -print0 \
                | xargs -0 gofmt -d -l -s )"
fi

if [ -n "$diff" ]; then
	echo "Unformatted Go source code:"
	echo "$diff"
	exit 1
fi

exit 0
