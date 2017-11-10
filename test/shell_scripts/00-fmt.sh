#!/usr/bin/env sh

set -x

diff="$(find . ! \( -path './contrib' -prune \) \
        ! \( -path './vendor' -prune \) \
        ! \( -path './.git' -prune \) \
        ! -samefile ./daemon/bindata.go \
        -type f -name '*.go' -print0 \
                | xargs -0 gofmt -d -l -s )"
set -e

if [ -n "$diff" ]; then
	echo "Unformatted Go source code:"
	echo "$diff"
	exit 1
fi

exit 0
