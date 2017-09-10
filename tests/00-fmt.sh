#!/usr/bin/env sh

set -ex

diff="$(find . ! \( -path './vendor' -prune \) ! -samefile ./daemon/bindata.go -type f -name '*.go' -print0 | xargs -0 gofmt -d -l -s )"

if [ -n "$diff" ]; then
	echo "Unformatted Go source code:"
	echo "$diff"
	exit 1
fi

exit 0
