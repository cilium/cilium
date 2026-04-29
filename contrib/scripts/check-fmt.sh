#!/usr/bin/env bash

set -e
set -o pipefail

_goroot=$(${GO:-go} env GOROOT)

# Go 1.26 changed `gofmt -d` to exit non-zero when a diff is found
# (https://cs.opensource.google/go/go/+/d945600d060e7a0b7c5e72ac606a017d105a17f3),
# which combined with `set -e -o pipefail` above kills this script before the
# user-friendly "Unformatted Go source code" branch below can run. Capture the
# output and exit code explicitly so we can dispatch on whether a diff was found
# (exit 1 with helpful message) versus a real gofmt failure (propagate the code).
set +e
diff="$(find . ! \( -path './contrib' -prune \) \
        ! \( -regex '.*/vendor/.*' -prune \) \
        ! \( -path './_build' -prune \) \
        ! \( -path './.git' -prune \) \
        ! \( -path '*.validate.go' -prune \) \
        -type f -name '*.go' | grep -Ev "(pkg/k8s/apis/cilium.io/v2/client/bindata.go)" | \
        xargs $_goroot/bin/gofmt -d -l -s )"
gofmt_exit=$?
set -e

if [ -n "$diff" ]; then
	echo "Unformatted Go source code:"
	echo "$diff"
	exit 1
fi

if [ "$gofmt_exit" -ne 0 ]; then
	echo "gofmt exited with $gofmt_exit but produced no diff" >&2
	exit "$gofmt_exit"
fi

exit 0
