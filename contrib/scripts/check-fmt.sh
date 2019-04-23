#!/usr/bin/env sh

set -exv

echo "listing contents of current dir"
ls
echo "done listing contents of current dir"
diff="$(find . ! \( -path './contrib' -prune \) \
        ! \( -path './vendor' -prune \) \
        ! \( -path './.git' -prune \) \
        ! \( -path '*.validate.go' -prune \) \
        ! -samefile ./daemon/bindata.go \
        -type f -name '*.go' -print0 \
                | xargs -0 gofmt -d -l -s )"

if [ -n "$diff" ]; then
	echo "Unformatted Go source code:"
	echo "$diff"
	exit 1
fi

exit 0
