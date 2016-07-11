#!/usr/bin/env bash

set -e
echo "" > coverage.txt

export CGO_CFLAGS="-DCI_BUILD"

for d in $(find ./* -maxdepth 10 -type d); do
	if ls $d/*.go &> /dev/null; then
		go test -coverprofile=profile.out -covermode=atomic $d
		if [ -f profile.out ]; then
			cat profile.out >> coverage.txt
			rm profile.out
		fi
	fi
done
