#!/bin/bash

for pkg in $(go list ./... | grep "types$" | grep -v "hubble"); do
	# Build on darwin/windows, this should be sufficient to ensure portability in terms of:
	# * No packages linked C libraries, such as pkg/bpf.
	# * No compilation errors due to common platform compiler directives.
	# * No use of 'unix' stl.
	if GOOS=darwin go build $pkg 2>/dev/null && GOOS=windows go build $pkg 2>/dev/null ; then
		echo "[OK] $pkg"
	else
		echo "[FAIL] $pkg fails to build on multiple platforms"
		exit 1
	fi
done

