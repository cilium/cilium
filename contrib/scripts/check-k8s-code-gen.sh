#!/usr/bin/env bash

set -e
set -o pipefail

# Delete all zz_generated.deepcopy.go files
find . -not -path "./vendor/*" -not -path "./_build/*" -iname "*zz_generated.deepcopy.go" -exec rm  {} \;
# Delete all zz_generated.deepequal.go files
find . -not -path "./vendor/*" -not -path "./_build/*" -iname "*zz_generated.deepequal.go" -exec rm  {} \;

# Generate all files
make generate-k8s-api manifests

# Check for diff
diff="$(git diff)"

if [ -n "$diff" ]; then
	echo "Ungenerated deepcopy source code:"
	echo "$diff"
	echo "Please run make generate-k8s-api and submit your changes"
	exit 1
fi

exit 0
