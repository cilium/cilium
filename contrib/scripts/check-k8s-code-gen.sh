#!/usr/bin/env bash

set -e
set -o pipefail

# Delete all zz_generated.deepcopy.go files
find . -not -regex ".*/vendor/.*" -not -path "./_build/*" -name "zz_generated.deepcopy.go" -exec rm  {} \;
# Delete all zz_generated.deepequal.go files
find . -not -regex ".*/vendor/.*" -not -path "./_build/*" -name "zz_generated.deepequal.go" -exec rm  {} \;
# Delete all generated proto and proto go files
find . -not -regex ".*/vendor/.*" -not -path "./_build/*" -name "generated.pb.go" -exec rm  {} \;
find . -not -regex ".*/vendor/.*" -not -path "./_build/*" -name "generated.proto" -exec rm  {} \;
# Delete cilium clientsets, informers & listers
rm -rf ./pkg/k8s/client/{clientset,informers,listers}
# Delete k8s slim clients
rm -rf ./pkg/k8s/slim/k8s/{client,apiextensions-client}

# Generate all files
make generate-k8s-api manifests

# Ensure new files are also considered in the diff
git add --intent-to-add .

# Check for diff
diff="$(git diff)"
diff_staged="$(git diff --staged)"

if [ -n "$diff" ] || [ -n "$diff_staged" ]; then
	echo "Ungenerated source code:"
	echo "$diff"
	echo "$diff_staged"
	echo "Please run make 'generate-k8s-api && make manifests' and submit your changes"
	exit 1
fi

exit 0
