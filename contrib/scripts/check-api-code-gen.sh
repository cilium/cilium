#!/usr/bin/env bash

set -e
set -o pipefail

# Remove api/v1/client generated code
rm -fr api/v1/client/

# Remove api/v1/models generated code
find api/v1/models/* -not -name 'doc.go' \
                     -not -name 'zz_generated.deepcopy.go' \
                     -not -name 'zz_generated.deepequal.go' \
                     -delete

# Remove api/v1/server generated code
find api/v1/server/* -not -name 'configure_cilium_api.go' \
                     -delete

# Remove api/v1/health generated code
rm -fr api/v1/health/client/
rm -fr api/v1/health/models/
find api/v1/health/server/* -not -name 'configure_cilium_health_api.go' \
                            -delete

# Remove api/v1/kvstoremesh generated code
rm -fr api/v1/kvstoremesh/client
find api/v1/kvstoremesh/models/* -not -name 'doc.go' \
                                 -not -name 'zz_generated.deepcopy.go' \
                                 -not -name 'zz_generated.deepequal.go' \
                                 -delete
find api/v1/kvstoremesh/server/* -not -name 'configure_kvstore_mesh.go' \
                                 -delete

# Generate all api files
make generate-api

# Generate all health-api files
make generate-health-api

# Generate operator-api files
make generate-operator-api

# Generate kvstoremesh-api files
make generate-kvstoremesh-api

# Generate all hubble api files
make generate-hubble-api

# Ensure new files are also considered in the diff
git add --intent-to-add .

# Check for diff
diff="$(git diff)"
diff_staged="$(git diff --staged)"

if [ -n "$diff" ] || [ -n "$diff_staged" ]; then
	echo "Ungenerated api source code:"
	echo "$diff"
	echo "$diff_staged"
	echo "Please run 'make generate-api generate-health-api generate-hubble-api generate-operator-api generate-kvstoremesh-api' and submit your changes"
	exit 1
fi

exit 0
