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

# Generate all api files
make generate-api

# Generate all health-api files
make generate-health-api

# Generate operator-api files
make generate-operator-api

# Generate all hubble api files
make generate-hubble-api

# Check for diff
diff="$(git diff)"

if [ -n "$diff" ]; then
	echo "Ungenerated api source code:"
	echo "$diff"
	echo "Please run 'make generate-api generate-health-api generate-hubble-api generate-operator-api' and submit your changes"
	exit 1
fi

exit 0
