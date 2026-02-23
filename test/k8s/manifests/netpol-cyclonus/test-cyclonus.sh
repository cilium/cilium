#!/usr/bin/env bash

set -eo pipefail
set -xv

# set up cyclonus
kubectl create clusterrolebinding cyclonus --clusterrole=cluster-admin --serviceaccount=kube-system:cyclonus
kubectl create sa cyclonus -n kube-system
kubectl create -f ./install-cyclonus.yml

# don't fail on errors, so we can dump the logs.
set +e

time kubectl wait --for=condition=complete --timeout=20m -n kube-system job.batch/cyclonus
rc=$?

# grab the job logs
LOG_FILE=$(mktemp)
kubectl logs -n kube-system job.batch/cyclonus > "$LOG_FILE"
cat "$LOG_FILE"

# retrieve the JUnit results file from the pod
RESULTS_DIR="cyclonus-results"
mkdir -p "$RESULTS_DIR"

# Get all pod names for the completed job
POD_NAMES=$(kubectl get pods -n kube-system -l job-name=cyclonus -o jsonpath='{.items[*].metadata.name}')

if [ -n "$POD_NAMES" ]; then
    RESULTS_COPIED=false
    for POD_NAME in $POD_NAMES; do
        echo "Attempting to retrieve JUnit results from pod: $POD_NAME"
        if kubectl cp -n kube-system "$POD_NAME":/results/cyclonus-results.xml "$RESULTS_DIR/cyclonus-results.xml" 2>/dev/null; then
            RESULTS_COPIED=true
            echo "Successfully copied results from pod: $POD_NAME"
            break
        else
            echo "Failed to copy JUnit results from pod: $POD_NAME"
        fi
    done

    # Check if the file was successfully copied and display its contents
    if [ "$RESULTS_COPIED" = true ] && [ -f "$RESULTS_DIR/cyclonus-results.xml" ]; then
        echo "JUnit results file retrieved successfully:"
        ls -la "$RESULTS_DIR/cyclonus-results.xml"
        echo "Contents preview:"
        head -20 "$RESULTS_DIR/cyclonus-results.xml"
    else
        echo "Warning: JUnit results file not found or could not be retrieved from any pod"
    fi
else
    echo "Warning: Could not find cyclonus pod to retrieve results"
fi

# Check for test failures by looking for percentage results less than 100%
# Only check lines after "Tag results:" header
# If any line contains a percentage that's not 100%, it's a failure
if sed -n '/Tag results:/,$p' "$LOG_FILE" | grep -E '\|.*[0-9]+ / [0-9]+ = [0-9]+%' | grep -v '100% ✅' | grep -E '[0-9]+%'; then
    echo "Test failures detected: some tests did not achieve 100% success"
    rc=1
fi
exit $rc
