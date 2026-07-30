#!/usr/bin/env bash

set -eo pipefail
set -xv

# set up cyclonus
kubectl create clusterrolebinding cyclonus --clusterrole=cluster-admin --serviceaccount=kube-system:cyclonus
kubectl create sa cyclonus -n kube-system
kubectl create -f ./install-cyclonus.yml

# don't fail on errors, so we can dump the logs.
set +e

time kubectl wait --for=condition=complete --timeout=60m -n kube-system job.batch/cyclonus
rc=$?

# Dump the logs of every pod that ever backed the job, current and previous
# containers alike. A single "kubectl logs job.batch/cyclonus" only resolves to
# one pod, so when the original runner crashes and the Job controller starts a
# replacement, the crashed pod's output (e.g. a Go panic stack) is lost. Iterate
# explicitly so a crash is always diagnosable.
for pod in $(kubectl get pods -n kube-system -l job-name=cyclonus -o jsonpath='{.items[*].metadata.name}'); do
    echo "===== logs for pod $pod ====="
    kubectl logs -n kube-system "$pod" || true
    echo "===== previous-container logs for pod $pod (if any) ====="
    kubectl logs -n kube-system "$pod" --previous 2>/dev/null || true
done

# grab the job logs
RAW_LOG_FILE=$(mktemp)
kubectl logs -n kube-system job.batch/cyclonus > "$RAW_LOG_FILE"
cat "$RAW_LOG_FILE"

# The cyclonus container prints its JUnit file between these two sentinels, see
# install-cyclonus.yml. Reading it out of the log is the only way to get it: the
# file sits on an emptyDir, kubectl cp implements copy-from-pod by exec'ing tar
# inside the container, and exec is refused on a pod that already reached
# Succeeded or Failed, which is exactly the state the job is in by the time we
# get here. So there is no window in which a copy could have worked.
BEGIN_MARKER="===== BEGIN CYCLONUS JUNIT XML ====="
END_MARKER="===== END CYCLONUS JUNIT XML ====="

# Keep the XML out of the log used for the pass/fail check below, so that no
# amount of XML text can ever look like a tag summary row.
LOG_FILE=$(mktemp)
awk -v b="$BEGIN_MARKER" '$0 == b { exit } { print }' "$RAW_LOG_FILE" > "$LOG_FILE"

# retrieve the JUnit results file out of the pod logs
RESULTS_DIR="cyclonus-results"
mkdir -p "$RESULTS_DIR"
RESULTS_FILE="$RESULTS_DIR/cyclonus-results.xml"

# Get the pod name for the completed job
POD_NAME=$(kubectl get pods -n kube-system -l job-name=cyclonus -o jsonpath='{.items[0].metadata.name}')

if [ -n "$POD_NAMES" ]; then
    for POD_NAME in $POD_NAMES; do
        echo "Extracting JUnit results from the log of pod: $POD_NAME"
        kubectl logs -n kube-system "$POD_NAME" |
            awk -v b="$BEGIN_MARKER" -v e="$END_MARKER" \
                '$0 == b { flag = 1; next } $0 == e { flag = 0 } flag' > "$RESULTS_FILE"
        # A pod that crashed before writing the file leaves us an empty or a
        # truncated block, so fall through to the pod that replaced it.
        if grep -q '</testsuite>' "$RESULTS_FILE"; then
            echo "JUnit results file retrieved successfully from pod: $POD_NAME"
            ls -la "$RESULTS_FILE"
            echo "Contents preview:"
            head -20 "$RESULTS_FILE"
            break
        fi
        echo "No usable JUnit results in the log of pod: $POD_NAME"
        rm -f "$RESULTS_FILE"
    done

    if [ ! -f "$RESULTS_FILE" ]; then
        echo "Warning: no pod backing the job logged a usable JUnit results file"
    fi
else
    echo "Warning: Could not find cyclonus pod to retrieve results"
fi

# if 'failure' is in the logs, fail; otherwise succeed
cat "$LOG_FILE" | grep "failure" > /dev/null 2>&1 && rc=1
exit $rc
