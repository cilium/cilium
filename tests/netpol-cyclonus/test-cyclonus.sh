#!/usr/bin/env bash

set -eo pipefail
set -xv

# set up cyclonus
kubectl create clusterrolebinding cyclonus --clusterrole=cluster-admin --serviceaccount=kube-system:cyclonus
kubectl create sa cyclonus -n kube-system
kubectl create -f ./install-cyclonus.yml

time kubectl wait --for=condition=complete --timeout=240m -n kube-system job.batch/cyclonus

# grab the job logs
LOG_FILE=$(mktemp)
kubectl logs -n kube-system job.batch/cyclonus > "$LOG_FILE"
cat "$LOG_FILE"

# if 'failure' is in the logs, fail; otherwise succeed
rc=0
cat "$LOG_FILE" | grep "failure" > /dev/null 2>&1 || rc=$?
if [ $rc -eq 0 ]; then
    exit 1
fi
