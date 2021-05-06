#!/bin/sh

set -x
set -e

cilium install --cluster-name "${CLUSTER_NAME}" --wait=false --config monitor-aggregation=none
