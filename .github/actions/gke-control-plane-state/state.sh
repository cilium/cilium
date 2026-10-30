#!/usr/bin/env bash
# Prints the cluster's status, its operations and GKE's audit log since its creation, to show control-plane changes.
set -uo pipefail

gc() {
  timeout 90 gcloud "$@"
}

echo "::group::Cluster ${CLUSTER} in ${ZONE}"
describe=$(gc container clusters describe "${CLUSTER}" --zone "${ZONE}" --format=json) || {
  echo "::warning title=GKE control plane::cannot describe ${CLUSTER} in ${ZONE}"
  echo "::endgroup::"
  exit 0
}
jq -r '"status: \(.status)", "statusMessage: \(.statusMessage // "")", "createTime: \(.createTime)",
  "currentMasterVersion: \(.currentMasterVersion)", "conditions: \(.conditions // [] | tojson)"' <<< "${describe}"
status=$(jq -r '.status' <<< "${describe}")
since=$(jq -r '.createTime' <<< "${describe}")
if [[ "${status}" != "RUNNING" ]]; then
  echo "::warning title=GKE control plane::cluster ${CLUSTER} is ${status} after the failure: $(jq -r '.statusMessage // ""' <<< "${describe}")"
fi
echo "::endgroup::"

echo "::group::Operations on ${CLUSTER}"
ops=$(gc container operations list --zone "${ZONE}" --filter="targetLink~/clusters/${CLUSTER}\$" --sort-by=startTime --format=json) || ops='[]'
jq -r '.[] | "\(.startTime) \(.endTime // "-") \(.operationType) \(.status) \(.statusMessage // "")"' <<< "${ops}"
jq -r '.[] | select(.operationType != "CREATE_CLUSTER") | "::warning title=GKE control plane::\(.operationType) on \(env.CLUSTER) from \(.startTime) to \(.endTime // "now"), \(.status)"' <<< "${ops}"
echo "::endgroup::"

echo "::group::GKE audit log for ${CLUSTER} since ${since}"
gc logging read "resource.type=\"gke_cluster\" AND resource.labels.cluster_name=\"${CLUSTER}\" AND resource.labels.location=\"${ZONE}\" AND timestamp>=\"${since}\"" \
  --order=asc --limit=200 --format='table(timestamp,severity,protoPayload.methodName,protoPayload.status.message)' \
  || echo "::warning title=GKE control plane::cannot read the GKE audit log for ${CLUSTER}"
echo "::endgroup::"
exit 0
