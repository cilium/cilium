#!/usr/bin/env bash
# Saves the cluster's API server lines that show stuck requests or etcd transport churn, and prints them.
set -uo pipefail

# All legs share one 60 requests per minute Logging read quota.
sleep $(( RANDOM % 30 ))

since=$(date -u -d '-3 hours' +%Y-%m-%dT%H:%M:%SZ)
filter="resource.type=\"k8s_control_plane_component\"
AND log_id(\"container.googleapis.com/apiserver\")
AND resource.labels.cluster_name=\"${CLUSTER}\"
AND resource.labels.location=\"${ZONE}\"
AND timestamp>=\"${since}\"
AND (severity>=WARNING OR \"addrConn.createTransport\" OR \"etcd-client\" OR \"unary invoker\"
  OR \"post-timeout activity\" OR \"context deadline exceeded\" OR \"Trace[\")"

if ! timeout 180 gcloud logging read "${filter}" --order=asc --limit=3000 --format=json > gke-apiserver-log.json; then
  echo "::warning title=GKE API server log::cannot read the API server log of ${CLUSTER}"
  exit 0
fi

jq -r '.[] | [.timestamp, .receiveTimestamp, .severity, (.sourceLocation.file // "-"),
  (.textPayload // .jsonPayload.message // (.jsonPayload | tojson)) | tostring | gsub("[\t\n]"; " ")] | @tsv' \
  gke-apiserver-log.json > gke-apiserver-log.tsv

echo "::group::API server log of ${CLUSTER}: $(wc -l < gke-apiserver-log.tsv) lines since ${since}"
for pattern in "addrConn.createTransport" "etcd-client" "unary invoker" "post-timeout activity" "context deadline exceeded" "Trace["; do
  printf '%6d %s\n' "$(grep -ciF -- "${pattern}" gke-apiserver-log.tsv)" "${pattern}"
done
grep -iE "addrConn.createTransport|unary invoker|post-timeout activity|context deadline exceeded" gke-apiserver-log.tsv | head -200
echo "::endgroup::"
exit 0
