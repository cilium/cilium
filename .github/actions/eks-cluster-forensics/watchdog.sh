#!/usr/bin/env bash
# Collects the forensics once, after two polls in a row count fewer nodes than the baseline.

set -u

ARTIFACTS_SUFFIX="${1:?artifacts_suffix argument is required}"
NODE_BASELINE="${2:?node baseline path is required}"

baseline="$(jq '.items | length' "${NODE_BASELINE}" 2>/dev/null)"
if ! [ "${baseline:-0}" -gt 0 ] 2>/dev/null; then
  echo "No usable node baseline in ${NODE_BASELINE}, not watching"
  exit 0
fi
echo "Watching for fewer than ${baseline} nodes"

drops=0
while sleep 30; do
  if ! nodes="$(kubectl get nodes -o name --request-timeout=20s 2>/dev/null)"; then
    echo "$(date -u +%H:%M:%S) kubectl get nodes failed"
    continue
  fi
  live="$(grep -c . <<<"${nodes}")"
  if [ "${live}" -ge "${baseline}" ]; then
    drops=0
    continue
  fi
  drops=$((drops + 1))
  echo "$(date -u +%H:%M:%S) live=${live} baseline=${baseline}"
  if [ "${drops}" -ge 2 ]; then
    echo "Node count dropped from ${baseline} to ${live}"
    # --foreground keeps the collection in this process group, which the stop step kills.
    NODE_BASELINE="${NODE_BASELINE}" timeout --foreground 600 bash "$(dirname "$0")/action.sh" "${ARTIFACTS_SUFFIX}" node-loss
    exit 0
  fi
done
