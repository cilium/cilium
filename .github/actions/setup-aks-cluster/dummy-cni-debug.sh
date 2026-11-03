#!/usr/bin/env bash
# Called when a nodes-without-cilium wait fails, before "Clean up AKS" deletes the group.
set -uo pipefail

probe="$(dirname "$0")/dummy-cni-node-probe.sh"
selector=cilium.io/no-schedule=true
kc=(kubectl --request-timeout=30s)

"${kc[@]}" get nodes -l "${selector}" -o custom-columns='NAME:.metadata.name,CREATED:.metadata.creationTimestamp,BOOT:.status.nodeInfo.bootID,HEARTBEAT:.status.conditions[?(@.type=="Ready")].lastHeartbeatTime,READY:.status.conditions[?(@.type=="Ready")].message'
"${kc[@]}" -n kube-system get pods -l app=dummy-cni -o wide
"${kc[@]}" -n kube-system describe pods -l app=dummy-cni
"${kc[@]}" get events -A --field-selector involvedObject.kind=Node --sort-by=.lastTimestamp
"${kc[@]}" -n kube-system get events --sort-by=.lastTimestamp

"${kc[@]}" get nodes -l "${selector}" -o jsonpath='{range .items[*]}{.spec.providerID}{"\n"}{end}' |
while read -r provider; do
  id="${provider#azure://}"
  echo "=== ${id##*/virtualMachineScaleSets/}"
  timeout 30 az vmss get-instance-view --ids "${id}" \
    --query '{vm: statuses[].code, agent: vmAgent.statuses[].code}' -o json < /dev/null
  timeout 120 az vmss run-command invoke --ids "${id}" \
    --command-id RunShellScript --scripts @"${probe}" \
    --query 'value[0].message' -o tsv < /dev/null
done
