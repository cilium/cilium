#!/usr/bin/env bash
# Dumps the Azure view of the node network that an Azure support case needs.
set -uo pipefail

az_() {
  timeout 120 az "$@"
}

node_rg=$(az_ aks show --resource-group "${RESOURCE_GROUP}" --name "${CLUSTER_NAME}" \
  --query nodeResourceGroup -o tsv)
if [ -z "${node_rg}" ]; then
  echo "::warning title=Node underlay::cannot read the node resource group of ${CLUSTER_NAME}"
  exit 0
fi

mapfile -t vmss_names < <(az_ vmss list --resource-group "${node_rg}" --query '[].name' -o tsv)
for vmss in "${vmss_names[@]}"; do
  echo "::group::VMSS ${vmss}: instances and NICs"
  az_ vmss list-instances --resource-group "${node_rg}" --name "${vmss}" \
    --query '[].{instanceId:instanceId, computerName:osProfile.computerName, vmId:vmId, latestModelApplied:latestModelApplied, provisioningState:provisioningState}' \
    -o table
  az_ vmss nic list --resource-group "${node_rg}" --vmss-name "${vmss}" -o table
  echo "::endgroup::"
done

echo "::group::Subnets, route tables and NSGs of ${node_rg}"
az_ network vnet list --resource-group "${node_rg}" \
  --query '[].subnets[].{name:name, prefix:addressPrefix, routeTable:routeTable.id, nsg:networkSecurityGroup.id}' \
  -o table
mapfile -t route_tables < <(az_ network route-table list --resource-group "${node_rg}" --query '[].name' -o tsv)
for rt in "${route_tables[@]}"; do
  echo "Routes of ${rt}:"
  az_ network route-table route list --resource-group "${node_rg}" --route-table-name "${rt}" -o table
done
mapfile -t nsgs < <(az_ network nsg list --resource-group "${node_rg}" --query '[].name' -o tsv)
for nsg in "${nsgs[@]}"; do
  echo "Rules of ${nsg}:"
  az_ network nsg rule list --resource-group "${node_rg}" --nsg-name "${nsg}" -o table
done
echo "::endgroup::"

echo "::group::Activity log of ${node_rg}, last 3 hours"
az_ monitor activity-log list --resource-group "${node_rg}" --offset 3h --max-events 200 \
  --query '[].{time:eventTimestamp, operation:operationName.value, status:status.value, resource:resourceId}' \
  -o table
echo "::endgroup::"
exit 0
