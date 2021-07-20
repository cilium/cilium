#!/bin/sh

set -x
set -e

# Install Cilium
cilium install \
  --disable-check=az-binary \
  --azure-subscription-id "${AZURE_SUBSCRIPTION_ID}" \
  --azure-node-resource-group "${AZURE_NODE_RESOURCE_GROUP}" \
  --azure-tenant-id "${AZURE_TENANT_ID}" \
  --azure-client-id "${AZURE_CLIENT_ID}" \
  --azure-client-secret "${AZURE_CLIENT_SECRET}" \
  --wait=false \
  --config monitor-aggregation=none
