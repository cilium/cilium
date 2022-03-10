#!/bin/sh

set -x
set -e

# Install Cilium
cilium install \
  --disable-check=az-binary \
  --helm-set=azure.subscriptionID="${AZURE_SUBSCRIPTION_ID}" \
  --helm-set=azure.resourceGroup="${AZURE_NODE_RESOURCE_GROUP}" \
  --helm-set=azure.tenantID="${AZURE_TENANT_ID}" \
  --helm-set=azure.clientID="${AZURE_CLIENT_ID}" \
  --helm-set=azure.clientSecret="${AZURE_CLIENT_SECRET}" \
  --wait=false \
  --helm-set=bpf.monitorAggregation=none
