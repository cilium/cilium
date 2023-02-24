#!/bin/sh

set -x
set -e

# Install Cilium
cilium install \
  --version "${CILIUM_VERSION}" \
  --disable-check=az-binary \
  --datapath-mode=azure \
  --azure-subscription-id "${AZURE_SUBSCRIPTION_ID}" \
  --azure-node-resource-group "${AZURE_NODE_RESOURCE_GROUP}" \
  --azure-tenant-id "${AZURE_TENANT_ID}" \
  --azure-client-id "${AZURE_CLIENT_ID}" \
  --azure-client-secret "${AZURE_CLIENT_SECRET}" \
  --wait=false \
  --helm-set loadBalancer.l7.backend=envoy \
  --helm-set tls.secretsBackend=k8s \
  --config monitor-aggregation=none
