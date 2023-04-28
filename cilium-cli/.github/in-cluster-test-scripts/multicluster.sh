#!/bin/sh

set -x
set -e

# Set up contexts
CONTEXT1=$(kubectl config view | grep "${CLUSTER_NAME_1}" | head -1 | awk '{print $2}')
CONTEXT2=$(kubectl config view | grep "${CLUSTER_NAME_2}" | head -1 | awk '{print $2}')

# Install Cilium in cluster1
# We can't get rid of --cluster-name until we fix https://github.com/cilium/cilium-cli/issues/1347.
cilium install \
  --version "${CILIUM_VERSION}" \
  --context "${CONTEXT1}" \
  --helm-set loadBalancer.l7.backend=envoy \
  --helm-set tls.secretsBackend=k8s \
  --cluster-name "${CLUSTER_NAME_1}" \
  --helm-set cluster.id=1 \
  --helm-set bpf.monitorAggregation=none \
  --helm-set ipv4NativeRoutingCIDR=10.0.0.0/9

# Copy the CA cert from cluster1 to cluster2
kubectl --context ${CONTEXT1} get secrets -n kube-system cilium-ca -oyaml \
  | kubectl --context ${CONTEXT2} apply -f -

# This seeds all CAs in cluster2 due to logic in the helm chart found here, e.g. for Hubble
# https://github.com/cilium/cilium/blob/8b6aa6eda91927275ae722ac020deeb5a9ce479d/install/kubernetes/cilium/templates/hubble/tls-helm/_helpers.tpl#L24-L33

# Install Cilium in cluster2
cilium install \
  --version "${CILIUM_VERSION}" \
  --context "${CONTEXT2}" \
  --helm-set loadBalancer.l7.backend=envoy \
  --helm-set tls.secretsBackend=k8s \
  --cluster-name "${CLUSTER_NAME_2}" \
  --helm-set cluster.id=2 \
  --helm-set bpf.monitorAggregation=none \
  --helm-set ipv4NativeRoutingCIDR=10.0.0.0/9

# Enable Relay
cilium --context "${CONTEXT1}" hubble enable
cilium --context "${CONTEXT2}" hubble enable --relay=false

# Wait for cilium and hubble relay to be ready
# NB: necessary to work against occassional flakes due to https://github.com/cilium/cilium-cli/issues/918
cilium --context "${CONTEXT1}" status --wait
cilium --context "${CONTEXT2}" status --wait

# Enable cluster mesh
cilium --context "${CONTEXT1}" clustermesh enable --service-type=LoadBalancer
cilium --context "${CONTEXT2}" clustermesh enable --service-type=LoadBalancer

# Copy the clustermesh secrets
# TODO(ajs): Patch the connect command to expect the Helm secret name
echo "CILIUM_CLI_MODE: $CILIUM_CLI_MODE"
if [ "$CILIUM_CLI_MODE" == "helm" ]; then
  kubectl get secrets --context ${CONTEXT1} \
    -n kube-system clustermesh-apiserver-remote-cert -oyaml \
    | sed 's/name: .*/name: clustermesh-apiserver-client-cert/' \
    | kubectl apply --context ${CONTEXT1} -f -
  kubectl get secrets --context ${CONTEXT2} \
    -n kube-system clustermesh-apiserver-remote-cert -oyaml \
    | sed 's/name: .*/name: clustermesh-apiserver-client-cert/' \
    | kubectl apply --context ${CONTEXT2} -f -
fi

# Wait for cluster mesh status to be ready
cilium --context "${CONTEXT1}" clustermesh status --wait
cilium --context "${CONTEXT2}" clustermesh status --wait

# Connect clusters
cilium --context "${CONTEXT1}" clustermesh connect --destination-context "${CONTEXT2}"

# Wait for cluster mesh status to be ready
cilium --context "${CONTEXT1}" clustermesh status --wait
cilium --context "${CONTEXT2}" clustermesh status --wait

# Port forward Relay
cilium --context "${CONTEXT1}" hubble port-forward&
sleep 10s
[[ $(pgrep -f "cilium.*hubble.*port-forward|kubectl.*port-forward.*hubble-relay" | wc -l) == 2 ]]

# Run connectivity test
cilium --context "${CONTEXT1}" connectivity test --debug --multi-cluster "${CONTEXT2}" --test '!/*-deny,!/pod-to-.*-nodeport' \
  --all-flows --collect-sysdump-on-failure --external-target google.com
