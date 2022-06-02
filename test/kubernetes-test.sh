#!/bin/bash

# Comment for the '--set identityChangeGracePeriod="0s"'
# We need to change the identity as quickly as possible as there
# is a k8s upstream test that relies on the policy to be enforced
# once a new label is added to a pod. If we delay the identity change
# process the test will fail.

# We generate the helm chart template validating it against the associated Kubernetes
# Cluster.
helm template --validate install/kubernetes/cilium \
  --namespace=kube-system \
  --set image.tag=$2 \
  --set image.repository=$1/cilium-ci \
  --set image.useDigest=false \
  --set operator.image.repository=$1/operator \
  --set operator.image.tag=$2 \
  --set operator.image.suffix=-ci \
  --set operator.image.useDigest=false \
  --set debug.enabled=true \
  --set k8s.requireIPv4PodCIDR=true \
  --set pprof.enabled=true \
  --set logSystemLoad=true \
  --set bpf.preallocateMaps=true \
  --set etcd.leaseTTL=30s \
  --set ipv4.enabled=true \
  --set ipv6.enabled=true \
  --set identityChangeGracePeriod="0s" \
  --set kubeProxyReplacement=probe \
  --set cni.chainingMode=portmap \
  > cilium.yaml

kubectl apply -f cilium.yaml

runningPods="0"

pollCiliumPods () {
  until [ "${runningPods}" == "2" ]; do
    runningPods=$(kubectl -n kube-system get pods -l k8s-app=cilium | grep "Running" -c)
    echo "Running Pods ${runningPods}"
    sleep 1
  done
  echo "result match, continue with kubernetes"
}

export -f pollCiliumPods
timeout ${POLL_TIMEOUT_SECONDS} bash -c pollCiliumPods
unset pollCiliumPods

set -e

echo "Installing kubetest manually"

mkdir -p ${HOME}/go/src/k8s.io
cd ${HOME}/go/src/k8s.io
test -d test-infra && rm -rfv test-infra
# Last commit before vendor directory was removed
# why? see https://github.com/kubernetes/test-infra/issues/14165#issuecomment-528620301
git clone https://github.com/kubernetes/test-infra.git
cd test-infra
git reset --hard dbc2ac103595c2348322d1bac7e4743b96fca225
GO111MODULE=off go install k8s.io/test-infra/kubetest

echo "Installing kubernetes"
KUBERNETES_VERSION=$(kubectl version -o json | jq -r '.serverVersion | .gitVersion')

mkdir -p ${HOME}/go/src/k8s.io/
cd ${HOME}/go/src/k8s.io/
test -d kubernetes && rm -rfv kubernetes
git clone https://github.com/kubernetes/kubernetes.git -b ${KUBERNETES_VERSION} --depth 1
cd kubernetes

GO_VERSION="1.18.3"
sudo rm -fr /usr/local/go
curl -LO https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
GO111MODULE=off make ginkgo
GO111MODULE=off make WHAT='test/e2e/e2e.test'

export KUBECTL_PATH=/usr/bin/kubectl
export KUBE_MASTER=192.168.56.11
export KUBE_MASTER_IP=192.168.56.11
export KUBE_MASTER_URL="https://192.168.56.11:6443"

echo "Running upstream services conformance tests"
${HOME}/go/bin/kubetest --provider=local --test \
  --test_args="--ginkgo.focus=HostPort.*\[Conformance\].* --e2e-verify-service-account=false --host ${KUBE_MASTER_URL}"
${HOME}/go/bin/kubetest --provider=local --test \
  --test_args="--ginkgo.focus=Services.*\[Conformance\].* --e2e-verify-service-account=false --host ${KUBE_MASTER_URL}"

# We currently skip the following tests:
# - NetworkPolicy between server and client using SCTP
# - should not allow access by TCP when a policy specifies only SCTP
# - should properly isolate pods that are selected by a policy allowing SCTP, even if the plugin doesn't supportSCTP [Feature:NetworkPolicy]
#   - Cilium does not support SCTP yet
#   - More info at https://github.com/cilium/cilium/issues/5719
# - should allow egress access to server in CIDR block and
# - should ensure an IP overlapping both IPBlock.CIDR and IPBlock.Except is allowed and
# - should enforce except clause while egress access to server in CIDR block
#   - TL;DR Cilium does not allow to specify pod CIDRs as part of the policy
#     because it conflicts with the pod's security identity.
#   - More info at https://github.com/cilium/cilium/issues/9209
#   - Cilium does not distinguish between UDP and TCP
#   - More info at https://github.com/cilium/cilium/issues/9207
# - should enforce ingress policy allowing any port traffic to a server on a specific protocol
# - should respect internalTrafficPolicy=Local Pod to Pod [Feature:ServiceInternalTrafficPolicy]
#   - Cilium does not support internalTrafficPolicy as Local Redirect Policy allows user to enable node-local redirection.
#   - More info at https://github.com/cilium/cilium/issues/17796
echo "Running upstream NetworkPolicy tests"
${HOME}/go/bin/kubetest --provider=local --test \
  --test_args="--ginkgo.focus=Net.*ol.* --e2e-verify-service-account=false --host ${KUBE_MASTER_URL} --ginkgo.skip=(should.not.allow.access.by.TCP.when.a.policy.specifies.only.SCTP)|(should.allow.egress.access.to.server.in.CIDR.block)|(should.enforce.except.clause.while.egress.access.to.server.in.CIDR.block)|(should.ensure.an.IP.overlapping.both.IPBlock.CIDR.and.IPBlock.Except.is.allowed)|(NetworkPolicy.between.server.and.client.using.SCTP)|(should.enforce.ingress.policy.allowing.any.port.traffic.to.a.server.on.a.specific.protocol)|(should.respect.internalTrafficPolicy.Local.Pod.*to.Pod.*.Feature.ServiceInternalTrafficPolicy.)|(should.properly.isolate.pods.that.are.selected.by.a.policy.allowing.SCTP..even.if.the.plugin.doesn.t.support.SCTP..Feature.NetworkPolicy.)"
