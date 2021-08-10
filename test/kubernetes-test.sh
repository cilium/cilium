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
  --set image.tag=$1 \
  --set image.repository=quay.io/cilium/cilium-ci \
  --set image.useDigest=false \
  --set operator.image.repository=quay.io/cilium/operator \
  --set operator.image.tag=$1 \
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
  > cilium.yaml

kubectl apply -f cilium.yaml

while true; do
    result=$(kubectl -n kube-system get pods -l k8s-app=cilium | grep "Running" -c)
    echo "Running pods ${result}"
    if [ "${result}" == "2" ]; then

        echo "result match, continue with kubernetes"
        break
    fi
    sleep 1
done

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

GO_VERSION="1.16.7"
sudo rm -fr /usr/local/go
curl -LO https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
GO111MODULE=off make ginkgo
GO111MODULE=off make WHAT='test/e2e/e2e.test'

export KUBECTL_PATH=/usr/bin/kubectl
export KUBE_MASTER=192.168.36.11
export KUBE_MASTER_IP=192.168.36.11
export KUBE_MASTER_URL="https://192.168.36.11:6443"

echo "Running upstream services conformance tests"
${HOME}/go/bin/kubetest --provider=local --test \
  --test_args="--ginkgo.focus=Services.*\[Conformance\].* --e2e-verify-service-account=false --host ${KUBE_MASTER_URL}"

# We currently skip the following tests:
# should not allow access by TCP when a policy specifies only SCTP
# NetworkPolicy between server and client using SCTP
#  - Cilium does not support SCTP yet
# should allow egress access to server in CIDR block and
# should ensure an IP overlapping both IPBlock.CIDR and IPBlock.Except is allowed
# should enforce except clause while egress access to server in CIDR block
#  - TL;DR Cilium does not allow to specify pod CIDRs as part of the policy
#    because it conflicts with the pod's security identity.
#  - More info at https://github.com/cilium/cilium/issues/9209
#  - Cilium does not distinguish between UDP and TCP
# should enforce ingress policy allowing any port traffic to a server on a specific protocol
echo "Running upstream NetworkPolicy tests"
${HOME}/go/bin/kubetest --provider=local --test \
  --test_args="--ginkgo.focus=Net.*ol.* --e2e-verify-service-account=false --host ${KUBE_MASTER_URL} --ginkgo.skip=(should.not.allow.access.by.TCP.when.a.policy.specifies.only.SCTP)|(should.allow.egress.access.to.server.in.CIDR.block)|(should.enforce.except.clause.while.egress.access.to.server.in.CIDR.block)|(should.ensure.an.IP.overlapping.both.IPBlock.CIDR.and.IPBlock.Except.is.allowed)|(NetworkPolicy.between.server.and.client.using.SCTP)|(should.enforce.ingress.policy.allowing.any.port.traffic.to.a.server.on.a.specific.protocol)"
