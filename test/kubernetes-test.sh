#!/bin/bash

helm template install/kubernetes/cilium \
  --namespace=kube-system \
  --set global.registry=k8s1:5000/cilium \
  --set global.tag=latest \
  --set agent.image=cilium-dev \
  --set operator.image=operator \
  --set global.debug.enabled=true \
  --set global.k8s.requireIPv4PodCIDR=true \
  --set global.pprof.enabled=true \
  --set global.logSystemLoad=true \
  --set global.bpf.preallocateMaps=true \
  --set global.etcd.leaseTTL=30s \
  --set global.ipv4.enabled=true \
  --set global.ipv6.enabled=true \
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

# Kubernetes is only compiling with golang 1.13.4 for versions >=1.17
sudo rm -fr /usr/local/go
curl https://dl.google.com/go/go1.13.6.linux-amd64.tar.gz > go1.13.6.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.13.6.linux-amd64.tar.gz
GO111MODULE=off make ginkgo
GO111MODULE=off make WHAT='test/e2e/e2e.test'

export KUBERNETES_PROVIDER=local
export KUBECTL_PATH=/usr/bin/kubectl
export KUBE_MASTER=192.168.36.11
export KUBE_MASTER_IP=192.168.36.11
export KUBE_MASTER_URL="https://192.168.36.11:6443"

${HOME}/go/bin/kubetest --test --test_args="--ginkgo.focus=NetworkPolicy --e2e-verify-service-account=false --host ${KUBE_MASTER_URL} --ginkgo.skip=(should.allow.egress.access.to.server.in.CIDR.block)|(should.allow.ingress.access.from.updated.pod)|(named.port)"
