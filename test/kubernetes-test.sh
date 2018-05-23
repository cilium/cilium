#!/bin/bash

/usr/bin/kubectl apply -f /vagrant/k8sT/manifests/cilium_ds.yaml

while true; do
    result=$(kubectl -n kube-system get pods -l k8s-app=cilium | grep "Running" -c)
    echo "Running pods ${result}"
    if [ "${result}" == "2" ]; then

        echo "result match, continue with kubernetes"
        break
    fi
    sleep 1
done

KUBERNETES_VERSION=$(kubectl version -o json | jq -r '.serverVersion | .gitVersion')

set -e
echo "Installing kubernetes"

mkdir -p $HOME/go/src/github.com/kubernetes/
cd $HOME/go/src/github.com/kubernetes/
git clone https://github.com/kubernetes/kubernetes.git -b ${KUBERNETES_VERSION} --depth 1
cd kubernetes
make ginkgo
make WHAT='test/e2e/e2e.test'

export KUBERNETES_PROVIDER=vagrant
export KUBECTL_PATH=/usr/bin/kubectl
export KUBE_MASTER=192.168.36.11
export KUBE_MASTER_IP=192.168.36.11
export KUBE_MASTER_URL="https://192.168.36.11:6443"

go run hack/e2e.go --test --test_args="--ginkgo.focus=NetworkPolicy --e2e-verify-service-account=false --host ${KUBE_MASTER_URL} --ginkgo.skip=name ports"
