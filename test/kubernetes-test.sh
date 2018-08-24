#!/bin/bash

k8sVersionJson=$(kubectl version -o json)

KUBERNETES_MAJOR_MINOR_VER="$(echo "${k8sVersionJson}" | jq -r '.serverVersion | .major').$(echo "${k8sVersionJson}" | jq -r '.serverVersion | .minor')"

k8sDescriptorsPath="./examples/kubernetes/${KUBERNETES_MAJOR_MINOR_VER}"
k8sManifestsPath="./test/k8sT/manifests"
etcdOperatorDir="./examples/kubernetes/addons/etcd-operator"

"${etcdOperatorDir}/tls/certs/gen-cert.sh" "cluster.local"
"${etcdOperatorDir}/tls/deploy-certs.sh"
kubectl apply --filename="${etcdOperatorDir}/00-crd-etcd.yaml"
kubectl apply --filename="${etcdOperatorDir}/cilium-etcd-cluster.yaml"
kubectl apply --filename="${etcdOperatorDir}/cilium-etcd-sa.yaml"
kubectl apply --filename="${etcdOperatorDir}/cluster-role-binding-template.yaml"
kubectl apply --filename="${etcdOperatorDir}/cluster-role-template.yaml"
kubectl apply --filename="${etcdOperatorDir}/deployment.yaml"

kubectl apply --filename="${k8sDescriptorsPath}/cilium-sa.yaml"
kubectl apply --filename="${k8sDescriptorsPath}/cilium-rbac.yaml"
kubectl patch --filename="${k8sDescriptorsPath}/cilium-cm.yaml" --patch "$(cat ${k8sManifestsPath}/cilium-cm-patch.yaml)" --local -o yaml | kubectl apply -f -
kubectl patch --filename="${k8sDescriptorsPath}/cilium-ds.yaml" --patch "$(cat ${k8sManifestsPath}/cilium-ds-patch.yaml)" --local -o yaml | kubectl apply -f -

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
echo "Installing kubernetes"

KUBERNETES_VERSION=$(kubectl version -o json | jq -r '.serverVersion | .gitVersion')

mkdir -p $HOME/go/src/github.com/kubernetes/
cd $HOME/go/src/github.com/kubernetes/
test -d kubernetes && rm -rfv kubernetes
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
