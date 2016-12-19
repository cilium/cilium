#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

kubectl label node worker0 --overwrite with-network-plugin=cilium
kubectl label node worker1 --overwrite with-network-plugin=cilium
kubectl label node worker2 --overwrite with-network-plugin=cilium

kubectl create -f https://raw.githubusercontent.com/cilium/cilium/gce-example/examples/gce/deployments/cilium-ds.yaml

kubectl get daemonset cilium-net-controller

kubectl delete -f https://raw.githubusercontent.com/cilium/cilium/gce-example/examples/gce/network-policy/dashboard-policy.json
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/gce-example/examples/gce/network-policy/guestbook-policy-redis.json
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/gce-example/examples/gce/network-policy/guestbook-policy-web.json
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/gce-example/examples/gce/network-policy/kubedns-policy.json

kubectl create -f https://raw.githubusercontent.com/cilium/cilium/master/examples/kubernetes/network-policy/guestbook-policy-redis.json
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/master/examples/kubernetes/network-policy/guestbook-policy-web.json
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/master/examples/kubernetes/network-policy/kubedns-policy.json

kubectl delete -f https://raw.githubusercontent.com/cilium/cilium/master/examples/kubernetes/network-policy/guestbook-policy-web.json
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/gce-example/examples/gce/network-policy/guestbook-policy-web.json

kubectl get networkpolicy

while [[ "$(kubectl get pods | grep cilium | grep Running -c)" -ne "3" ]] ; do
    echo "Waiting for all cilium pods to be Running..."
    sleep 2s
done
sleep 5s

while read line; do
cat <<EOF | kubectl exec -i ${line} -- cilium -D policy import -
{
        "name": "root",
        "rules": [{
                "coverage": ["reserved:world"],
                "allow": ["k8s:root.io.cilium.k8s.k8s-app=kube-dns", "k8s:root.io.cilium.k8s.k8s-app=kubernetes-dashboard"]
        }]
}
EOF
done < <(kubectl get pods --output=jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')

random_pod=$(kubectl get pods --output=jsonpath='{.items[0].metadata.name}{"\n"}')

kubectl exec ${random_pod} cilium policy get io.cilium
