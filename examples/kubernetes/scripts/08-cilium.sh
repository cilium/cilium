#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

kubectl create -f "${dir}/../network-policy/" || true

kubectl get networkpolicy

# TODO remove sudo once socket permissions are set with cilium group
cat <<EOF | sudo cilium -D policy import -
{
        "name": "io.cilium",
        "rules": [{
                "coverage": ["reserved:world"],
                "allow": ["k8s:io.cilium.k8s.k8s-app=kube-dns"]
        }]
}
EOF

sudo cilium policy get io.cilium
