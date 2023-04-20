#!/usr/bin/env bash

have_kind() {
    [[ -n "$(command -v kind)" ]]
}

if ! have_kind; then
    echo "Please install kind first:"
    echo "  https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
fi

default_cluster_name="kind"
default_network="kind-cilium"

for cluster in "${@:-${default_cluster_name}}"; do
    kind delete cluster --name "$cluster"
done

docker network rm ${default_network}
