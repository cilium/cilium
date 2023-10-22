#!/usr/bin/env bash

have_kind() {
    [[ -n "$(command -v kind)" ]]
}

if ! have_kind; then
    echo "Please install kind first:"
    echo "  https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
    exit 1
fi

default_cluster_name="kind"
default_network="kind-cilium"
secondary_network="${default_network}-secondary"

for cluster in "${@:-${default_cluster_name}}"; do
    kind delete cluster --name "$cluster"
done

docker network rm ${default_network}
if docker network inspect "${secondary_network}" >/dev/null 2>&1; then
    docker network rm ${secondary_network}
fi
