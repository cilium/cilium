#!/usr/bin/env bash

have_kind() {
    [[ -n "$(command -v kind)" ]]
}

if ! have_kind; then
    echo "Please install kind first:"
    echo "  https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
fi

if [ "${1:-}" != "--keep-registry" ]; then
    docker kill kind-registry && \
        docker rm kind-registry
fi

kind delete clusters kind && \
    docker network rm kind-cilium

secondary_network="kind-cilium-secondary"
if docker network inspect "${secondary_network}" >/dev/null 2>&1; then
  docker network rm ${secondary_network}
fi
