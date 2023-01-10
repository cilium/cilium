#!/usr/bin/env bash

have_kind() {
    [[ -n "$(command -v kind)" ]]
}

if ! have_kind; then
    echo "Please install kind first:"
    echo "  https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
fi

kind delete clusters kind && \
docker kill kind-registry && \
docker rm kind-registry
