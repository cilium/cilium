#!/usr/bin/env bash
# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

# Ginkgo Cilium Test
#
# $1 - integration
# $2 - cilium image
# $3 - focus string
# $4 - additional ginkgo arguments
gct()
{
    if [ $# -lt 2 ]; then
        >&2 echo "usage: gct <INTEGRATION> <IMAGE> [FOCUS] [GINKGO-ARGS]"
        return 1
    fi
    for dep in jq kubectl ginkgo; do
        if ! which $dep >/dev/null; then
            >&2 echo "This script requires '$dep'"
            return 1
        fi
    done
    (
        set -e
        set -o pipefail

        if [ ! -e $PWD/test_suite_test.go ]; then
            CILIUM_DIR="${CILIUM_DIR:-"$GOPATH/src/github.com/cilium/cilium/test"}"
            >&2 echo "Switching to $CILIUM_DIR..."
            cd "$CILIUM_DIR"
        fi

        CNI_INTEGRATION="$1"; shift
        CILIUM_IMAGE="$(echo "$1" | sed 's/^\(.*\):[^:]*$/\1/')"
        CILIUM_TAG="$(echo "$1" | sed 's/^.*:\([^:]*\)$/\1/')"
        shift
        FOCUS=""
        if [ $# -ge 1 ]; then
            FOCUS="--focus=$1"
        fi
        shift
        CNI_INTEGRATION="$CNI_INTEGRATION" \
        CILIUM_IMAGE="$CILIUM_IMAGE" \
        CILIUM_TAG="$CILIUM_TAG" \
        CILIUM_OPERATOR_IMAGE="${CILIUM_OPERATOR_IMAGE:-"quay.io/cilium/operator"}" \
        CILIUM_OPERATOR_TAG="${CILIUM_OPERATOR_TAG:-"latest"}" \
        HUBBLE_RELAY_IMAGE="${HUBBLE_RELAY_IMAGE:-"quay.io/cilium/hubble-relay"}" \
        HUBBLE_RELAY_IMAGE_TAG="${HUBBLE_RELAY_IMAGE_TAG:-"latest"}" \
        K8S_VERSION="$(kubectl version -o json |  jq -r '(.serverVersion.major + "." + (.serverVersion.minor | scan("[0-9]+")))' | sed 's/"//g')" \
        INTEGRATION_TESTS=true ginkgo -v "$FOCUS" -- \
            -cilium.provision=false \
            -cilium.kubeconfig=$HOME/.kube/config \
            -cilium.passCLIEnvironment=true \
            -cilium.testScope=k8s \
            -cilium.holdEnvironment=true \
            -cilium.skipLogs=true \
            "$@"
    )
}

# Ginkgo for eKS
gks()
{
    if [ $# -lt 2 ]; then
        >&2 echo "usage: gks <IMAGE> [FOCUS] [ARGS]"
        return 1
    fi
    IMAGE="$1"; shift
    FOCUS="$1"; shift
    gct "eks" "$IMAGE" "$FOCUS" "$@"
}


# GinKgo for Gke
gkg()
{
    if [ $# -lt 2 ]; then
        >&2 echo "usage: gkg <IMAGE> [FOCUS] [ARGS]"
        return 1
    fi
    IMAGE="$1"; shift
    FOCUS="$1"; shift
    gct "gke" "$IMAGE" "$FOCUS" "$@"
}

# GinKgo for Kind
gkk()
{
    if [ $# -lt 2 ]; then
        >&2 echo "usage: gkk <IMAGE> [FOCUS] [ARGS]"
        return 1
    fi
    IMAGE="$1"; shift
    FOCUS="$1"; shift
    kind load docker-image "$IMAGE" || return 1
    gct "kind" "$IMAGE" "$FOCUS" "$@"
}

# GinKgo for Microk8s
gkm()
{
    if [ $# -lt 1 ]; then
        >&2 echo "usage: gkm [FOCUS] [ARGS]"
        return 1
    fi
    IMAGE="${CILIUM_IMAGE:-"localhost:32000/cilium/cilium:local"}"
    FOCUS="$1"; shift
    gct "microk8s" "$IMAGE" "$FOCUS" "$@"
}
