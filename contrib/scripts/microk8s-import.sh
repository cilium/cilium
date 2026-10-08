#!/usr/bin/env bash

set -e
set -o pipefail

CONTAINER_ENGINE=${CONTAINER_ENGINE:-"docker"}
TARGET_IMAGE=${1:-""}
MICROK8S_CTR="microk8s.ctr"

main()
{
    "$CONTAINER_ENGINE" image inspect "$TARGET_IMAGE" >/dev/null
    LOCAL_IMAGE=$(mktemp "$(echo $TARGET_IMAGE | sed 's/\//-/g').XXXXXX")
    trap "rm -f $LOCAL_IMAGE" EXIT

    "$CONTAINER_ENGINE" image save "$TARGET_IMAGE" -o "$LOCAL_IMAGE"
    "$MICROK8S_CTR" image import "$LOCAL_IMAGE"

    echo "Update image tag like this when ready:"
    echo "    microk8s.kubectl -n kube-system set image ds/cilium cilium-agent=$TARGET_IMAGE"
    echo "Or, redeploy the Cilium pods:"
    echo "    microk8s.kubectl -n kube-system delete pod -l k8s-app=cilium"
}

main "$@"
