#!/usr/bin/env bash
set -xeo pipefail

if [ -z "${EGW_IMAGE_TAG}" ]; then
    echo "FATAL: \$EGW_IMAGE_TAG must be defined"
    exit 1
fi

fill_template() {
    envsubst < "$1" | tee > "${1//\.tmpl/}"
}

get_node_internal_ip() {
    kubectl get node -l "$1" -ojsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}' | \
        awk '{print $1}'  # Ignore the IPv6 address in dual stack clusters
}

if [ "$1" != "baseline" ]; then
    external_target_ip=$(get_node_internal_ip "role.scaffolding/egw-node=true")
    export EGW_ALLOWED_CIDR="${external_target_ip}/32"
else
    export EGW_ALLOWED_CIDR="0.0.0.0/0"
fi

egw_node_ip=$(get_node_internal_ip "cilium.io/no-schedule=true")
export EGW_EXTERNAL_TARGET_CIDR="${egw_node_ip}/32"
export EGW_EXTERNAL_TARGET_ADDR="${egw_node_ip}"

for template in ./manifests/*.tmpl.yaml; do
    fill_template "$template"
done

if [ "$1" != "baseline" ]; then
    kubectl apply -f ./manifests/egw-policy.yaml
else
    kubectl delete --ignore-not-found \
        ciliumegressgatewaypolicies.cilium.io/egw-scale-test-route-external
fi
