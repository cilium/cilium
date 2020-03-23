#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"
source "${dir}/cert-gen-helpers.bash"

set -e

certs_dir="${dir}/certs"
mkdir -p "${certs_dir}"
cd "${certs_dir}"

master="k8s1"

if [ -n "${INSTALL}" ]; then
    download_to "${cache_dir}/cfssl" "cfssl_linux-amd64" \
        "https://pkg.cfssl.org/R1.2/cfssl_linux-amd64"
    chmod +x "${cache_dir}/cfssl/cfssl_linux-amd64"
    sudo mv "${cache_dir}/cfssl/cfssl_linux-amd64" /usr/bin/cfssl
    download_to "${cache_dir}/cfssl" "cfssljson_linux-amd64" \
        "https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64"
    chmod +x "${cache_dir}/cfssl/cfssljson_linux-amd64"
    sudo mv "${cache_dir}/cfssl/cfssljson_linux-amd64" /usr/bin/cfssljson
fi



log "Generating certificates..."

# Generate CA for k8s
generate_ca_certs k8s

# Generate k8s-api-server certs
generate_server_certs k8s k8s-api-server ${master}

# Generate k8s components certs so the component would be able to talk to the
# api-server
generate_k8s_component_certs k8s system:kube-controller-manager k8s-controller-manager
generate_k8s_component_certs k8s system:kube-scheduler k8s-scheduler

# Generate the certificates necessary for the service account credentials
# --service-account-private-key-file in the controller manager and
# --service-account-key-file in the kube api-server.
generate_k8s_component_certs k8s controller-manager-sa k8s-controller-manager-sa

# Generate kubelet certs so they are able to talk with api-server and have
# the correct permissions to manage its own node
# Leave the client cert generation to client node since master at this point
# has no idea how many workers there are.
generate_kubelet_client_certs k8s system:node:${master} k8s-kubelet-${master}
generate_k8s_component_certs k8s system:kube-proxy k8s-kube-proxy-${master}

# Generate kubelet client certificate so kube-apiserver can talk with kubelets
generate_k8s_component_certs k8s kubelet-api-server kubelet-api-server

# Generate CA for kubelets
generate_ca_certs kubelet

# Generate kubelet serving certificates to use to serve its endpoints
# Leave the client cert generation to client node.
generate_k8s_component_certs kubelet ${master} kubelet-kubelet-${master}

# Generate each components certs
generate_k8s_component_certs k8s system:kube-controller-manager k8s-controller-manager
generate_k8s_component_certs k8s system:kube-scheduler k8s-scheduler

# Generate kubectl and cilium certs as administrators of the cluster
# it's not the safest approach but it will be enough for testing
generate_kubectl_admin_certs k8s admin k8s-admin
generate_kubectl_admin_certs k8s cilium k8s-cilium
generate_kubectl_admin_certs k8s nginx k8s-nginx

# Generate CA for etcd
generate_ca_certs etcd

# Generate server certificates for etcd
generate_server_certs etcd etcd-server ${master}

# Generate client certificates for each client that talks with etcd
generate_etcd_client_certs etcd api-server etcd-k8s-api-server
generate_etcd_client_certs etcd cilium etcd-cilium

log "Generating certificates... DONE!"
