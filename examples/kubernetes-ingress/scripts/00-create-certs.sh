#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

certs_dir="${dir}/certs"
mkdir -p "${certs_dir}"
cd "${certs_dir}"

master="cilium-k8s-master"
worker="cilium-k8s-node-2"

if [ -n "${INSTALL}" ]; then
    log "Downloading cfssl utility..."
    cfssl_url="https://pkg.cfssl.org/R1.2/cfssl_linux-amd64"
    cfssljson_url="https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64"
    wget -nv ${cfssl_url}
    wget -nv ${cfssljson_url}
    log "Downloading cfssl utility... Done!"
    chmod +x cfssl_linux-amd64
    sudo mv cfssl_linux-amd64 /usr/bin/cfssl
    chmod +x cfssljson_linux-amd64
    sudo mv cfssljson_linux-amd64 /usr/bin/cfssljson
fi

#######################################
# Generate the certificate authority certificates in the form of ca-name.pem
# Arguments:
#   name
#######################################
generate_ca_certs(){
    if [ $# -ne 1 ]; then
        echo "Invalid arguments: usage generate_ca_certs <name>"
        exit
    fi
    name=${1}
    cat > ${name}-config.json <<EOF
{
  "signing": {
    "default": {
      "expiry": "2191h"
    },
    "profiles": {
      "${name}": {
        "usages": ["signing", "key encipherment", "server auth", "client auth"],
        "expiry": "2191h"
      }
    }
  }
}
EOF

    cat > ca-${name}-csr.json <<EOF
{
  "CN": "${name}",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "San Francisco",
      "O": "${name}",
      "OU": "CI",
      "ST": "California"
    }
  ]
}
EOF

    cfssl gencert -initca ca-${name}-csr.json | cfssljson -bare ca-${name}

    openssl x509 -in ca-${name}.pem -text -noout
}

#######################################
# Generate server certificates in the form of cli-name.pem
# Arguments:
#   certificate-authority filename
#   server/client filename
#   server/client's hostname
#######################################
generate_server_certs() {
    if [ $# -ne 3 ]; then
        echo "Invalid arguments: usage generate_client_certs <ca-name> <cli-name> <hostname>"
        exit
    fi
    ca_name=${1}
    cli_name=${2}
    master_hostname=${3}
    cat > ${cli_name}-csr.json <<EOF
{
  "CN": "${cli_name}",
  "hosts": [
    "${master_hostname}",
    "${master_ip}",
    "${cluster_api_server_ip}",
    "${cli_name}.cluster.default"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "San Francisco",
      "O": "${ca_name}",
      "OU": "CI",
      "ST": "California"
    }
  ]
}
EOF

    cfssl gencert \
      -ca=ca-${ca_name}.pem \
      -ca-key=ca-${ca_name}-key.pem \
      -config=${ca_name}-config.json \
      -profile=${ca_name} \
      ${cli_name}-csr.json | cfssljson -bare ${cli_name}

    openssl x509 -in ${cli_name}.pem -text -noout
}

#######################################
# Generate kubelet client certificates in the form of "filename.pem"
# Arguments:
#   certificate-authority filename
#   client name
#   filename
#######################################
generate_kubelet_client_certs() {
    if [ $# -ne 3 ]; then
        echo "Invalid arguments: usage generate_client_certs <ca-name> <cli-name> <filename>"
        exit
    fi
    ca_name=${1}
    cli_name=${2}
    filename=${3}
    cat > ${filename}-csr.json <<EOF
{
  "CN": "${cli_name}",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "San Francisco",
      "O": "system:nodes",
      "OU": "CI",
      "ST": "California"
    }
  ]
}
EOF

    cfssl gencert \
      -ca=ca-${ca_name}.pem \
      -ca-key=ca-${ca_name}-key.pem \
      -config=${ca_name}-config.json \
      -profile=${ca_name} \
      ${filename}-csr.json | cfssljson -bare ${filename}

    openssl x509 -in ${filename}.pem -text -noout
}

#######################################
# Generate k8s component certificates in the form of "filename.pem"
# Arguments:
#   certificate-authority filename
#   k8s component name
#   filename
#######################################
generate_k8s_component_certs() {
    if [ $# -ne 3 ]; then
        echo "Invalid arguments: usage generate_k8s_component_certs <ca-name> <k8s-component-name> <filename>"
        exit
    fi
    ca_name=${1}
    k8s_name=${2}
    cm_name=${3}
    cat > ${cm_name}-csr.json <<EOF
{
  "CN": "${k8s_name}",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "San Francisco",
      "O": "${k8s_name}",
      "OU": "CI",
      "ST": "California"
    }
  ]
}
EOF

    cfssl gencert \
      -ca=ca-${ca_name}.pem \
      -ca-key=ca-${ca_name}-key.pem \
      -config=${ca_name}-config.json \
      -profile=${ca_name} \
      ${cm_name}-csr.json | cfssljson -bare ${cm_name}

    openssl x509 -in ${cm_name}.pem -text -noout
}

#######################################
# Generates kubectl admin certificates in the form of "filename.pem"
# Arguments:
#   certificate-authority filename
#   username used in kubectl
#   filename
#######################################
generate_kubectl_admin_certs() {
    if [ $# -ne 3 ]; then
        echo "Invalid arguments: usage generate_kubectl_admin_certs <ca-name> <username> <filename>"
        exit
    fi
    ca_name=${1}
    username=${2}
    filename=${3}
    cat > ${filename}-csr.json <<EOF
{
  "CN": "${username}",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "San Francisco",
      "O": "system:masters",
      "OU": "CI",
      "ST": "California"
    }
  ]
}
EOF

    cfssl gencert \
      -ca=ca-${ca_name}.pem \
      -ca-key=ca-${ca_name}-key.pem \
      -config=${ca_name}-config.json \
      -profile=${ca_name} \
      ${filename}-csr.json | cfssljson -bare ${filename}

    openssl x509 -in ${filename}.pem -text -noout
}

#######################################
# Generates etcd client certificates in the form of "filename.pem"
# Arguments:
#   certificate-authority filename
#   client name used in etcd
#   filename
#######################################
generate_etcd_client_certs() {
    if [ $# -ne 3 ]; then
        echo "Invalid arguments: usage generate_etcd_client_certs <ca-name> <client-name> <filename>"
        exit
    fi
    ca_name=${1}
    client_name=${2}
    filename=${3}
    cat > ${filename}-csr.json <<EOF
{
  "CN": "${client_name}",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "San Francisco",
      "O": "kubernetes",
      "OU": "CI",
      "ST": "California"
    }
  ]
}
EOF

    cfssl gencert \
      -ca=ca-${ca_name}.pem \
      -ca-key=ca-${ca_name}-key.pem \
      -config=${ca_name}-config.json \
      -profile=${ca_name} \
      ${filename}-csr.json | cfssljson -bare ${filename}

    openssl x509 -in ${filename}.pem -text -noout
}

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
generate_kubelet_client_certs k8s system:node:${master} k8s-kubelet-${master}
generate_kubelet_client_certs k8s system:node:${worker} k8s-kubelet-${worker}
generate_k8s_component_certs k8s system:kube-proxy k8s-kube-proxy-${master}
generate_k8s_component_certs k8s system:kube-proxy k8s-kube-proxy-${worker}

# Generate kubelet client certificate so kube-apiserver can talk with kubelets
generate_k8s_component_certs k8s kubelet-api-server kubelet-api-server

# Generate CA for kubelets
generate_ca_certs kubelet

# Generate kubelet serving certificates to use to serve its endpoints
generate_k8s_component_certs kubelet ${master} kubelet-kubelet-${master}
generate_k8s_component_certs kubelet ${worker} kubelet-kubelet-${worker}

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
