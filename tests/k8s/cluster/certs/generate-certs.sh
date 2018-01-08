#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

set -ex

export 'KUBERNETES_MASTER_IP4'=${KUBERNETES_MASTER_IP4:-"192.168.36.11"}
export 'KUBERNETES_MASTER_IP6'=${KUBERNETES_MASTER_IP6:-"FD01::B"}
export 'KUBERNETES_NODE_2_IP4'=${KUBERNETES_NODE_2_IP4:-"192.168.36.12"}
export 'KUBERNETES_NODE_2_IP6'=${KUBERNETES_NODE_2_IP6:-"FD01::C"}
export 'KUBERNETES_MASTER_SVC_IP4'=${KUBERNETES_MASTER_SVC_IP4:-"172.20.0.1"}
export 'KUBERNETES_MASTER_SVC_IP6'=${KUBERNETES_MASTER_SVC_IP6:-"FD03::1"}
export 'cluster_name'=${cluster_name:-"cilium-k8s-tests"}

if [ -z "$(command -v cfssl)" ]; then
    echo "cfssl not found, please download it from"
    echo "https://pkg.cfssl.org/R1.2/cfssl_linux-amd64"
    echo "and add it to your PATH."
    exit -1
fi

if [ -z "$(command -v cfssljson)" ]; then
    echo "cfssljson not found, please download it from"
    echo "https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64"
    echo "and add it to your PATH."
    exit -1
fi

cat > "${dir}/ca-config.json" <<EOF
{
  "signing": {
    "default": {
      "expiry": "8760h"
    },
    "profiles": {
      "kubernetes": {
        "usages": ["signing", "key encipherment", "server auth", "client auth"],
        "expiry": "8760h"
      }
    }
  }
}
EOF

cat > "${dir}/ca-csr.json" <<EOF
{
  "CN": "Kubernetes",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "Kubernetes",
      "OU": "CA",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert -initca "${dir}/ca-csr.json" | cfssljson -bare "${dir}/ca"

cat > "${dir}/kubernetes-csr.json" <<EOF
{
  "CN": "kubernetes",
  "hosts": [
    "192.168.36.10",
    "${KUBERNETES_MASTER_IP4}",
    "${KUBERNETES_MASTER_IP6}",
    "${KUBERNETES_MASTER_SVC_IP4}",
    "${KUBERNETES_MASTER_SVC_IP6}",
    "127.0.0.1",
    "::1",
    "localhost",
    "${cluster_name}.default"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "Kubernetes",
      "OU": "Cluster",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca="${dir}/ca.pem" \
  -ca-key="${dir}/ca-key.pem" \
  -config="${dir}/ca-config.json" \
  -profile=kubernetes \
  "${dir}/kubernetes-csr.json" | cfssljson -bare "${dir}/kubernetes"

rm "${dir}/ca-config.json" \
   "${dir}/ca-csr.json" \
   "${dir}/kubernetes-csr.json"
