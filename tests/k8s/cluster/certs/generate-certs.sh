#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/../../helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
certs_dir="${dir}/${k8s_version}"

set -e

function cleanup {
 rm ${certs_dir}/cfssl*
}

trap cleanup EXIT

if [ -z "${K8S}" ] ; then
  log "K8S environment variable not set; please set it and re-run this script"
  exit 1
fi

case "${K8S}" in
  "1.6")
    NUM="6"
    ;;
  "1.7")
    NUM="7"
    ;;
  *)
    log "Usage: K8S={1.6,1.7} generate-certs.sh"
    exit 1
esac

mkdir -p "${certs_dir}"
cd "${certs_dir}"
log "pwd: $(pwd)"

export 'KUBERNETES_MASTER_IP4'=${KUBERNETES_MASTER_IP4:-"192.168.3$NUM.11"}
export 'KUBERNETES_MASTER_IP6'=${KUBERNETES_MASTER_IP6:-"FD01::B"}
export 'KUBERNETES_NODE_2_IP4'=${KUBERNETES_NODE_2_IP4:-"192.168.3$NUM.12"}
export 'KUBERNETES_NODE_2_IP6'=${KUBERNETES_NODE_2_IP6:-"FD01::C"}
export 'KUBERNETES_MASTER_SVC_IP4'=${KUBERNETES_MASTER_SVC_IP4:-"172.20.0.1"}
export 'KUBERNETES_MASTER_SVC_IP6'=${KUBERNETES_MASTER_SVC_IP6:-"FD03::1"}
export 'cluster_name'=${cluster_name:-"cilium-k8s-tests"}

log "KUBERNETES_MASTER_IP4: ${KUBERNETES_MASTER_IP4}"
log "KUBERNETES_MASTER_IP6: ${KUBERNETES_MASTER_IP6}"
log "KUBERNETES_NODE_2_IP4: ${KUBERNETES_NODE_2_IP4}"
log "KUBERNETES_NODE_2_IP6: ${KUBERNETES_NODE_2_IP6}"
log "KUBERNETES_MASTER_SVC_IP4: ${KUBERNETES_MASTER_SVC_IP4}"
log "KUBERNETES_MASTER_SVC_IP6: ${KUBERNETES_MASTER_SVC_IP6}"
log "cluster_name: ${cluster_name}"


function download_cfssl {
  wget --quiet https://pkg.cfssl.org/R1.2/cfssl_linux-amd64 -O cfssl 
  mv cfssl /usr/bin/cfssl && chmod +x /usr/bin/cfssl
  
  wget --quiet https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64 -O cfssljson
  mv cfssljson /usr/bin/cfssljson && chmod +x /usr/bin/cfssljson
}

download_cfssl

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

log "creating ${certs_dir}/ca-config.json"
cat > "${certs_dir}/ca-config.json" <<EOF
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

log "creating ${certs_dir}/ca-csr.json"
cat > "${certs_dir}/ca-csr.json" <<EOF
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

log "generating certificates"
cfssl gencert -initca "${certs_dir}/ca-csr.json" | cfssljson -bare "${certs_dir}/ca"

log "creating ${certs_dir}/kubernetes-csr.json"
cat > "${certs_dir}/kubernetes-csr.json" <<EOF
{
  "CN": "kubernetes",
  "hosts": [
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
  -ca="${certs_dir}/ca.pem" \
  -ca-key="${certs_dir}/ca-key.pem" \
  -config="${certs_dir}/ca-config.json" \
  -profile=kubernetes \
  "${certs_dir}/kubernetes-csr.json" | cfssljson -bare "${certs_dir}/kubernetes"

log "${certs_dir} contents:"
ls ${certs_dir}
log "${dir} contents:"
ls ${dir}

rm "${certs_dir}/ca-config.json" \
   "${certs_dir}/ca-csr.json" \
   "${certs_dir}/kubernetes-csr.json"
