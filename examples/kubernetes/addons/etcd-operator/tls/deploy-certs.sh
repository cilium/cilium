#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

CERT_TMP_DIR=${1:-"${dir}/certs"}

if [ -z "${1}" ]; then
    echo "DEBUG: Using provided folder ${CERT_TMP_DIR}"
fi

cd "${CERT_TMP_DIR}"

# member.peerSecret
kubectl create secret generic -n kube-system cilium-etcd-peer-tls --from-file=peer-ca.crt --from-file=peer.crt --from-file=peer.key

# member.serverSecret
kubectl create secret generic -n kube-system cilium-etcd-server-tls --from-file=server-ca.crt --from-file=server.crt --from-file=server.key

# operatorSecret
kubectl create secret generic -n kube-system cilium-etcd-client-tls --from-file=etcd-client-ca.crt --from-file=etcd-client.crt --from-file=etcd-client.key
