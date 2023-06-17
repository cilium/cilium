#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

# Extract a clustermesh secret from the local cluster to be used in other clusters
set -e

NAMESPACE=$(kubectl get pod -l k8s-app=clustermesh-apiserver -o jsonpath='{.items[0].metadata.namespace}' --all-namespaces)
NODE_NAME=$(kubectl -n $NAMESPACE get pod -l k8s-app=clustermesh-apiserver -o jsonpath='{.items[0].spec.nodeName}')
NODE_IP=$(kubectl -n $NAMESPACE get node $NODE_NAME -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' | awk '{print $1}')
NODE_PORT=$(kubectl -n $NAMESPACE get svc clustermesh-apiserver -o jsonpath='{.spec.ports[0].nodePort}')
CLUSTER_NAME=$(kubectl -n $NAMESPACE get cm cilium-config -o jsonpath='{.data.cluster-name}')
# TODO: once v1.10 is the minimum version supported, we can replace the
# following line to use ca.crt from the clustermesh-apiserver-remote-cert
# secret directly.
CA_CRT=$(kubectl -n $NAMESPACE get secret clustermesh-apiserver-ca-cert -o jsonpath="{.data['ca\.crt']}")
TLS_CRT=$(kubectl -n $NAMESPACE get secret clustermesh-apiserver-remote-cert -o jsonpath="{.data['tls\.crt']}")
TLS_KEY=$(kubectl -n $NAMESPACE get secret clustermesh-apiserver-remote-cert -o jsonpath="{.data['tls\.key']}")

define(){ IFS='\n' read -r -d '' ${1} || true; }

ETCD_CONFIG=`cat <<EOF |
endpoints:
- https://${NODE_IP}:${NODE_PORT}
trusted-ca-file: '/var/lib/cilium/clustermesh/${CLUSTER_NAME}-ca.crt'
cert-file: '/var/lib/cilium/clustermesh/${CLUSTER_NAME}.crt'
key-file: '/var/lib/cilium/clustermesh/${CLUSTER_NAME}.key'
EOF
base64 | tr -d '\n'`

cat << EOF
{
    "apiVersion": "v1",
    "kind": "Secret",
    "metadata": {
        "name": "cilium-clustermesh"
    },
    "type": "Opaque",
    "data": {
        "${CLUSTER_NAME}": "${ETCD_CONFIG}",
        "${CLUSTER_NAME}-ca.crt": "${CA_CRT}",
        "${CLUSTER_NAME}.crt": "${TLS_CRT}",
        "${CLUSTER_NAME}.key": "${TLS_KEY}"
    }
}
EOF
