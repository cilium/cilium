#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

cd "${dir}/certs"

# member.peerSecret
kubectl create secret generic -n kube-system cilium-etcd-peer-tls --from-file=peer-ca.crt --from-file=peer.crt --from-file=peer.key

# member.serverSecret
kubectl create secret generic -n kube-system cilium-etcd-server-tls --from-file=server-ca.crt --from-file=server.crt --from-file=server.key

# operatorSecret
kubectl create secret generic -n kube-system cilium-etcd-client-tls --from-file=etcd-client-ca.crt --from-file=etcd-client.crt --from-file=etcd-client.key
