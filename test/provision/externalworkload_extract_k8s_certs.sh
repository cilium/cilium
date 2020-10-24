#!/bin/bash
set -e

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

echo "Extracting VM TLS config from Kubernetes secrets"
kubectl -n kube-system get secret clustermesh-apiserver-ca-cert -o jsonpath="{.data['ca\.crt']}" | base64 --decode >${DIR}/externalworkload-client-ca.crt
kubectl -n kube-system get secret clustermesh-apiserver-client-cert -o jsonpath="{.data['tls\.crt']}" | base64 --decode >${DIR}/externalworkload-client-tls.crt
kubectl -n kube-system get secret clustermesh-apiserver-client-cert -o jsonpath="{.data['tls\.key']}" | base64 --decode >${DIR}/externalworkload-client-tls.key
