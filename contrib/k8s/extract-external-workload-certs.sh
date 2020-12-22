#!/bin/bash
set -e

# TLS certs path defaults to the current directory
TLS_PATH=${TLS_PATH:-.}

echo "Extracting external workload TLS config from Kubernetes secrets in to ${TLS_PATH}"
kubectl -n kube-system get secret clustermesh-apiserver-ca-cert -o jsonpath="{.data['ca\.crt']}" | base64 --decode >"${TLS_PATH}"/external-workload-ca.crt
kubectl -n kube-system get secret clustermesh-apiserver-client-cert -o jsonpath="{.data['tls\.crt']}" | base64 --decode >"${TLS_PATH}"/external-workload-tls.crt
kubectl -n kube-system get secret clustermesh-apiserver-client-cert -o jsonpath="{.data['tls\.key']}" | base64 --decode >"${TLS_PATH}"/external-workload-tls.key
