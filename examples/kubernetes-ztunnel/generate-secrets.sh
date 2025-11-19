#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -eu

# == Bootstrap ===
openssl genrsa -out bootstrap-private.key 2048

echo '
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[ req_distinguished_name ]
O = cluster.local

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
' > openssl.conf

openssl req -x509 -new -nodes -key bootstrap-private.key -sha256 -days 3650 -out bootstrap-root.crt -config openssl.conf

# == CA ==
openssl genrsa -out ca-private.key 2048

echo '
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[ req_distinguished_name ]
O = cluster.local

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
' > openssl.conf

openssl req -x509 -new -nodes -key ca-private.key -sha256 -days 3650 -out ca-root.crt -config openssl.conf

kubectl --namespace kube-system create secret generic cilium-ztunnel-secrets \
      --from-file=bootstrap-private.key=bootstrap-private.key \
      --from-file=bootstrap-root.crt=bootstrap-root.crt \
      --from-file=ca-private.key=ca-private.key \
      --from-file=ca-root.crt=ca-root.crt
