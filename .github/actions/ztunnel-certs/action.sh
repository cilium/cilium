#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

# Generate TLS certificates for ztunnel xDS communication and create
# the cilium-ztunnel-secrets Kubernetes secret.

set -euo pipefail

WORKDIR=$(mktemp -d)
trap "rm -rf ${WORKDIR}" EXIT

cd "${WORKDIR}"

# == Bootstrap certificates ==
# Used for TLS between ztunnel and the Cilium agent xDS server
openssl genrsa -out bootstrap-private.key 2048

cat > bootstrap.conf << 'EOF'
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
EOF

openssl req -x509 -new -nodes \
    -key bootstrap-private.key \
    -sha256 -days 3650 \
    -out bootstrap-root.crt \
    -config bootstrap.conf

# == CA certificates ==
# Used by Cilium agent to sign workload certificates for ztunnel mTLS
openssl genrsa -out ca-private.key 2048

cat > ca.conf << 'EOF'
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
EOF

openssl req -x509 -new -nodes \
    -key ca-private.key \
    -sha256 -days 3650 \
    -out ca-root.crt \
    -config ca.conf

# == Create Kubernetes secret ==
kubectl --namespace kube-system create secret generic cilium-ztunnel-secrets \
    --from-file=bootstrap-private.key=bootstrap-private.key \
    --from-file=bootstrap-root.crt=bootstrap-root.crt \
    --from-file=ca-private.key=ca-private.key \
    --from-file=ca-root.crt=ca-root.crt

echo "Successfully created cilium-ztunnel-secrets in kube-system namespace"
