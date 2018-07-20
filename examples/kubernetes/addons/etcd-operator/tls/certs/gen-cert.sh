#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

if [ -z "$(which cfssl)" ]; then
    echo "Please install the cfssl utility and make sure you have it in your \$PATH"
    echo "You can install it in your \$GOPATH by running:"
    echo "go get -u github.com/cloudflare/cfssl/cmd/cfssl"
    exit -1
fi

if [ -z "$(which cfssljson)" ]; then
    echo "Please install the cfssljson utility and make sure you have it in your \$PATH"
    echo "You can install it in your \$GOPATH by running:"
    echo "go get -u github.com/cloudflare/cfssl/cmd/cfssljson"
    exit -1
fi

cluster_domain="${1:-"${CLUSTER_DOMAIN}"}"
if [ -z "${cluster_domain}" ]; then
    echo "Please provide your cluster domain ./gen-cert.sh <cluster-domain>"
    echo "You can find it by checking the config map of core-dns by running"
    echo "kubectl get ConfigMap --namespace kube-system coredns -o yaml | grep kubernetes"
    echo "or by checking the kube-dns deployment and grepping for 'domain'"
    echo "kubectl get Deployment --namespace kube-system kube-dns -o yaml | grep domain"
    echo "For reference, the cluster domain used in Kubernetes clusters by default is 'cluster.local'"
    exit -1
fi

cd "${dir}"

echo "generating CA certs ==="
cfssl gencert -initca ca-csr.json | cfssljson -bare ca

echo "generating etcd peer.json for cluster domain ${cluster_domain} ==="

sed -e "s/CLUSTER_DOMAIN/${cluster_domain}/" peer.json.sed > peer.json

echo "generating etcd peer certs ==="
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=peer peer.json | cfssljson -bare peer

echo "generating etcd server certs ==="
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=server server.json | cfssljson -bare server

echo "generating etcd client certs ==="
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=client etcd-client.json | cfssljson -bare etcd-client

mv etcd-client.pem etcd-client.crt
mv etcd-client-key.pem etcd-client.key
cp ca.pem etcd-client-ca.crt

mv server.pem server.crt
mv server-key.pem server.key
cp ca.pem server-ca.crt

mv peer.pem peer.crt
mv peer-key.pem peer.key
mv ca.pem peer-ca.crt

rm *.csr ca-key.pem

cd -
