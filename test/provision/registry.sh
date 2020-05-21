#!/usr/bin/env bash

source "${ENV_FILEPATH}"

set -e

CERTS_DIR=/certs/

echo '{"insecure-registries": ["k8s1:5000"]}' > /etc/docker/daemon.json
sudo pkill -SIGHUP docker

docker kill registry
docker rm registry

# Docker registry - certs

sudo mkdir -p $CERTS_DIR
sudo chmod 777 $CERTS_DIR
cd $HOME
rm -rfv certs
mkdir certs

cat <<EOF > server.conf
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req

[ req_distinguished_name ]
C                      = UK
ST                     = UK
L                      = London
O                      = cilium
OU                     = experimental
CN                     = cilium.io
emailAddress           = ian@cilium.io

[ v3_req ]
# Extensions to add to a certificate request
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = cilium.io
DNS.2 = *.cilium.io
DNS.3 = k8s1
IP.1 = 192.168.36.11
IP.2 = 10.0.2.15
EOF

openssl genrsa -out certs/ca.key 4096
openssl req -new -x509 -days 3650 -key certs/ca.key -out certs/ca.crt \
    -subj "/C=uk/ST=uk/L=London/O=cilium/CN=cilium.io"

openssl genrsa -out certs/cilium.key 4096
openssl req -new -nodes \
    -key certs/cilium.key \
    -out certs/cilium.request -config server.conf

openssl x509 -req -days 366 \
    -in certs/cilium.request \
    -CA certs/ca.crt \
    -CAkey certs/ca.key \
    -set_serial 01 \
    -out certs/cilium.cert \
    -extensions v3_req -extfile server.conf

mkdir -p /usr/local/share/ca-certificates

cp -rfv certs/* /certs/
cp certs/ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

docker run -d -p 5000:5000 --name registry -v ${CERTS_DIR}:/certs \
        -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/cilium.cert \
        -e REGISTRY_HTTP_TLS_KEY=/certs/cilium.key \
        --restart=always \
        docker.io/library/registry:2.6.2
