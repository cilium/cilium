#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

if [ -n "${INSTALL}" ]; then
    cfssl_url="https://pkg.cfssl.org/R1.2/cfssl_linux-amd64"
    cfssljson_url="https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64"
    wget ${cfssl_url}
    chmod +x cfssl_linux-amd64
    sudo mv cfssl_linux-amd64 /usr/bin/cfssl
    wget ${cfssljson_url}
    chmod +x cfssljson_linux-amd64
    sudo mv cfssljson_linux-amd64 /usr/bin/cfssljson
fi

echo '{
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
}' > ca-config.json

echo '{
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
}' > ca-csr.json

cfssl gencert -initca ca-csr.json | cfssljson -bare ca

openssl x509 -in ca.pem -text -noout

KUBERNETES_PUBLIC_ADDRESS=$(gcloud compute addresses describe kubernetes \
  --format 'value(address)')

cat > kubernetes-csr.json <<EOF
{
  "CN": "kubernetes",
  "hosts": [
    "worker0",
    "worker1",
    "worker2",
    "ip-$(echo "${workers_ips[0]}" | tr "." -)",
    "ip-$(echo "${workers_ips[1]}" | tr "." -)",
    "ip-$(echo "${workers_ips[2]}" | tr "." -)",
    "${k8s_master_service_ip}",
    "${controllers_ips[0]}",
    "${controllers_ips[1]}",
    "${controllers_ips[2]}",
    "${workers_ips[0]}",
    "${workers_ips[1]}",
    "${workers_ips[2]}",
    "${KUBERNETES_PUBLIC_ADDRESS}",
    "127.0.0.1"
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
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -profile=kubernetes \
  kubernetes-csr.json | cfssljson -bare kubernetes

openssl x509 -in kubernetes.pem -text -noout

KUBERNETES_HOSTS=(controller0 controller1 controller2 worker0 worker1 worker2)

for host in ${KUBERNETES_HOSTS[*]}; do
  gcloud compute copy-files ca.pem kubernetes-key.pem kubernetes.pem ${host}:~/
done
