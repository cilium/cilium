#!/bin/bash
set -e
set -x

# IP address at which the clustermesh-apiserver service is reachable at
# Default to the address of k8s1
CLUSTER_IP=${CLUSTER_IP:-"192.168.36.11"}

# IP address of the VM itself. This is needed due to avoid Cilium selecting the "10.0.2.15"
# each vagrant VM has as the first address. Default to the address of the runtime VM
VM_IP=${VM_IP:-"192.168.36.10"}

PROVISIONSRC="/tmp/provision"

CA_CRT="${PROVISIONSRC}/externalworkload-client-ca.crt"
TLS_CRT="${PROVISIONSRC}/externalworkload-client-tls.crt"
TLS_KEY="${PROVISIONSRC}/externalworkload-client-tls.key"

if [[ ! ( -f $CA_CRT && -f $TLS_CRT && -f $TLS_KEY ) ]]; then
    echo "Client certificates not found. These can be extracted from your Kubernetes"
    echo "cluster with 'test/provision/externalworkload_extract_k8s_certs.sh'"
    exit 1
fi

sudo mkdir -p /var/lib/cilium/etcd
sudo cp $CA_CRT /var/lib/cilium/etcd/ca.crt
sudo cp $TLS_CRT /var/lib/cilium/etcd/tls.crt
sudo cp $TLS_KEY /var/lib/cilium/etcd/tls.key
sudo tee /var/lib/cilium/etcd/config.yaml <<EOF
---
trusted-ca-file: /var/lib/cilium/etcd/ca.crt
cert-file: /var/lib/cilium/etcd/tls.crt
key-file: /var/lib/cilium/etcd/tls.key
endpoints:
- https://clustermesh-apiserver.cilium.io:32379
EOF

CILIUM_OPTS=" --debug --ipv4-node $VM_IP"
CILIUM_OPTS+=" --join-cluster"
CILIUM_OPTS+=" --kvstore etcd --kvstore-opt etcd.config=/var/lib/cilium/etcd/config.yaml"

# Build docker image
DOCKER_BUILDKIT=1 make -C /home/vagrant/go/src/github.com/cilium/cilium dev-docker-image

# Etcd TLS config needs hostname IP mapping
CLUSTER_HOST="clustermesh-apiserver.cilium.io:$CLUSTER_IP"

DOCKER_OPTS=" -d --log-driver syslog --restart always"
DOCKER_OPTS+=" --privileged --network host --cap-add NET_ADMIN --cap-add SYS_MODULE"
DOCKER_OPTS+=" --volume /var/lib/cilium/etcd:/var/lib/cilium/etcd"
DOCKER_OPTS+=" --volume /var/run/cilium:/var/run/cilium"
DOCKER_OPTS+=" --volume /boot:/boot"
DOCKER_OPTS+=" --volume /lib/modules:/lib/modules"
DOCKER_OPTS+=" --volume /sys/fs/bpf:/sys/fs/bpf"
DOCKER_OPTS+=" --volume /run/xtables.lock:/run/xtables.lock"
DOCKER_OPTS+=" --add-host $CLUSTER_HOST"

sudo docker run --name cilium $DOCKER_OPTS cilium/cilium-dev:latest cilium-agent $CILIUM_OPTS

# Copy Cilium CLI
sudo docker cp cilium:/usr/bin/cilium /usr/bin/cilium
