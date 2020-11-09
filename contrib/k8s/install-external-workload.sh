#!/bin/bash
set -e
set -x
shopt -s extglob

if [ -z "$CLUSTER_ADDR" ] ; then
    echo "CLUSTER_ADDR must be defined to the IP:PORT at which the clustermesh-apiserver is reachable."
    exit 1
fi

CILIUM_IMAGE=${CILIUM_IMAGE:-cilium/cilium:latest}

# TLS certs path defaults to the current directory
TLS_PATH=${TLS_PATH:-.}

port='@(6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9][0-9][0-9]|[1-5][0-9][0-9][0-9][0-9]|[1-9][0-9][0-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9]|[1-9])'
byte='@(25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])'
ipv4="$byte\.$byte\.$byte\.$byte"

# Default port is for a HostPort service
case "$CLUSTER_ADDR" in
    \[+([0-9a-fA-F:])\]:$port)
	CLUSTER_PORT=${CLUSTER_ADDR##\[*\]:}
	CLUSTER_IP=${CLUSTER_ADDR#\[}
	CLUSTER_IP=${CLUSTER_IP%\]:*}
	;;
    [^[]$ipv4:$port)
	CLUSTER_PORT=${CLUSTER_ADDR##*:}
	CLUSTER_IP=${CLUSTER_ADDR%:*}
	;;
    *:*)
	echo "Malformed CLUSTER_ADDR: $CLUSTER_ADDR"
	exit 1
	;;
    *)
	CLUSTER_PORT=32379
	CLUSTER_IP=$CLUSTER_ADDR
	;;
esac

CA_CRT="${TLS_PATH}/external-workload-ca.crt"
TLS_CRT="${TLS_PATH}/external-workload-tls.crt"
TLS_KEY="${TLS_PATH}/external-workload-tls.key"

if [[ ! ( -f $CA_CRT && -f $TLS_CRT && -f $TLS_KEY ) ]]; then
    echo "Client certificates not found. These can be extracted from your Kubernetes"
    echo "cluster with 'contrib/k8s/extract-external-workload-certs.sh'"
    exit 1
fi

sudo mkdir -p /var/lib/cilium/etcd
sudo cp "$CA_CRT" /var/lib/cilium/etcd/ca.crt
sudo cp "$TLS_CRT" /var/lib/cilium/etcd/tls.crt
sudo cp "$TLS_KEY" /var/lib/cilium/etcd/tls.key
sudo tee /var/lib/cilium/etcd/config.yaml <<EOF >/dev/null
---
trusted-ca-file: /var/lib/cilium/etcd/ca.crt
cert-file: /var/lib/cilium/etcd/tls.crt
key-file: /var/lib/cilium/etcd/tls.key
endpoints:
- https://clustermesh-apiserver.cilium.io:$CLUSTER_PORT
EOF

CILIUM_OPTS=" --join-cluster --enable-host-reachable-services"
CILIUM_OPTS+=" --kvstore etcd --kvstore-opt etcd.config=/var/lib/cilium/etcd/config.yaml"
if [ -n "$HOST_IP" ] ; then
    CILIUM_OPTS+=" --ipv4-node $HOST_IP"
fi
if [ -n "$DEBUG" ] ; then
    CILIUM_OPTS+=" --debug"
fi

DOCKER_OPTS=" -d --log-driver syslog --restart always"
DOCKER_OPTS+=" --privileged --network host --cap-add NET_ADMIN --cap-add SYS_MODULE"
DOCKER_OPTS+=" --volume /var/lib/cilium/etcd:/var/lib/cilium/etcd"
DOCKER_OPTS+=" --volume /var/run/cilium:/var/run/cilium"
DOCKER_OPTS+=" --volume /boot:/boot"
DOCKER_OPTS+=" --volume /lib/modules:/lib/modules"
DOCKER_OPTS+=" --volume /sys/fs/bpf:/sys/fs/bpf"
DOCKER_OPTS+=" --volume /run/xtables.lock:/run/xtables.lock"
DOCKER_OPTS+=" --add-host clustermesh-apiserver.cilium.io:$CLUSTER_IP"

if [ -n "$(docker ps -a -q -f name=cilium)" ]; then
    echo "Shutting down running Cilium agent"
    sudo docker rm -f cilium || true
fi

echo "Launching Cilium agent..."
sudo docker run --name cilium $DOCKER_OPTS cilium/cilium:latest cilium-agent $CILIUM_OPTS

# Copy Cilium CLI
sudo docker cp cilium:/usr/bin/cilium /usr/bin/cilium

# Wait for cilium agent to become available
cilium_started=false
for ((i = 0 ; i < 24; i++)); do
    if cilium status --brief > /dev/null 2>&1; then
        cilium_started=true
        break
    fi
    sleep 5s
    echo "Waiting for Cilium daemon to come up..."
done

if [ "$cilium_started" = true ] ; then
    echo 'Cilium successfully started!'
else
    >&2 echo 'Timeout waiting for Cilium to start.'
    exit 1
fi

# Wait for kube-dns service to become available
kubedns=""
for ((i = 0 ; i < 24; i++)); do
    kubedns=$(cilium service list get -o jsonpath='{[?(@.spec.frontend-address.port==53)].spec.frontend-address.ip}')
    if [ -n "$kubedns" ] ; then
        break
    fi
    sleep 5s
    echo "Waiting for kube-dns service to come available..."
done

if [ -n "$kubedns" ] ; then
    echo "updating /etc/resolv.conf with kube-dns IP $kubedns"

    sudo tee /etc/resolv.conf <<EOF >/dev/null
nameserver $kubedns
EOF
else
    >&2 echo "kube-dns not found."
    exit 1
fi
