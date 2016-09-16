#!/usr/bin/env bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "./helpers.bash"

set -e

if [ -z $K8S ]; then
	exit 0
fi

source "${dir}/../examples/kubernetes/env-kube.sh"

TEST_NET="cilium"
NETPERF_IMAGE="noironetworks/netperf"
K8S_PATH="/home/vagrant/kubernetes"

function start_k8s {
    if [ ! -d "${K8S_PATH}" ]; then
        exit 1
    fi
    echo "Starting kubernetes..."
    cd ${K8S_PATH}
    "./hack/local-up-cluster.sh" &
    sleep 5s
}

function cleanup {
    echo "Cleaning up"
    sleep 3s
    sudo killall -9 etcd || true
    sudo killall -9 kubelet || true
    sudo killall -9 hyperkube || true
    sudo killall -9 kube-scheduler || true
    sudo killall -9 kube-controller-manager || true
    sudo killall -9 kube-proxy || true
    sudo killall -9 kube-apiserver || true
    docker rm -f `docker ps -aq --filter=name=k8s` 2> /dev/null || true
    monitor_stop
    sudo cilium -D policy delete io.cilium
}

trap cleanup EXIT

start_k8s

monitor_start

set -x

"${dir}/../examples/kubernetes/0-policy.sh" 300
"${dir}/../examples/kubernetes/1-guestbook.sh" 300
"${dir}/wait-for-docker.bash" k8s_guestbook 100
"${dir}/wait-for-docker.bash" k8s_redis-slave 100
"${dir}/wait-for-docker.bash" k8s_redis-master 100

monitor_clear

if [ -n "${IPV4}" ]; then
    docker exec -ti `docker ps -aq --filter=name=k8s_guestbook` sh -c 'sleep 60 && nc redis-master 6379 <<EOF
PING
EOF' || {
        abort "Unable to nc redis-master 6379"
    }
else
    docker exec -ti `docker ps -aq --filter=name=k8s_guestbook` sh -c 'sleep 60 && nc redis-master 6379 <<EOF
PING
EOF' || {
        abort "Unable to nc redis-master 6379"
    }
fi

echo "SUCCESS!"
