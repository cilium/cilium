#!/usr/bin/env bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "./helpers.bash"

set -e

if [ -z $K8S ]; then
	exit 0
fi

function cleanup {
    echo "Cleaning up"
    sleep 3s
    monitor_stop
    "${dir}/../examples/kubernetes/scripts/11-cleanup.sh"
}

trap cleanup EXIT

monitor_start

set -x

"${dir}/../examples/kubernetes/scripts/08-cilium.sh"
"${dir}/../examples/kubernetes/scripts/09-dns-addon.sh"
SOCAT_OFF=1 "${dir}/../examples/kubernetes/scripts/10-1-smoke-test.sh"
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
