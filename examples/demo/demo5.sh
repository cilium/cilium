#!/usr/bin/env bash

. $(dirname ${BASH_SOURCE})/../../contrib/shell/util.sh

NETWORK="cilium"

function cleanup {
    tmux kill-session -t my-session >/dev/null 2>&1
    sudo killall -9 etcd 2> /dev/null || true
    sudo killall -9 kubelet 2> /dev/null || true
    sudo killall -9 hyperkube 2> /dev/null || true
    sudo killall -9 kube-scheduler 2> /dev/null || true
    sudo killall -9 kube-controller-manager 2> /dev/null || true
    sudo killall -9 kube-proxy 2> /dev/null || true
    sudo killall -9 kube-apiserver 2> /dev/null || true
    docker rm -f `docker ps -aq --filter=name=k8s` 2> /dev/null || true
    cilium policy delete --all
}

trap cleanup EXIT

docker network rm $NETWORK > /dev/null 2>&1
docker network create --ipv6 --subnet ::1/112 --driver cilium --ipam-driver cilium $NETWORK > /dev/null
cilium policy delete --all
#Clean old kubernetes certificates
sudo rm -fr /run/kubernetes

desc "Demo: Start kubernetes, import k8s network policy, test connections"
run ""

tmux new -d -s my-session \
    "$(dirname ${BASH_SOURCE})/demo5_top.sh" \; \
    split-window -v -d "$(dirname $BASH_SOURCE)/demo5_bottom.sh" \; \
    attach \;

desc "Clean up"
