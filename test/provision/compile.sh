#!/bin/bash
set -e

CILIUM_DS_TAG="k8s-app=cilium"
KUBE_SYSTEM_NAMESPACE="kube-system"
KUBECTL="/usr/bin/kubectl"
PROVISIONSRC="/tmp/provision"
GOPATH="/home/vagrant/go"

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${PROVISIONSRC}/helpers.bash"

cd ${GOPATH}/src/github.com/cilium/cilium

if echo $(hostname) | grep "k8s" -q;
then
    if [[ "$(hostname)" == "k8s1" ]]; then
        echo "building cilium/cilium container image..."
        make LOCKDEBUG=1 docker-image-no-clean
        echo "pushing container image to k8s1:5000/cilium/cilium-dev..."
        docker tag cilium/cilium k8s1:5000/cilium/cilium-dev
        docker rmi cilium/cilium:latest
        docker push k8s1:5000/cilium/cilium-dev
        echo "building cilium/operator-dev container image..."
        docker build -t k8s1:5000/cilium/operator-dev -f ./cilium-operator.Dockerfile .
        docker push k8s1:5000/cilium/operator-dev
        echo "Executing: $KUBECTL delete pods -n $KUBE_SYSTEM_NAMESPACE -l $CILIUM_DS_TAG"
        $KUBECTL delete pods -n $KUBE_SYSTEM_NAMESPACE -l $CILIUM_DS_TAG
    else
        echo "Not on master K8S node; no need to compile Cilium container"
    fi
else
    echo "compiling cilium..."
    sudo -u vagrant -H -E make LOCKDEBUG=1 SKIP_DOCS=true
    echo "installing cilium..."
    make install
    mkdir -p /etc/sysconfig/
    cp -f contrib/systemd/cilium /etc/sysconfig/cilium
    for svc in $(ls -1 ./contrib/systemd/*.*); do
        cp -f "${svc}"  /etc/systemd/system/
        service=$(echo "$svc" | sed -E -n 's/.*\/(.*?).(service|mount)/\1.\2/p')
        echo "service $service"
        systemctl enable $service || echo "service $service failed"
        systemctl restart $service || echo "service $service failed to restart"
    done
    echo "running \"sudo adduser vagrant cilium\" "
    sudo adduser vagrant cilium
fi
