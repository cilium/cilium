#!/bin/bash
set -e

CILIUM_DS_TAG="k8s-app=cilium"
KUBE_SYSTEM_NAMESPACE="kube-system"
KUBECTL="/usr/bin/kubectl"
PROVISIONSRC="/tmp/provision"
GOPATH="/home/vagrant/go"
REGISTRY="k8s1:5000"
CILIUM_TAG="cilium/cilium-dev"
CILIUM_OPERATOR_TAG="cilium/operator"

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${PROVISIONSRC}/helpers.bash"

function delete_cilium_pods {
  echo "Executing: $KUBECTL delete pods -n $KUBE_SYSTEM_NAMESPACE -l $CILIUM_DS_TAG"
  $KUBECTL delete pods -n $KUBE_SYSTEM_NAMESPACE -l $CILIUM_DS_TAG
}


cd ${GOPATH}/src/github.com/cilium/cilium


if echo $(hostname) | grep "k8s" -q;
then
    # Only need to build on one host, since we can pull from the other host.
    if [[ "$(hostname)" == "k8s1" ]]; then
      ./test/provision/container-images.sh cilium_images .
      if [[ "${CILIUM_IMAGE}" == "" && "${CILIUM_OPERATOR_IMAGE}" == "" ]]; then
        echo "building cilium/cilium container image..."
        make LOCKDEBUG=1 docker-image-no-clean

        echo "building cilium/operator container image..."
	make LOCKDEBUG=1 docker-operator-image&
        export OPERATORPID=$!

        echo "pushing cilium/cilium image to k8s1:5000/cilium/cilium-dev..."
        docker tag cilium/cilium k8s1:5000/cilium/cilium-dev
        docker rmi cilium/cilium:latest
        docker push k8s1:5000/cilium/cilium-dev

        wait $OPERATORPID
        echo "pushing cilium/operator image to k8s1:5000/cilium/operator..."
        docker tag cilium/operator k8s1:5000/cilium/operator
        docker push k8s1:5000/cilium/operator
        delete_cilium_pods
      elif [[ "${CILIUM_IMAGE}" != "" && "${CILIUM_OPERATOR_IMAGE}" == "" ]]; then
        pull_image_and_push_to_local_registry ${CILIUM_IMAGE} ${REGISTRY} ${CILIUM_TAG}
        build_operator_image
        delete_cilium_pods
      elif [[ "${CILIUM_IMAGE}" == "" && "${CILIUM_OPERATOR_IMAGE}" != "" ]]; then
        pull_image_and_push_to_local_registry ${CILIUM_OPERATOR_IMAGE} ${REGISTRY} ${CILIUM_OPERATOR_TAG}
        build_cilium_image
        delete_cilium_pods
      else
        pull_image_and_push_to_local_registry ${CILIUM_IMAGE} ${REGISTRY} ${CILIUM_TAG}
        pull_image_and_push_to_local_registry ${CILIUM_OPERATOR_IMAGE} ${REGISTRY} ${CILIUM_OPERATOR_TAG}
        delete_cilium_pods
      fi
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

# Download all images needed for tests.
./test/provision/container-images.sh test_images .
