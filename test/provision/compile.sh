#!/bin/bash
set -e

CILIUM_DS_TAG="k8s-app=cilium"
KUBE_SYSTEM_NAMESPACE="kube-system"
KUBECTL="/usr/bin/kubectl"
PROVISIONSRC="/tmp/provision"
GOPATH="/home/vagrant/go"
CILIUM_REGISTRY=${CILIUM_REGISTRY:-"k8s1:5000"}
CILIUM_REMOTE_IMAGE=${CILIUM_IMAGE:-cilium/cilium-dev}
CILIUM_TAG=${CILIUM_TAG:-"latest"}
CILIUM_OPERATOR_REMOTE_IMAGE=${CILIUM_OPERATOR_IMAGE:-cilium/operator}
CILIUM_OPERATOR_TAG=${CILIUM_OPERATOR_TAG:-"latest"}

# These must match the makefile/Dockerfile since that names the image in the local docker
CILIUM_LOCAL_BUILD_IMAGE=${CILIUM_LOCAL_BUILD_IMAGE:-cilium/cilium}
CILIUM_OPERATOR_LOCAL_BUILD_IMAGE=${CILIUM_OPERATOR_LOCAL_BUILD_IMAGE:-cilium/operator}

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
        echo "building ${CILIUM_LOCAL_BUILD_IMAGE} container image..."
        make LOCKDEBUG=1 docker-image-no-clean

        echo "building ${CILIUM_OPERATOR_LOCAL_BUILD_IMAGE} container image..."
        make LOCKDEBUG=1 docker-operator-image&
        export OPERATORPID=$!

        echo "pushing ${CILIUM_LOCAL_BUILD_IMAGE} image to k8s1:5000/cilium/cilium-dev..."
        docker tag ${CILIUM_LOCAL_BUILD_IMAGE} "${CILIUM_REGISTRY}/${CILIUM_REMOTE_IMAGE}:${CILIUM_TAG}"
        docker rmi "${CILIUM_LOCAL_BUILD_IMAGE}:${CILIUM_TAG}"
        docker push ${CILIUM_REGISTRY}/${CILIUM_REMOTE_IMAGE}:${CILIUM_TAG}


        wait $OPERATORPID
        echo "pushing ${CILIUM_OPERATOR_LOCAL_BUILD_IMAGE} image to k8s1:5000/cilium/operator..."
        docker tag ${CILIUM_OPERATOR_LOCAL_BUILD_IMAGE} "${CILIUM_REGISTRY}/${CILIUM_OPERATOR_REMOTE_IMAGE}:${CILIUM_OPERATOR_TAG}"
        docker push "${CILIUM_REGISTRY}/${CILIUM_OPERATOR_REMOTE_IMAGE}:${CILIUM_OPERATOR_TAG}"
        delete_cilium_pods
      elif [[ "${CILIUM_IMAGE}" != "" && "${CILIUM_OPERATOR_IMAGE}" == "" ]]; then
        pull_image_and_push_to_local_registry ${CILIUM_IMAGE} ${CILIUM_REGISTRY} ${CILIUM_TAG}
				build_operator_image ${CILIUM_OPERATOR_LOCAL_BUILD_IMAGE} "${CILIUM_REGISTRY}/${CILIUM_OPERATOR_REMOTE_IMAGE}:${CILIUM_OPERATOR_TAG}"
        delete_cilium_pods
      elif [[ "${CILIUM_IMAGE}" == "" && "${CILIUM_OPERATOR_IMAGE}" != "" ]]; then
        pull_image_and_push_to_local_registry ${CILIUM_OPERATOR_IMAGE} ${CILIUM_REGISTRY} ${CILIUM_OPERATOR_TAG}
        build_cilium_image ${CILIUM_LOCAL_BUILD_IMAGE} "${CILIUM_REGISTRY}/${CILIUM_REMOTE_IMAGE}:${CILIUM__TAG}"
        delete_cilium_pods
      else
        pull_image_and_push_to_local_registry ${CILIUM_IMAGE} ${CILIUM_REGISTRY} ${CILIUM_TAG}
        pull_image_and_push_to_local_registry ${CILIUM_OPERATOR_IMAGE} ${CILIUM_REGISTRY} ${CILIUM_OPERATOR_TAG}
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
