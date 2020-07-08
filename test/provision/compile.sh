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
CILIUM_OPERATOR_GENERIC_TAG="cilium/operator-generic"
CILIUM_OPERATOR_AWS_TAG="cilium/operator-aws"
CILIUM_OPERATOR_AZURE_TAG="cilium/operator-azure"
HUBBLE_RELAY_TAG="cilium/hubble-relay"

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
    if [[ "$(hostname)" == "k8s1" && "${CILIUM_REGISTRY}" == "" ]]; then
      ./test/provision/container-images.sh cilium_images .

      if [[ "${CILIUM_IMAGE}" == "" ]]; then
        echo "building cilium container image..."
        DOCKER_BUILDKIT=1 make LOCKDEBUG=1 docker-cilium-image
        echo "tagging cilium image..."
        docker tag cilium/cilium "${REGISTRY}/${CILIUM_TAG}"
        echo "pushing cilium image to ${REGISTRY}/${CILIUM_TAG}..."
        docker push "${REGISTRY}/${CILIUM_TAG}"
        echo "removing local cilium image..."
        docker rmi cilium/cilium:latest
      else
        pull_image_and_push_to_local_registry "${CILIUM_IMAGE}" "${REGISTRY}" "${CILIUM_TAG}"
      fi

      if [[ "${CILIUM_OPERATOR_IMAGE}" == "" ]]; then
        echo "building cilium-operator image..."
        DOCKER_BUILDKIT=1 make LOCKDEBUG=1 docker-operator-image
        echo "building cilium-operator-aws image..."
        DOCKER_BUILDKIT=1 make -B LOCKDEBUG=1 docker-operator-aws-image
        echo "building cilium-operator-azure image..."
        DOCKER_BUILDKIT=1 make -B LOCKDEBUG=1 docker-operator-azure-image
        echo "building cilium-operator-generic image..."
        DOCKER_BUILDKIT=1 make -B LOCKDEBUG=1 docker-operator-generic-image
        echo "tagging cilium-operator images..."
        docker tag "${CILIUM_OPERATOR_TAG}" "${REGISTRY}/${CILIUM_OPERATOR_TAG}"
        docker tag "${CILIUM_OPERATOR_AWS_TAG}" "${REGISTRY}/${CILIUM_OPERATOR_AWS_TAG}"
        docker tag "${CILIUM_OPERATOR_AZURE_TAG}" "${REGISTRY}/${CILIUM_OPERATOR_AZURE_TAG}"
        docker tag "${CILIUM_OPERATOR_GENERIC_TAG}" "${REGISTRY}/${CILIUM_OPERATOR_GENERIC_TAG}"
        echo "pushing cilium/operator image to ${REGISTRY}/${CILIUM_OPERATOR_TAG}..."
        docker push "${REGISTRY}/${CILIUM_OPERATOR_TAG}"
        echo "pushing cilium/operator-aws image to ${REGISTRY}/${CILIUM_OPERATOR_AWS_TAG}..."
        docker push "${REGISTRY}/${CILIUM_OPERATOR_AWS_TAG}"
        echo "pushing cilium/operator-azure image to ${REGISTRY}/${CILIUM_OPERATOR_AZURE_TAG}..."
        docker push "${REGISTRY}/${CILIUM_OPERATOR_AZURE_TAG}"
        echo "pushing cilium/operator-generic image to ${REGISTRY}/${CILIUM_OPERATOR_GENERIC_TAG}..."
        docker push "${REGISTRY}/${CILIUM_OPERATOR_GENERIC_TAG}"
        echo "removing local cilium-operator image..."
        docker rmi "${CILIUM_OPERATOR_TAG}:latest"
        echo "removing local cilium-operator image..."
        docker rmi "${CILIUM_OPERATOR_AWS_TAG}:latest"
        echo "removing local cilium-operator image..."
        docker rmi "${CILIUM_OPERATOR_AZURE_TAG}:latest"
        echo "removing local cilium-operator image..."
        docker rmi "${CILIUM_OPERATOR_GENERIC_TAG}:latest"
      else
        pull_image_and_push_to_local_registry "${CILIUM_OPERATOR_IMAGE}" "${REGISTRY}" "${CILIUM_OPERATOR_TAG}"
      fi

      delete_cilium_pods

      if [[ "${HUBBLE_RELAY_IMAGE}" == "" ]]; then
        echo "building hubble-relay image..."
        DOCKER_BUILDKIT=1 make LOCKDEBUG=1 docker-hubble-relay-image
        echo "tagging hubble-relay image..."
        docker tag ${HUBBLE_RELAY_TAG} ${REGISTRY}/${HUBBLE_RELAY_TAG}
        echo "pushing hubble-relay image to ${REGISTRY}/${HUBBLE_RELAY_TAG}..."
        docker push ${REGISTRY}/${HUBBLE_RELAY_TAG}
        echo "removing local hubble-relay image..."
        docker rmi "${HUBBLE_RELAY_TAG}:latest"
      else
        pull_image_and_push_to_local_registry "${HUBBLE_RELAY_IMAGE}" "${REGISTRY}" "${HUBBLE_RELAY_TAG}"
      fi

    elif [[ "$(hostname)" == "k8s1" && "${CILIUM_REGISTRY}" != "" ]]; then
		if [[ ${CILIUM_IMAGE} != "" ]]; then
			pull_image_and_push_to_local_registry "${CILIUM_REGISTRY}/${CILIUM_IMAGE}" "${REGISTRY}" "${CILIUM_TAG}"
		fi
		if [[ ${CILIUM_OPERATOR_IMAGE} != "" ]]; then
			pull_image_and_push_to_local_registry "${CILIUM_REGISTRY}/${CILIUM_OPERATOR_IMAGE}" "${REGISTRY}" "${CILIUM_OPERATOR_TAG}"
		fi
		if [[ ${HUBBLE_RELAY_IMAGE} != "" ]]; then
			pull_image_and_push_to_local_registry "${CILIUM_REGISTRY}/${HUBBLE_RELAY_IMAGE}" "${REGISTRY}" "${HUBBLE_RELAY_TAG}"
		fi
    else
        echo "Not on master K8S node; no need to compile Cilium container"
    fi
else
    echo "compiling cilium..."
    sudo -u vagrant -H -E make LOCKDEBUG=1 SKIP_K8S_CODE_GEN_CHECK=false SKIP_DOCS=true
    echo "installing cilium..."
    make install
    mkdir -p /etc/sysconfig/
    cp -f contrib/systemd/cilium /etc/sysconfig/cilium
    services=$(ls -1 ./contrib/systemd/*.*)
    for svc in ${services}; do
        cp -f "${svc}" /etc/systemd/system/
    done
    for svc in ${services}; do
        service=$(echo "$svc" | sed -E -n 's/.*\/(.*?).(service|mount)/\1.\2/p')
        if [ -n "$service" ] ; then
          echo "installing service $service"
          systemctl enable $service || echo "service $service failed"
          systemctl restart $service || echo "service $service failed to restart"
        fi
    done
    echo "running \"sudo adduser vagrant cilium\" "
    sudo adduser vagrant cilium
fi

# Download all images needed for tests.
./test/provision/container-images.sh test_images .
