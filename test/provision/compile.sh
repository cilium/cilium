#!/usr/bin/env bash
set -e

export CILIUM_DS_TAG="k8s-app=cilium"
export KUBE_SYSTEM_NAMESPACE="kube-system"
export KUBECTL="/usr/bin/kubectl"
export VMUSER=${VMUSER:-vagrant}
export PROVISIONSRC=${PROVISIONSRC:-/tmp/provision}
export GOPATH="/home/${VMUSER}/go"
export REGISTRY="k8s1:5000"
export DOCKER_REGISTRY="docker.io"
export CILIUM_TAG="cilium/cilium-dev"
export CILIUM_OPERATOR_TAG="cilium/operator"
export CILIUM_OPERATOR_GENERIC_TAG="cilium/operator-generic"
export CILIUM_OPERATOR_AWS_TAG="cilium/operator-aws"
export CILIUM_OPERATOR_AZURE_TAG="cilium/operator-azure"
export HUBBLE_RELAY_TAG="cilium/hubble-relay"

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
        make LOCKDEBUG=1 docker-cilium-image
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
        make LOCKDEBUG=1 docker-operator-image
        echo "building cilium-operator-aws image..."
        make -B LOCKDEBUG=1 docker-operator-aws-image
        echo "building cilium-operator-azure image..."
        make -B LOCKDEBUG=1 docker-operator-azure-image
        echo "building cilium-operator-alibabacloud image..."
        make -B LOCKDEBUG=1 docker-operator-alibabacloud-image
        echo "building cilium-operator-generic image..."
        make -B LOCKDEBUG=1 docker-operator-generic-image
        echo "tagging cilium-operator images..."
        docker tag "${CILIUM_OPERATOR_TAG}" "${REGISTRY}/${CILIUM_OPERATOR_TAG}-ci"
        docker tag "${CILIUM_OPERATOR_AWS_TAG}" "${REGISTRY}/${CILIUM_OPERATOR_AWS_TAG}-ci"
        docker tag "${CILIUM_OPERATOR_AZURE_TAG}" "${REGISTRY}/${CILIUM_OPERATOR_AZURE_TAG}-ci"
        docker tag "${CILIUM_OPERATOR_GENERIC_TAG}" "${REGISTRY}/${CILIUM_OPERATOR_GENERIC_TAG}-ci"
        echo "pushing cilium/operator image to ${REGISTRY}/${CILIUM_OPERATOR_TAG}-ci..."
        docker push "${REGISTRY}/${CILIUM_OPERATOR_TAG}-ci"
        echo "pushing cilium/operator-aws image to ${REGISTRY}/${CILIUM_OPERATOR_AWS_TAG}-ci..."
        docker push "${REGISTRY}/${CILIUM_OPERATOR_AWS_TAG}-ci"
        echo "pushing cilium/operator-azure image to ${REGISTRY}/${CILIUM_OPERATOR_AZURE_TAG}-ci..."
        docker push "${REGISTRY}/${CILIUM_OPERATOR_AZURE_TAG}-ci"
        echo "pushing cilium/operator-generic image to ${REGISTRY}/${CILIUM_OPERATOR_GENERIC_TAG}-ci..."
        docker push "${REGISTRY}/${CILIUM_OPERATOR_GENERIC_TAG}-ci"
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
        make LOCKDEBUG=1 docker-hubble-relay-image
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

    # Download all images needed for k8s tests.
    ./test/provision/container-images.sh test_images test/k8s
else
    echo "Installing docker-plugin..."
    if [[ "${CILIUM_DOCKER_PLUGIN_IMAGE}" == "" ]]; then
      make -C plugins/cilium-docker
      sudo make -C plugins/cilium-docker install
    else
      ${PROVISIONSRC}/docker-run-cilium-docker-plugin.sh
    fi

    if [[ "${CILIUM_IMAGE}" == "" ]]; then
	export CILIUM_IMAGE=cilium/cilium:latest
	echo "Building Cilium..."
	make docker-cilium-image LOCKDEBUG=1
    fi
    sudo cp ${PROVISIONSRC}/docker-run-cilium.sh /usr/bin/docker-run-cilium

    sudo mkdir -p /etc/sysconfig/
    sed -e "s|CILIUM_IMAGE[^[:space:]]*$|CILIUM_IMAGE=${CILIUM_IMAGE}|" -e "s|HOME=/home/vagrant|HOME=/home/${VMUSER}|" contrib/systemd/cilium | sudo tee /etc/sysconfig/cilium

    sudo cp -f contrib/systemd/*.* /etc/systemd/system/
    # Use dockerized Cilium with runtime tests
    sudo cp -f contrib/systemd/cilium.service-with-docker /etc/systemd/system/cilium.service
    # Do not run cilium-operator with runtime tests, as it fails to connect to k8s api-server
    sudo rm -f /etc/systemd/system/cilium-operator.service

    services_pattern="cilium*.service"
    if ! mount | grep /sys/fs/bpf; then
	services_pattern+=" sys-fs-bpf.mount"
    fi
    services=$(cd /etc/systemd/system; ls -1 ${services_pattern})
    for service in ${services}; do
        echo "installing service $service"
        sudo systemctl enable $service || echo "service $service failed"
        sudo systemctl restart $service || echo "service $service failed to restart"
    done

    echo "running \"sudo adduser ${VMUSER} cilium\" "
    # Add group explicitly to avoid the case where the group was not added yet
    getent group cilium >/dev/null || sudo groupadd -r cilium
    sudo adduser ${VMUSER} cilium

    # Download all images needed for runtime tests.
    if [ -z "${SKIP_TEST_IMAGE_DOWNLOAD}" ]; then
	./test/provision/container-images.sh test_images test/helpers
    fi
fi
