#!/usr/bin/env bash

function log_msg {
  MSG="$1"
  echo "***************************************"
  echo "*"
  echo "*"
  echo "* ${MSG}"
  echo "*"
  echo "*"
  echo "***************************************"
}

function retry_function {
  set +e
  FUNC="$1"
  COUNTER=0
  MAX_TRIES=10
  echo "beginning trying up to ${MAX_TRIES} times function \"${FUNC}\""
  while [ $COUNTER -lt $MAX_TRIES ]; do
    log_msg "on attempt ${COUNTER} of function \"${FUNC}\""
    ${FUNC}
    if [[ "$?" == "0" ]] ; then
      echo "running of \"${FUNC}\" successful"
      echo
      echo
      echo
      set -e
      return 0
    fi
    sleep 1
    let COUNTER=COUNTER+1
  done

  log_msg "running function \"${FUNC}\" ${MAX_TRIES} times did not succeed"
  set -e
  return 1
}

function install_using_apt {
    apt-get update
    apt-get install --allow-downgrades -y \
        "$@"
}

function install_k8s_using_packages {
    install_using_apt "$@"
}

function install_k8s_using_binary {
    local RELEASE=$1
    local CNI_VERSION=$2
    cd $(mktemp -d)

    mkdir -p /opt/cni/bin
    mkdir -p /etc/systemd/system/kubelet.service.d

    curl -sSL "https://github.com/containernetworking/plugins/releases/download/${CNI_VERSION}/cni-plugins-amd64-${CNI_VERSION}.tgz" | tar -C /opt/cni/bin -xz

    wget -q https://storage.googleapis.com/kubernetes-release/release/$RELEASE/bin/linux/amd64/{kubectl,kubeadm,kubelet}
    chmod 777 ku*
    cp -fv ku* /usr/bin/
    rm -rf /etc/systemd/system/kubelet.service || true
    curl -sSL https://raw.githubusercontent.com/kubernetes/kubernetes/${RELEASE}/build/debs/kubelet.service > /etc/systemd/system/kubelet.service


    curl -sSL "https://raw.githubusercontent.com/kubernetes/kubernetes/${RELEASE}/build/debs/10-kubeadm.conf" > /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
    systemctl enable kubelet
}

function pull_image_and_push_to_local_registry {
  local IMG=$1
  local REGISTRY=$2
  local TAG_NAME=$3

  local TAG_WITH_REG="${REGISTRY}/${TAG_NAME}"

  echo "pulling ${IMG}..."
  docker pull "${IMG}"
  echo "done pulling ${IMG}"

  echo "tagging ${IMG} with tag ${TAG_WITH_REG}"
  docker tag "${IMG}" ${TAG_WITH_REG}
  echo "done tagging ${IMG} with tag ${TAG_WITH_REG}"

  echo "pushing ${TAG_WITH_REG}"
  docker push ${TAG_WITH_REG}
  echo "done pushing ${TAG_WITH_REG}"
}

function build_cilium_image {
  echo "building cilium image..."
  make LOCKDEBUG=1 docker-image-no-clean
  echo "tagging cilium image..."
  docker tag cilium/cilium k8s1:5000/cilium/cilium-dev
  echo "pushing cilium image..."
  docker push k8s1:5000/cilium/cilium-dev
}

function build_operator_image {
  # build cilium-operator image
  echo "building cilium-operator image..."
  make LOCKDEBUG=1 docker-operator-image
  echo "tagging cilium-operator image..."
  docker tag cilium/operator k8s1:5000/cilium/operator
  echo "pushing cilium-operator image..."
  docker push k8s1:5000/cilium/operator
}
