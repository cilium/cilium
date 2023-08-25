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
    local OS=$3
    cd $(mktemp -d)

    mkdir -p /opt/cni/bin
    mkdir -p /etc/systemd/system/kubelet.service.d

    if [[ -n "$CNI_VERSION" ]]; then
    	curl -sSL "https://github.com/containernetworking/plugins/releases/download/${CNI_VERSION}/cni-plugins${OS}-amd64-${CNI_VERSION}.tgz" | tar -C /opt/cni/bin -xz
    fi

    wget -q https://storage.googleapis.com/kubernetes-release/release/${RELEASE}/bin/linux/amd64/{kubectl,kubeadm,kubelet}
    chmod 777 ku*
    cp -fv ku* /usr/bin/
    rm -rf /etc/systemd/system/kubelet.service || true

    # github.com/kubernetes/release is the canonical location for deb/rpm build definitions/specs.
    curl -sSL "https://raw.githubusercontent.com/kubernetes/release/v0.6.0/cmd/kubepkg/templates/latest/deb/kubelet/lib/systemd/system/kubelet.service" \
      > /etc/systemd/system/kubelet.service


    curl -sSL "https://raw.githubusercontent.com/kubernetes/release/v0.6.0/cmd/kubepkg/templates/latest/deb/kubeadm/10-kubeadm.conf" \
        > /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
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
  docker tag "${IMG}" "${TAG_WITH_REG}"
  echo "done tagging ${IMG} with tag ${TAG_WITH_REG}"

  echo "pushing ${TAG_WITH_REG}"
  docker push "${TAG_WITH_REG}"
  echo "done pushing ${TAG_WITH_REG}"
}
