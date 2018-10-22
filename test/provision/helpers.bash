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
