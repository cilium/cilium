#!/usr/bin/env bash

### enable debug

set -e

### User Setting

KUBERNETES_VERSION=v1.31
KIND_VERSION=v0.19.0
CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
CLI_ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi

### Functions Implementation

function confirmation_prompt() {
    echo "-------------------------------------------------------------------"
    echo "This will install kubernetes, kind and cilium-cli packages."
    echo "*** Basically this needs to be done only once on devcontainer image creation ***"
    echo "-------------------------------------------------------------------"

    while true; do
        read -p "Do you want to proceed? (yes/no) " yn
        case $yn in
            yes ) echo OK, we will proceed;
                break;;
            no ) echo exiting...;
                exit;;
            * ) echo invalid response;
        esac
    done
}

function exit_trap() {
    if [ $? != 0 ]; then
        echo "Command [$BASH_COMMAND] is failed"
        exit 1
    fi
}

function check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        echo "Please run this script with sudo."
        exit 1
    fi
}

function command_exist() {
    trap exit_trap ERR
    echo "[${FUNCNAME[0]}]: checking $1 command exists."
    if command -v "$1" >/dev/null 2>&1; then
        echo "$1 exists."
    else
        echo "Error: $1 not found."
        exit 1
    fi
}

function install_kubernetes () {
    trap exit_trap ERR
    apt install -y apt-transport-https ca-certificates curl
    curl -fsSL https://pkgs.k8s.io/core:/stable:/${KUBERNETES_VERSION}/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${KUBERNETES_VERSION}/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list
    apt-get update
    apt-get install -y kubelet kubeadm kubectl
    apt-mark hold kubelet kubeadm kubectl
    command_exist kubeadm
    kubeadm version
    command_exist kubectl
    kubectl version --client
}

function install_kind () {
    trap exit_trap ERR
    go install sigs.k8s.io/kind@${KIND_VERSION}
    command_exist kind
    kind version
}

function install_ciliumcli () {
    echo $CILIUM_CLI_VERSION
    echo $CLI_ARCH
    curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
    sha256sum --check cilium-linux-${CLI_ARCH}.tar.gz.sha256sum
    tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
    rm cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
    command_exist cilium
    cilium version
}

### Main

trap exit_trap ERR

confirmation_prompt

check_sudo
apt-get update

echo "Install Kubernetes ----------"
install_kubernetes

echo "Install Clium-CLI ----------"
install_ciliumcli

echo "Install KIND ----------"
install_kind

echo "Installation completed, enjoy your cilium devcontainer !!!"

exit 0
