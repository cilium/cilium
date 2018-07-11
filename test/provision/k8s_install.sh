#!/bin/bash

set -e
HOST=$(hostname)
TOKEN="258062.5d84c017c9b2796c"
CILIUM_CONFIG_DIR="/opt/cilium"
PROVISIONSRC="/tmp/provision/"
SRC_FOLDER="/home/vagrant/go/src/github.com/cilium/cilium"
SYSTEMD_SERVICES="$SRC_FOLDER/contrib/systemd"
MOUNT_SYSTEMD="sys-fs-bpf.mount"

NODE=$1
IP=$2
K8S_VERSION=$3
IPv6=$4
CONTAINER_RUNTIME=$5

# Kubeadm default parameters
export KUBEADM_ADDR='192.168.36.11'
export KUBEADM_POD_NETWORK='10.10.0.0'
export KUBEADM_POD_CIDR='16'
export KUBEADM_CRI_SOCKET="/var/run/dockershim.sock"
export KUBEADM_SLAVE_OPTIONS=""
export KUBEADM_OPTIONS=""
export K8S_FULL_VERSION=""
export INSTALL_KUBEDNS=1

source ${PROVISIONSRC}/helpers.bash

# TODO: Check if the k8s version is the same

if [[ -f  "/etc/provision_finished" ]]; then
    sudo dpkg -l | grep kubelet
    echo "provision is finished, recompiling"
    /tmp/provision/compile.sh
    exit 0
fi

$PROVISIONSRC/dns.sh

cat <<EOF > /etc/hosts
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
192.168.36.11 k8s1
192.168.36.12 k8s2
192.168.36.13 k8s3
192.168.36.14 k8s4
192.168.36.15 k8s5
192.168.36.16 k8s6
EOF

cat <<EOF > /etc/apt/sources.list.d/kubernetes.list
deb http://apt.kubernetes.io/ kubernetes-xenial main
EOF

sudo rm /var/lib/apt/lists/lock || true
retry_function "wget https://packages.cloud.google.com/apt/doc/apt-key.gpg"
apt-key add apt-key.gpg

KUBEADM_SLAVE_OPTIONS=""
KUBEADM_OPTIONS=""

case $K8S_VERSION in
    "1.7")
        KUBERNETES_CNI_VERSION="0.5.1-00"
        K8S_FULL_VERSION="1.7.15"
        ;;
    "1.8")
        KUBERNETES_CNI_VERSION="0.5.1-00"
        K8S_FULL_VERSION="1.8.13"
        ;;
    "1.9")
        KUBERNETES_CNI_VERSION="0.6.0-00"
        K8S_FULL_VERSION="1.9.8"
        KUBEADM_SLAVE_OPTIONS="--discovery-token-unsafe-skip-ca-verification --ignore-preflight-errors=cri"
        KUBEADM_OPTIONS="--ignore-preflight-errors=cri"
        ;;
    "1.10")
        KUBERNETES_CNI_VERSION="0.6.0-00"
        K8S_FULL_VERSION="1.10.3"
        KUBEADM_SLAVE_OPTIONS="--discovery-token-unsafe-skip-ca-verification --ignore-preflight-errors=cri"
        KUBEADM_OPTIONS="--ignore-preflight-errors=cri"
        ;;
    "1.11")
        KUBERNETES_CNI_VERSION="v0.6.0"
        K8S_FULL_VERSION="1.11.0-beta.0"
        KUBEADM_OPTIONS="--ignore-preflight-errors=cri"
        KUBEADM_SLAVE_OPTIONS="--discovery-token-unsafe-skip-ca-verification --ignore-preflight-errors=cri"
        ;;
    "1.12")
        KUBERNETES_CNI_VERSION="v0.6.0"
        K8S_FULL_VERSION="1.12.0-alpha.0"
        KUBEADM_OPTIONS="--ignore-preflight-errors=cri"
        KUBEADM_SLAVE_OPTIONS="--discovery-token-unsafe-skip-ca-verification --ignore-preflight-errors=cri"
        INSTALL_KUBEDNS=0
        ;;
esac

#Install kubernetes
case $K8S_VERSION in
    "1.7"|"1.8"|"1.9"|"1.10")
        install_k8s_using_packages \
            kubernetes-cni=${KUBERNETES_CNI_VERSION} \
            kubelet=${K8S_FULL_VERSION}* \
            kubeadm=${K8S_FULL_VERSION}* \
            kubectl=${K8S_FULL_VERSION}*
        ;;
    "1.11"|"1.12")
        install_k8s_using_binary "v${K8S_FULL_VERSION}" "${KUBERNETES_CNI_VERSION}"
        ;;
esac

sudo mkdir -p ${CILIUM_CONFIG_DIR}

sudo cp "$SYSTEMD_SERVICES/$MOUNT_SYSTEMD" /etc/systemd/system/
sudo systemctl enable $MOUNT_SYSTEMD
sudo systemctl restart $MOUNT_SYSTEMD
sudo rm -rfv /var/lib/kubelet

# Allow iptables forwarding so kube-dns can function.
sudo iptables --policy FORWARD ACCEPT

#check hostname to know if is kubernetes or runtime test
if [[ "${HOST}" == "k8s1" ]]; then
    sudo kubeadm init --token=$TOKEN \
        --apiserver-advertise-address="192.168.36.11" \
        --pod-network-cidr=10.10.0.0/16 \
        ${KUBEADM_OPTIONS}

    mkdir -p /root/.kube
    sudo cp -i /etc/kubernetes/admin.conf /root/.kube/config
    sudo chown root:root /root/.kube/config

    sudo -u vagrant mkdir -p /home/vagrant/.kube
    sudo cp -i /etc/kubernetes/admin.conf /home/vagrant/.kube/config
    sudo chown vagrant:vagrant /home/vagrant/.kube/config

    sudo cp /etc/kubernetes/admin.conf ${CILIUM_CONFIG_DIR}/kubeconfig
    kubectl taint nodes --all node-role.kubernetes.io/master-

    sudo systemctl start etcd

    kubectl -n kube-system delete svc,deployment,sa,cm kube-dns || true
    kubectl -n kube-system apply -f ${PROVISIONSRC}/manifest/dns_deployment.yaml

    $PROVISIONSRC/compile.sh
else
    kubeadm join --token=$TOKEN 192.168.36.11:6443 \
        ${KUBEADM_SLAVE_OPTIONS}
    sudo systemctl stop etcd
    docker pull k8s1:5000/cilium/cilium-dev:latest
    # We need this workaround since kube-proxy is not aware of multiple network
    # interfaces. If we send a packet to a service IP that packet is sent
    # to the default route, because the service IP is unknown by the linux routing
    # table, with the source IP of the interface in the default routing table, even
    # though the service IP should be routed to a different interface.
    # This particular workaround is only needed for cilium, running on a pod on host
    # network namespace, to reach out kube-api-server.
    sudo iptables -t nat -A POSTROUTING -o enp0s8 ! -s 192.168.36.12 -j MASQUERADE
fi

sudo touch /etc/provision_finished
