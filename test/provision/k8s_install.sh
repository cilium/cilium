#!/bin/bash

set -e
HOST=$(hostname)
TOKEN="258062.5d84c017c9b2796c"
CILIUM_CONFIG_DIR="/opt/cilium"
ETCD_VERSION="v3.1.0"
NODE=$1
IP=$2
K8S_VERSION=$3
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

if [[ -f  "/etc/provision_finished" ]]; then
    sudo dpkg -l | grep kubelet
    echo "provision is finished, recompiling"
    /tmp/provision/compile.sh
    exit 0
fi

cat <<EOF > /etc/hosts
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
192.168.36.11 k8s1
192.168.36.12 k8s2
EOF

cat <<EOF > /etc/apt/sources.list.d/kubernetes.list
deb http://apt.kubernetes.io/ kubernetes-xenial main
EOF

sudo rm /var/lib/apt/lists/lock
wget https://packages.cloud.google.com/apt/doc/apt-key.gpg
apt-key add apt-key.gpg

apt-get update
apt-get install --allow-downgrades -y \
    llvm \
    kubernetes-cni \
    kubelet="${K8S_VERSION}*" \
    kubeadm="${K8S_VERSION}*" \
    kubectl="${K8S_VERSION}*"


sudo mkdir -p ${CILIUM_CONFIG_DIR}

sudo mount bpffs /sys/fs/bpf -t bpf
sudo rm -rfv /var/lib/kubelet

#check hostname to know if is kubernetes or runtime test
if [[ "${HOST}" == "k8s1" ]]; then
    # FIXME: IP needs to be dynamic
    kubeadm init --token=$TOKEN --apiserver-advertise-address="192.168.36.11" --pod-network-cidr=10.10.0.0/16

    mkdir -p /root/.kube
    sudo cp -i /etc/kubernetes/admin.conf /root/.kube/config
    sudo chown root:root /root/.kube/config

    sudo -u vagrant mkdir -p /home/vagrant/.kube
    sudo cp -i /etc/kubernetes/admin.conf /home/vagrant/.kube/config
    sudo chown vagrant:vagrant /home/vagrant/.kube/config

    sudo cp /etc/kubernetes/admin.conf ${CILIUM_CONFIG_DIR}/kubeconfig
    kubectl taint nodes --all node-role.kubernetes.io/master-

    sudo systemctl start etcd
    /tmp/provision/compile.sh
else
    kubeadm join --token=$TOKEN 192.168.36.11:6443
    cp /etc/kubernetes/kubelet.conf ${CILIUM_CONFIG_DIR}/kubeconfig
    sudo systemctl stop etcd
    docker pull k8s1:5000/cilium/cilium-dev:latest
fi

sudo touch /etc/provision_finished
