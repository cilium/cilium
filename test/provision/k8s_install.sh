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

function install_etcd {
  wget -nv https://github.com/coreos/etcd/releases/download/${ETCD_VERSION}/etcd-${ETCD_VERSION}-linux-amd64.tar.gz
  tar -xf etcd-${ETCD_VERSION}-linux-amd64.tar.gz
  sudo mv etcd-${ETCD_VERSION}-linux-amd64/etcd* /usr/bin/

  sudo tee /etc/systemd/system/etcd.service <<EOF
[Unit]
Description=etcd
Documentation=https://github.com/coreos

[Service]
ExecStart=/usr/bin/etcd --name=cilium --data-dir=/var/etcd/cilium --advertise-client-urls=http://192.168.36.11:9732 --listen-client-urls=http://0.0.0.0:9732 --listen-peer-urls=http://0.0.0.0:9733
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl enable etcd
  sudo systemctl start etcd
}


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
  cat <<EOF > /etc/docker/daemon.json
{
  "insecure-registries" : ["k8s1:5000"]
}
EOF
  echo "restarting Docker"
  sudo service docker restart
  echo "done restarting Docker"

  install_etcd
  
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

  /tmp/provision/compile.sh
else
    cat <<EOF > /etc/docker/daemon.json
{
  "insecure-registries" : ["k8s1:5000"]
}
EOF
    echo "restarting Docker"
    sudo service docker restart
    echo "done restarting Docker"
    
    kubeadm join --token=$TOKEN 192.168.36.11:6443
    cp /etc/kubernetes/kubelet.conf ${CILIUM_CONFIG_DIR}/kubeconfig

    #certs_dir="/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/cluster/certs"
    #sudo mkdir -p /etc/docker/certs.d/192.168.36.11:5000
    #sudo cp ${certs_dir}/ca.pem /etc/docker/certs.d/192.168.36.11:5000/ca.crt
    #docker pull 192.168.36.11:5000/cilium:${DOCKER_IMAGE_TAG}
    #docker tag 192.168.36.11:5000/cilium:${DOCKER_IMAGE_TAG} cilium:${DOCKER_IMAGE_TAG}
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
