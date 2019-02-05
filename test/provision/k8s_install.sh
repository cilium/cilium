#!/bin/bash

set -e
HOST=$(hostname)
export TOKEN="258062.5d84c017c9b2796c"
export CILIUM_CONFIG_DIR="/opt/cilium"
export PROVISIONSRC="/tmp/provision/"
export SRC_FOLDER="/home/vagrant/go/src/github.com/cilium/cilium"
export SYSTEMD_SERVICES="$SRC_FOLDER/contrib/systemd"
MOUNT_SYSTEMD="sys-fs-bpf.mount"

NODE=$1
IP=$2
K8S_VERSION=$3
IPv6=$4
CONTAINER_RUNTIME=$5
CNI_INTEGRATION=$6

# Kubeadm default parameters
export KUBEADM_ADDR='192.168.36.11'
export KUBEADM_POD_NETWORK='10.10.0.0'
export KUBEADM_POD_CIDR='16'
export KUBEADM_SVC_CIDR='10.96.0.0/12'
export KUBEADM_CRI_SOCKET="/var/run/dockershim.sock"
export KUBEADM_SLAVE_OPTIONS=""
export KUBEADM_OPTIONS=""
export K8S_FULL_VERSION=""
export DNS_DEPLOYMENT="${PROVISIONSRC}/manifest/dns_deployment.yaml"
export KUBEDNS_DEPLOYMENT="${PROVISIONSRC}/manifest/kubedns_deployment.yaml"
export COREDNS_DEPLOYMENT="${PROVISIONSRC}/manifest/${K8S_VERSION}/coredns_deployment.yaml"
if [ ! -f "${COREDNS_DEPLOYMENT}" ]; then
    export COREDNS_DEPLOYMENT="${PROVISIONSRC}/manifest/coredns_deployment.yaml"
fi

if [ "${CNI_INTEGRATION}" == "flannel" ]; then
    export KUBEADM_POD_NETWORK="10.244.0.0"
fi

source ${PROVISIONSRC}/helpers.bash

sudo bash -c "echo MaxSessions 200 >> /etc/ssh/sshd_config"
sudo systemctl restart ssh

# TODO: Check if the k8s version is the same
if [[ -f  "/etc/provision_finished" ]]; then
    sudo dpkg -l | grep kubelet
    echo "provision is finished, recompiling"
    /tmp/provision/compile.sh
    exit 0
fi

sudo ln -sf $KUBEDNS_DEPLOYMENT $DNS_DEPLOYMENT
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

KUBEADM_CONFIG_ALPHA1=$(cat <<-EOF
apiVersion: kubeadm.k8s.io/v1alpha1
kind: MasterConfiguration
api:
  advertiseAddress: "{{ .KUBEADM_ADDR }}"
criSocket: "{{ .KUBEADM_CRI_SOCKET }}"
kubernetesVersion: "v{{ .K8S_FULL_VERSION }}"
token: "{{ .TOKEN }}"
networking:
  podSubnet: "{{ .KUBEADM_POD_NETWORK }}/{{ .KUBEADM_POD_CIDR}}"
EOF
)

KUBEADM_CONFIG="${KUBEADM_CONFIG_ALPHA1}"

KUBEADM_CONFIG_ALPHA2=$(cat <<-EOF
apiVersion: kubeadm.k8s.io/v1alpha2
kind: MasterConfiguration
api:
  advertiseAddress: {{ .KUBEADM_ADDR }}
  bindPort: 6443
bootstrapTokens:
- groups:
  - system:bootstrappers:kubeadm:default-node-token
  token: "{{ .TOKEN }}"
kubernetesVersion: "v{{ .K8S_FULL_VERSION }}"
networking:
  dnsDomain: cluster.local
  podSubnet: "{{ .KUBEADM_POD_NETWORK }}/{{ .KUBEADM_POD_CIDR}}"
  serviceSubnet: "{{ .KUBEADM_SVC_CIDR }}"
nodeRegistration:
  criSocket: "{{ .KUBEADM_CRI_SOCKET }}"
EOF
)

KUBEADM_CONFIG_ALPHA3=$(cat <<-EOF
apiVersion: kubeadm.k8s.io/v1beta1
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: "{{ .KUBEADM_ADDR }}"
  bindPort: 6443
bootstrapTokens:
- groups:
  - system:bootstrappers:kubeadm:default-node-token
  token: {{ .TOKEN }}
  ttl: 24h0m0s
  usages:
  - signing
  - authentication
nodeRegistration:
  criSocket: "{{ .KUBEADM_CRI_SOCKET }}"
---
apiVersion: kubeadm.k8s.io/v1beta1
kind: ClusterConfiguration
kubernetesVersion: "v{{ .K8S_FULL_VERSION }}"
networking:
  dnsDomain: cluster.local
  podSubnet: "{{ .KUBEADM_POD_NETWORK }}/{{ .KUBEADM_POD_CIDR}}"
  serviceSubnet: "{{ .KUBEADM_SVC_CIDR }}"
EOF
)

# CRIO bridge disabled.
if [[ -f  "/etc/cni/net.d/100-crio-bridge.conf" ]]; then
    echo "Disabling crio CNI bridge"
    sudo rm -rfv /etc/cni/net.d/100-crio-bridge.conf
    sudo rm -rfv /etc/cni/net.d/200-loopback.conf || true
fi

# Around the `--ignore-preflight-errors=cri` is used because
# /var/run/dockershim.sock is not present (because base image has containerd)
# so with that option kubeadm fallback to /var/run/docker.sock
case $K8S_VERSION in
    "1.8")
        KUBERNETES_CNI_VERSION="0.5.1"
        K8S_FULL_VERSION="1.8.14"
        KUBEADM_OPTIONS="--skip-preflight-checks"
        KUBEADM_SLAVE_OPTIONS="--skip-preflight-checks"
        ;;
    "1.9")
        KUBERNETES_CNI_VERSION="0.6.0"
        K8S_FULL_VERSION="1.9.11"
        KUBEADM_SLAVE_OPTIONS="--discovery-token-unsafe-skip-ca-verification --ignore-preflight-errors=cri,SystemVerification"
        KUBEADM_OPTIONS="--ignore-preflight-errors=cri,SystemVerification"
        ;;
    "1.10")
        KUBERNETES_CNI_VERSION="0.6.0"
        K8S_FULL_VERSION="1.10.12"
        KUBEADM_SLAVE_OPTIONS="--discovery-token-unsafe-skip-ca-verification --ignore-preflight-errors=cri,SystemVerification"
        KUBEADM_OPTIONS="--ignore-preflight-errors=cri,SystemVerification"
        ;;
    "1.11")
        KUBERNETES_CNI_VERSION="0.6.0"
        K8S_FULL_VERSION="1.11.7"
        KUBEADM_OPTIONS="--ignore-preflight-errors=cri,FileExisting-crictl,SystemVerification"
        KUBEADM_SLAVE_OPTIONS="--discovery-token-unsafe-skip-ca-verification --ignore-preflight-errors=cri,FileExisting-crictl,SystemVerification"
        sudo ln -sf $COREDNS_DEPLOYMENT $DNS_DEPLOYMENT
        ;;
    "1.12")
        KUBERNETES_CNI_VERSION="0.6.0"
        K8S_FULL_VERSION="1.12.5"
        KUBEADM_OPTIONS="--ignore-preflight-errors=cri,SystemVerification"
        KUBEADM_SLAVE_OPTIONS="--discovery-token-unsafe-skip-ca-verification --ignore-preflight-errors=cri,SystemVerification"
        sudo ln -sf $COREDNS_DEPLOYMENT $DNS_DEPLOYMENT
        KUBEADM_CONFIG="${KUBEADM_CONFIG_ALPHA2}"
        ;;
    "1.13")
        KUBERNETES_CNI_VERSION="0.6.0"
        K8S_FULL_VERSION="1.13.3"
        KUBEADM_OPTIONS="--ignore-preflight-errors=cri"
        KUBEADM_SLAVE_OPTIONS="--discovery-token-unsafe-skip-ca-verification --ignore-preflight-errors=cri,SystemVerification"
        sudo ln -sf $COREDNS_DEPLOYMENT $DNS_DEPLOYMENT
        KUBEADM_CONFIG="${KUBEADM_CONFIG_ALPHA3}"
        ;;
esac

#Install kubernetes
case $K8S_VERSION in
    "1.8"|"1.9"|"1.10"|"1.11"|"1.12"|"1.13")
        install_k8s_using_packages \
            kubernetes-cni=${KUBERNETES_CNI_VERSION}* \
            kubelet=${K8S_FULL_VERSION}* \
            kubeadm=${K8S_FULL_VERSION}* \
            kubectl=${K8S_FULL_VERSION}*
        ;;
#    "1.13")
#        install_k8s_using_binary "v${K8S_FULL_VERSION}" "v${KUBERNETES_CNI_VERSION}"
#        ;;
esac

case $CONTAINER_RUNTIME in
    "docker")
        ;;
    "containerd")
        KUBEADM_CRI_SOCKET="unix:///var/run/cri-containerd.sock"
        ;;
    *)
        echo "Invalid container runtime '${CONTAINER_RUNTIME}'"
esac

if [ "${IPv6}" -eq "1" ]; then
    KUBEADM_ADDR='[fd04::11]'
    KUBEADM_POD_NETWORK="fd02::"
    KUBEADM_POD_CIDR="112"
    KUBEADM_SVC_CIDR="fd03::/112"
fi

sudo mkdir -p ${CILIUM_CONFIG_DIR}

sudo cp "$SYSTEMD_SERVICES/$MOUNT_SYSTEMD" /etc/systemd/system/
sudo systemctl enable $MOUNT_SYSTEMD
sudo systemctl restart $MOUNT_SYSTEMD
sudo rm -rfv /var/lib/kubelet

# Allow iptables forwarding so kube-dns can function.
sudo iptables --policy FORWARD ACCEPT

#check hostname to know if is kubernetes or runtime test
if [[ "${HOST}" == "k8s1" ]]; then

    echo "${KUBEADM_CONFIG}" | envtpl > /tmp/config.yaml

    sudo kubeadm init  --config /tmp/config.yaml $KUBEADM_OPTIONS

    mkdir -p /root/.kube
    sudo cp -i /etc/kubernetes/admin.conf /root/.kube/config
    sudo chown root:root /root/.kube/config

    sudo -u vagrant mkdir -p /home/vagrant/.kube
    sudo cp -fi /etc/kubernetes/admin.conf /home/vagrant/.kube/config
    sudo chown vagrant:vagrant /home/vagrant/.kube/config

    sudo cp -f /etc/kubernetes/admin.conf ${CILIUM_CONFIG_DIR}/kubeconfig
    kubectl taint nodes --all node-role.kubernetes.io/master-

    sudo systemctl start etcd

    # Install custom DNS deployment
    kubectl -n kube-system delete -f ${PROVISIONSRC}/manifest/dns_deployment.yaml || true
    kubectl -n kube-system apply -f ${PROVISIONSRC}/manifest/dns_deployment.yaml

    $PROVISIONSRC/compile.sh
else
    kubeadm join --token=$TOKEN ${KUBEADM_ADDR}:6443 \
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

# Create world network
docker network create --subnet=192.168.9.0/24 outside
docker run --net outside --ip 192.168.9.10 --restart=always -d docker.io/cilium/demo-httpd:latest
docker run --net outside --ip 192.168.9.11 --restart=always -d docker.io/cilium/demo-httpd:latest

#Preload the ip6tables table we need
sudo modprobe ip6table_mangle

sudo touch /etc/provision_finished
