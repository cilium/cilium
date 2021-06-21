#!/bin/bash

set -e

if ! [[ -z $DOCKER_LOGIN && -z $DOCKER_PASSWORD ]]; then
    echo "${DOCKER_PASSWORD}" | docker login -u "${DOCKER_LOGIN}" --password-stdin
fi

HOST=$(hostname)
export HELM_VERSION="3.3.4"
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

# Kubeadm default parameters
export KUBEADM_ADDR='192.168.36.11'
export KUBEADM_POD_CIDR='10.10.0.0/16'
export KUBEADM_V1BETA2_POD_CIDR='10.10.0.0/16,fd02::/112'
export KUBEADM_SVC_CIDR='10.96.0.0/12'
export KUBEADM_V1BETA2_SVC_CIDR='10.96.0.0/12,fd03::/112'
export IPV6_DUAL_STACK_FEATURE_GATE='true'
export KUBEADM_CRI_SOCKET="/var/run/dockershim.sock"
export KUBEADM_SLAVE_OPTIONS=""
export KUBEADM_OPTIONS=""
export K8S_FULL_VERSION=""
export CONTROLLER_FEATURE_GATES=""
export API_SERVER_FEATURE_GATES=""
export DNS_DEPLOYMENT="${PROVISIONSRC}/manifest/dns_deployment.yaml"
export KUBEDNS_DEPLOYMENT="${PROVISIONSRC}/manifest/kubedns_deployment.yaml"
export COREDNS_DEPLOYMENT="${PROVISIONSRC}/manifest/${K8S_VERSION}/coredns_deployment.yaml"
if [ ! -f "${COREDNS_DEPLOYMENT}" ]; then
    export COREDNS_DEPLOYMENT="${PROVISIONSRC}/manifest/coredns_deployment.yaml"
fi

source ${PROVISIONSRC}/helpers.bash

sudo bash -c "echo MaxSessions 200 >> /etc/ssh/sshd_config"
sudo systemctl restart ssh

if [[ ! $(helm version | grep ${HELM_VERSION}) ]]; then
  HELM_TAR=helm-v${HELM_VERSION}-linux-amd64.tar.gz
  retry_function "wget -nv https://get.helm.sh/$HELM_TAR"
  tar xzvf $HELM_TAR
  mv linux-amd64/helm /usr/local/bin/
  rm -rf linux-amd64 $HELM_TAR
fi
helm version

# Install serial ttyS0 server
cat <<EOF > /etc/systemd/system/serial-getty@ttyS0.service
[Service]
ExecStart=
ExecStart=/sbin/agetty --autologin root -8 --keep-baud 115200,38400,9600 ttyS0 \$TERM
EOF

systemctl daemon-reload
sudo service serial-getty@ttyS0 start

# TODO: Check if the k8s version is the same
if [[ -f  "/etc/provision_finished" ]]; then
    echo "Checking that kubelet exists in path"
    which kubelet
    echo "provision is finished, recompiling"
    $PROVISIONSRC/compile.sh
    exit 0
fi

sudo ln -sf $KUBEDNS_DEPLOYMENT $DNS_DEPLOYMENT
$PROVISIONSRC/dns.sh

cat <<EOF >> /etc/hosts
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

# Configure default IPv6 route without this connectivity from host to
# services is not possible as there is no default route. enp0s8 is the primary
# interface for test environment.
sudo ip -6 route add default dev enp0s8

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
  podSubnet: "{{ .KUBEADM_POD_CIDR }}"
controlPlaneEndpoint: "k8s1:6443"
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
  podSubnet: "{{ .KUBEADM_POD_CIDR }}"
  serviceSubnet: "{{ .KUBEADM_SVC_CIDR }}"
nodeRegistration:
  criSocket: "{{ .KUBEADM_CRI_SOCKET }}"
controlPlaneEndpoint: "k8s1:6443"
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
  podSubnet: "{{ .KUBEADM_POD_CIDR }}"
  serviceSubnet: "{{ .KUBEADM_SVC_CIDR }}"
controlPlaneEndpoint: "k8s1:6443"
controllerManager:
  extraArgs:
    "feature-gates": "{{ .CONTROLLER_FEATURE_GATES }}"
apiServer:
  extraArgs:
    "feature-gates": "{{ .API_SERVER_FEATURE_GATES }}"
EOF
)

# V1BETA2 configuration is enabled with DualStack feature gate by default.
# IPv6 only clusters can still be opted by setting IPv6 variable to 1.
KUBEADM_CONFIG_V1BETA2=$(cat <<-EOF
apiVersion: kubeadm.k8s.io/v1beta2
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
apiVersion: kubeadm.k8s.io/v1beta2
kind: ClusterConfiguration
kubernetesVersion: "v{{ .K8S_FULL_VERSION }}"
featureGates:
  IPv6DualStack: {{ .IPV6_DUAL_STACK_FEATURE_GATE }}
networking:
  dnsDomain: cluster.local
  podSubnet: "{{ .KUBEADM_V1BETA2_POD_CIDR }}"
  serviceSubnet: "{{ .KUBEADM_V1BETA2_SVC_CIDR }}"
controlPlaneEndpoint: "k8s1:6443"
controllerManager:
  extraArgs:
    "node-cidr-mask-size-ipv6": "120"
    "feature-gates": "{{ .CONTROLLER_FEATURE_GATES }},IPv6DualStack={{ .IPV6_DUAL_STACK_FEATURE_GATE }}"
apiServer:
  extraArgs:
    "feature-gates": "{{ .API_SERVER_FEATURE_GATES }},IPv6DualStack={{ .IPV6_DUAL_STACK_FEATURE_GATE }}"
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
#
# SystemVerification errors are ignored as net-next VM often triggers them, eg:
#     [ERROR SystemVerification]: unsupported kernel release: 5.0.0-rc6+
case $K8S_VERSION in
    "1.16")
        KUBERNETES_CNI_VERSION="0.7.5"
        K8S_FULL_VERSION="1.16.15"
        KUBEADM_OPTIONS="--ignore-preflight-errors=cri,swap"
        KUBEADM_SLAVE_OPTIONS="--discovery-token-unsafe-skip-ca-verification --ignore-preflight-errors=cri,SystemVerification,swap"
        sudo ln -sf $COREDNS_DEPLOYMENT $DNS_DEPLOYMENT
        KUBEADM_CONFIG="${KUBEADM_CONFIG_ALPHA3}"
        ;;
    "1.17")
        KUBERNETES_CNI_VERSION="0.8.7"
        K8S_FULL_VERSION="1.17.17"
        KUBEADM_OPTIONS="--ignore-preflight-errors=cri,swap"
        KUBEADM_SLAVE_OPTIONS="--discovery-token-unsafe-skip-ca-verification --ignore-preflight-errors=cri,SystemVerification,swap"
        sudo ln -sf $COREDNS_DEPLOYMENT $DNS_DEPLOYMENT
        KUBEADM_CONFIG="${KUBEADM_CONFIG_ALPHA3}"
        ;;
    "1.18")
        # kubeadm 1.18 requires conntrack to be installed, we can remove this
        # once we have upgrade the VM image version.
        sudo apt-get install -y conntrack
        KUBERNETES_CNI_VERSION="0.8.7"
        KUBERNETES_CNI_OS="-linux"
        K8S_FULL_VERSION="1.18.20"
        KUBEADM_OPTIONS="--ignore-preflight-errors=cri,swap"
        KUBEADM_SLAVE_OPTIONS="--discovery-token-unsafe-skip-ca-verification --ignore-preflight-errors=cri,SystemVerification,swap"
        sudo ln -sf $COREDNS_DEPLOYMENT $DNS_DEPLOYMENT
        KUBEADM_CONFIG="${KUBEADM_CONFIG_V1BETA2}"
        CONTROLLER_FEATURE_GATES="EndpointSlice=true"
        API_SERVER_FEATURE_GATES="EndpointSlice=true"
        ;;
    "1.19")
        # kubeadm 1.19 requires conntrack to be installed, we can remove this
        # once we have upgrade the VM image version.
        sudo apt-get install -y conntrack
        KUBERNETES_CNI_VERSION="0.8.7"
        KUBERNETES_CNI_OS="-linux"
        K8S_FULL_VERSION="1.19.13"
        KUBEADM_OPTIONS="--ignore-preflight-errors=cri,swap"
        KUBEADM_SLAVE_OPTIONS="--discovery-token-unsafe-skip-ca-verification --ignore-preflight-errors=cri,SystemVerification,swap"
        sudo ln -sf $COREDNS_DEPLOYMENT $DNS_DEPLOYMENT
        KUBEADM_CONFIG="${KUBEADM_CONFIG_V1BETA2}"
        CONTROLLER_FEATURE_GATES="EndpointSlice=true"
        API_SERVER_FEATURE_GATES="EndpointSlice=true"
        ;;
    "1.20")
        # kubeadm 1.20 requires conntrack to be installed, we can remove this
        # once we have upgrade the VM image version.
        sudo apt-get install -y conntrack
        KUBERNETES_CNI_VERSION="0.8.7"
        KUBERNETES_CNI_OS="-linux"
        K8S_FULL_VERSION="1.20.9"
        KUBEADM_OPTIONS="--ignore-preflight-errors=cri,swap"
        KUBEADM_SLAVE_OPTIONS="--discovery-token-unsafe-skip-ca-verification --ignore-preflight-errors=cri,SystemVerification,swap"
        sudo ln -sf $COREDNS_DEPLOYMENT $DNS_DEPLOYMENT
        KUBEADM_CONFIG="${KUBEADM_CONFIG_V1BETA2}"
        CONTROLLER_FEATURE_GATES="EndpointSlice=true"
        API_SERVER_FEATURE_GATES="EndpointSlice=true"
        ;;
    "1.21")
        # kubeadm 1.21 requires conntrack to be installed, we can remove this
        # once we have upgrade the VM image version.
        sudo apt-get install -y conntrack
        KUBERNETES_CNI_VERSION="0.8.7"
        KUBERNETES_CNI_OS="-linux"
        K8S_FULL_VERSION="1.21.3"
        KUBEADM_OPTIONS="--ignore-preflight-errors=cri,swap"
        KUBEADM_SLAVE_OPTIONS="--discovery-token-unsafe-skip-ca-verification --ignore-preflight-errors=cri,SystemVerification,swap"
        sudo ln -sf $COREDNS_DEPLOYMENT $DNS_DEPLOYMENT
        KUBEADM_CONFIG="${KUBEADM_CONFIG_V1BETA2}"
        CONTROLLER_FEATURE_GATES="EndpointSlice=true"
        API_SERVER_FEATURE_GATES="EndpointSlice=true"
        ;;
esac

if [ "$KUBEPROXY" == "0" ]; then
    KUBEADM_OPTIONS="$KUBEADM_OPTIONS --skip-phases=addon/kube-proxy"
fi

#Install kubernetes
set +e
case $K8S_VERSION in
    "1.16"|"1.17"|"1.18"|"1.19"|"1.20"|"1.21")
        install_k8s_using_packages \
            kubernetes-cni=${KUBERNETES_CNI_VERSION}* \
            kubelet=${K8S_FULL_VERSION}* \
            kubeadm=${K8S_FULL_VERSION}* \
            kubectl=${K8S_FULL_VERSION}*
        if [ $? -ne 0 ]; then
            echo "falling back on binary k8s install"
            set -e
            install_k8s_using_binary "v${K8S_FULL_VERSION}" "v${KUBERNETES_CNI_VERSION}" "${KUBERNETES_CNI_OS}"
        fi
        ;;
#   "1.21")
#       install_k8s_using_binary "v${K8S_FULL_VERSION}" "v${KUBERNETES_CNI_VERSION}" "${KUBERNETES_CNI_OS}"
#       ;;
esac
set -e

case $CONTAINER_RUNTIME in
    "docker")
        ;;
    "containerd")
        KUBEADM_CRI_SOCKET="unix:///run/containerd/containerd.sock"
        ;;
    *)
        echo "Invalid container runtime '${CONTAINER_RUNTIME}'"
esac

if [ "${IPv6}" -eq "1" ]; then
    KUBEADM_ADDR='[fd04::11]'
    KUBEADM_POD_CIDR="fd02::/112"
    KUBEADM_SVC_CIDR="fd03::/112"
    KUBEADM_V1BETA2_POD_CIDR="fd02::/112"
    KUBEADM_V1BETA2_SVC_CIDR="fd03::/112"
    IPV6_DUAL_STACK_FEATURE_GATE='false'
fi

sudo mkdir -p ${CILIUM_CONFIG_DIR}

sudo cp "$SYSTEMD_SERVICES/$MOUNT_SYSTEMD" /etc/systemd/system/
sudo systemctl enable $MOUNT_SYSTEMD
sudo systemctl restart $MOUNT_SYSTEMD
sudo rm -rfv /var/lib/kubelet || true

if [[ "${PRELOAD_VM}" == "true" ]]; then
    cd ${SRC_FOLDER}
    ./test/provision/container-images.sh test_images .
    ./test/provision/container-images.sh cilium_images .
    echo "VM preloading is finished, skipping the rest"
    exit 0
fi

echo KUBELET_EXTRA_ARGS=\"--fail-swap-on=false\" | tee -a /etc/default/kubelet

#check hostname to know if is kubernetes or runtime test
if [[ "${HOST}" == "k8s1" ]]; then
    if [[ "${SKIP_K8S_PROVISION}" == "false" ]]; then
      echo "${KUBEADM_CONFIG}" | envtpl > /tmp/config.yaml

      sudo kubeadm init  --config /tmp/config.yaml $KUBEADM_OPTIONS

      mkdir -p /root/.kube
      sudo sed -i "s/${KUBEADM_ADDR}/k8s1/" /etc/kubernetes/admin.conf
      sudo cp -i /etc/kubernetes/admin.conf /root/.kube/config
      sudo chown root:root /root/.kube/config

      sudo -u vagrant mkdir -p /home/vagrant/.kube
      sudo cp -fi /etc/kubernetes/admin.conf /home/vagrant/.kube/config
      sudo chown vagrant:vagrant /home/vagrant/.kube/config

      sudo cp -f /etc/kubernetes/admin.conf ${CILIUM_CONFIG_DIR}/kubeconfig
      kubectl taint nodes --all node-role.kubernetes.io/master- || true
      kubectl taint nodes --all node-role.kubernetes.io/control-plane- || true
    else
      echo "SKIPPING K8S INSTALLATION"
    fi
    sudo systemctl start etcd

    # Install custom DNS deployment
    kubectl -n kube-system delete -f ${PROVISIONSRC}/manifest/dns_deployment.yaml || true
    kubectl -n kube-system apply -f ${PROVISIONSRC}/manifest/dns_deployment.yaml

    $PROVISIONSRC/compile.sh
else
    if [[ "${SKIP_K8S_PROVISION}" == "false" ]]; then
      sudo -E bash -c 'echo "${KUBEADM_ADDR} k8s1" >> /etc/hosts'
      kubeadm join --token=$TOKEN ${KUBEADM_ADDR}:6443 \
          ${KUBEADM_SLAVE_OPTIONS}
    else
      echo "SKIPPING K8S INSTALLATION"
    fi
    sudo systemctl stop etcd
fi

# Add aliases and bash completion for kubectl
cat <<EOF >> /home/vagrant/.bashrc

# kubectl
source <(kubectl completion bash)
alias k='kubectl'
complete -F __start_kubectl k
alias ks='kubectl -n kube-system'
complete -F __start_kubectl ks
alias kslogs='kubectl -n kube-system logs -l k8s-app=cilium --tail=-1'
alias wk='watch -n2 kubectl get pods -o wide'
alias wks='watch -n2 kubectl -n kube-system get pods -o wide'
alias wka='watch -n2 kubectl get all --all-namespaces -o wide'
cilium_pod() {
    kubectl -n kube-system get pods -l k8s-app=cilium \
            -o jsonpath="{.items[?(@.spec.nodeName == \"\$1\")].metadata.name}"
}
EOF

# Create world network
docker network create --subnet=192.168.9.0/24 outside
docker run --net outside --ip 192.168.9.10 --restart=always -d docker.io/cilium/demo-httpd:1.0
docker run --net outside --ip 192.168.9.11 --restart=always -d docker.io/cilium/demo-httpd:1.0

sudo touch /etc/provision_finished
