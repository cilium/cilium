#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/../helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

etcd_version="v3.1.0"
# due a kubeadm bug, only upgrade directly to >=1.7.3 once it's released!
# more info github.com/kubernetes/kubeadm/issues/354
k8s_version=${k8s_version:-"1.7.0-00"}

certs_dir="${dir}/certs"
k8s_dir="${dir}/k8s"
cilium_dir="${dir}/cilium"
rbac_yaml="${dir}/../../../examples/kubernetes/rbac.yaml"

function get_options(){
    if [[ "${1}" == "ipv6" ]]; then
        cat <<'EOF' > "${dir}/env.bash"
# IPv6
controller_ip="fd01::b"
controller_ip_brackets="[${controller_ip}]"
local="::1"
local_with_brackets="[${local}]"
cluster_cidr="F00D::C0A8:0000:0:0/96"
cluster_dns_ip="FD03::A"
cluster_name="cilium-k8s-tests"
node_cidr_mask_size="112"
service_cluster_ip_range="FD03::/112"
disable_ipv4=true
EOF
    else
        cat <<'EOF' > "${dir}/env.bash"
# IPv4
controller_ip="192.168.36.11"
controller_ip_brackets="${controller_ip}"
local="127.0.0.1"
local_with_brackets="${local}"
cluster_cidr="10.20.0.0/10"
cluster_dns_ip="172.20.0.10"
cluster_name="cilium-k8s-tests"
node_cidr_mask_size="16"
service_cluster_ip_range="172.20.0.0/16"
disable_ipv4=false
EOF
    fi

echo "k8s_version=${k8s_version}" >> "${dir}/env.bash"

    source "${dir}/env.bash"

    cat <<EOF > "${dir}/kubeadm-master.conf"
apiVersion: kubeadm.k8s.io/v1alpha1
kind: MasterConfiguration
api:
  advertiseAddress: ${controller_ip_brackets}
kubernetesVersion: "v${k8s_version::-3}"
etcd:
  endpoints:
  - https://${controller_ip_brackets}:2379
  caFile: /etc/kubernetes/ca.pem
  certFile: /etc/kubernetes/kubernetes.pem
  keyFile: /etc/kubernetes/kubernetes-key.pem
networking:
  dnsDomain: ${cluster_name}.local
  serviceSubnet: "${service_cluster_ip_range}"
token: "123456.abcdefghijklmnop"
controllerManagerExtraArgs:
  allocate-node-cidrs: "true"
  cluster-cidr: "${cluster_cidr}"
  node-cidr-mask-size: "${node_cidr_mask_size}"
EOF
}

function generate_certs(){
    bash "${certs_dir}/generate-certs.sh"
}

function install_etcd(){
    wget -nv https://github.com/coreos/etcd/releases/download/${etcd_version}/etcd-${etcd_version}-linux-amd64.tar.gz
    tar -xvf etcd-${etcd_version}-linux-amd64.tar.gz
    sudo mv etcd-${etcd_version}-linux-amd64/etcd* /usr/bin/
}

function copy_etcd_certs(){
    sudo mkdir -p /etc/etcd/
    sudo mkdir -p /etc/kubernetes/

    sudo cp "${certs_dir}/ca.pem" \
            "${certs_dir}/kubernetes-key.pem" \
            "${certs_dir}/kubernetes.pem" \
            /etc/etcd/

    # kubeadm doesn't automatically mount the files to the containers
    # yet so we need to copy the files to directory that we specify in
    # the kubeadm configuration file
    sudo cp "${certs_dir}/ca.pem" \
            "${certs_dir}/kubernetes-key.pem" \
            "${certs_dir}/kubernetes.pem" \
            /etc/kubernetes
}

function generate_etcd_config(){
    sudo mkdir -p /var/lib/etcd

    sudo tee /etc/systemd/system/etcd.service <<EOF
[Unit]
Description=etcd
Documentation=https://github.com/coreos

[Service]
ExecStart=/usr/bin/etcd --name master \\
  --cert-file=/etc/etcd/kubernetes.pem \\
  --key-file=/etc/etcd/kubernetes-key.pem \\
  --peer-cert-file=/etc/etcd/kubernetes.pem \\
  --peer-key-file=/etc/etcd/kubernetes-key.pem \\
  --trusted-ca-file=/etc/etcd/ca.pem \\
  --peer-trusted-ca-file=/etc/etcd/ca.pem \\
  --peer-client-cert-auth \\
  --initial-advertise-peer-urls https://${controller_ip_brackets}:2380 \\
  --listen-peer-urls https://${controller_ip_brackets}:2380 \\
  --listen-client-urls https://${controller_ip_brackets}:2379,http://127.0.0.1:2379 \\
  --advertise-client-urls https://${controller_ip_brackets}:2379 \\
  --initial-cluster-token etcd-cluster-0 \\
  --initial-cluster master=https://${controller_ip_brackets}:2380 \\
  --initial-cluster-state new \\
  --data-dir=/var/lib/etcd
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
}

# FIXME remove this workaround in kubeadm 1.7.3
# More info: github.com/kubernetes/kubeadm/issues/335
function create_rolebinding(){
    wait_for_healthy_k8s_cluster 1
    kubectl create -f "${dir}/kubeadm-fix.yaml" || true
}

function start_kubeadm() {
    cd /home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/cluster

    sudo bash -c "cat <<EOF > /etc/systemd/system/kubelet.service.d/15-kubelet-dns-args.conf
[Service]
Environment='KUBELET_DNS_ARGS=--cluster-dns=${cluster_dns_ip} --cluster-domain=${cluster_name}.local'
EOF
"
    sudo systemctl daemon-reload

    sudo mkdir -p /home/vagrant/.kube
    sudo mkdir -p /root/.kube
    sudo mkdir -p /var/lib/cilium/

    if [[ "$(hostname)" -eq "k8s-1" ]]; then
        sudo kubeadm init --config ./kubeadm-master.conf

        # copy kubeconfig for cilium and vagrant user
        sudo cp /etc/kubernetes/admin.conf /home/vagrant/.kube/config
        sudo cp /etc/kubernetes/admin.conf /var/lib/cilium/kubeconfig
        sudo chown 1000:1000 /home/vagrant/.kube/config

        # copy kubeconfig for root
        sudo cp /etc/kubernetes/admin.conf /root/.kube/config
        sudo chown vagrant.vagrant -R /home/vagrant/.kube

        # copy kubeconfig so we can share it with node-2
        sudo cp /etc/kubernetes/admin.conf ./kubelet.conf

        create_rolebinding
    else
        sudo kubeadm join --token 123456.abcdefghijklmnop ${controller_ip_brackets}:6443

        # copy kubeconfig file previously copied from the master
        sudo cp ./kubelet.conf /home/vagrant/.kube/config
        sudo cp ./kubelet.conf /var/lib/cilium/kubeconfig
        sudo chown 1000:1000 /home/vagrant/.kube/config

        # copy kubeconfig for root
        sudo cp ./kubelet.conf /root/.kube/config
        sudo chown vagrant.vagrant -R /home/vagrant/.kube

        # taint all node with the label master so we can schedule pods all nodes
        kubectl taint nodes --all node-role.kubernetes.io/master-
    fi
}

function install_kubeadm_dependencies(){
    sudo apt-get update && sudo apt-get install -y apt-transport-https
    sudo touch /etc/apt/sources.list.d/kubernetes.list
    curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg  | sudo apt-key add -
    sudo bash -c "cat <<EOF > /etc/apt/sources.list.d/kubernetes.list
deb http://apt.kubernetes.io/ kubernetes-xenial main
EOF
"

    sudo apt-get update && sudo apt-get install -y docker-engine
    sudo usermod -aG docker vagrant
}

function install_kubeadm() {
    sudo apt-get install --allow-downgrades -y kubelet=${k8s_version} kubeadm=${k8s_version} kubectl=${k8s_version} kubernetes-cni
}

function install_cilium_config(){
    sudo mkdir -p /var/lib/cilium

    sudo cp "${certs_dir}/ca.pem" \
       "/var/lib/cilium/etcd-ca.pem"

    sudo tee /var/lib/cilium/etcd-config.yml <<EOF
---
endpoints:
- https://${controller_ip_brackets}:2379
ca-file: '/var/lib/cilium/etcd-ca.pem'
EOF

}

function start_etcd(){
    sudo systemctl daemon-reload
    sudo systemctl enable etcd
    sudo systemctl start etcd
    sudo systemctl status etcd --no-pager
}

function clean_etcd(){
    sudo service etcd stop
    sudo rm -fr /var/lib/etcd
}

function clean_kubeadm(){
    sudo kubeadm reset
    sudo docker rm -f `sudo docker ps -aq` 2>/dev/null
}

function fresh_install(){
    while getopts ":-:" opt; do
      case $opt in
        "-")
          case "${OPTARG}" in
            "ipv6")
              ipv6="ipv6"
            ;;
          esac
        ;;
      esac
    done

    get_options "${ipv6}"

    if [[ "$(hostname)" -eq "k8s-1" ]]; then
        install_etcd
        copy_etcd_certs
        generate_etcd_config
        start_etcd
    fi
    install_kubeadm_dependencies
    install_kubeadm

    start_kubeadm

    install_cilium_config
}

function reinstall(){
    while getopts ":-:" opt; do
      case $opt in
        "-")
          case "${OPTARG}" in
            "yes-delete-all-data")
              clean_etcd_opt=1
              clean_kubeadm_opt=1
            ;;
            "yes-delete-etcd-data")
              clean_etcd_opt=1
            ;;
            "yes-delete-kubeadm-data")
              clean_kubeadm_opt=1
            ;;
            "reinstall-kubeadm")
              clean_kubeadm_opt=1
              reinstall_kubeadm_opt=1
            ;;
            "ipv6")
              ipv6="ipv6"
            ;;
          esac
        ;;
      esac
    done

    get_options "${ipv6}"

    if [[ -n "${clean_etcd_opt}" ]]; then
        clean_etcd
    fi
    if [[ -n "${clean_kubeadm_opt}" ]]; then
        clean_kubeadm
    fi
    if [[ -n "${reinstall_kubeadm_opt}" ]]; then
        install_kubeadm
    fi

    if [[ "$(hostname)" -eq "k8s-1" ]]; then
        copy_etcd_certs
        generate_etcd_config
        start_etcd
    fi
    start_kubeadm

    install_cilium_config
}

function deploy_cilium(){
    while getopts ":-:" opt; do
      case $opt in
        "-")
          case "${OPTARG}" in
            "lb-mode")
              lb=1
            ;;
          esac
        ;;
      esac
    done
    
    source "${dir}/env.bash"

    rm "${cilium_dir}/cilium-ds.yaml" 2>/dev/null

    if [[ -n "${lb}" ]]; then
        # In loadbalancer mode we set the snoop and LB interface to
        # enp0s8, the interface with IP 192.168.36.11.
        iface='enp0s8'

        sed -e "s+\$disable_ipv4+${disable_ipv4}+g;\
                s+\$iface+${iface}+g" \
            "${cilium_dir}/cilium-lb-ds.yaml.sed" > "${cilium_dir}/cilium-lb-ds.yaml"

        kubectl create -f "${cilium_dir}"

        wait_for_daemon_set_ready kube-system cilium 1
    else
        sed -e "s+\$disable_ipv4+${disable_ipv4}+g" \
            "${cilium_dir}/cilium-ds.yaml.sed" > "${cilium_dir}/cilium-ds.yaml"

        kubectl create -f "${rbac_yaml}"
        kubectl create -f "${cilium_dir}"

        wait_for_daemon_set_ready kube-system cilium 2
    fi

    echo "lb='${lb}'" >> "${dir}/env.bash"
}

case "$1" in
        generate_certs)
            generate_certs
            ;;
        fresh_install)
            shift
            fresh_install "$@"
            ;;
        reinstall)
            shift
            reinstall "$@"
            ;;
        deploy_cilium)
            shift
            deploy_cilium "$@"
            ;;
        *)
            echo $"Usage: $0 {generate_certs | fresh_install [--ipv6] | \
reinstall [--yes-delete-all-data] [--yes-delete-etcd-data] [--yes-delete-kubeadm-data] \
[--ipv6] [--reinstall-kubeadm] | \
deploy_cilium [--lb-mode]}"
            exit 1
esac
