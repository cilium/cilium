#!/usr/bin/env bash

set -e

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/../helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

etcd_version="v3.1.0"
k8s_version=${k8s_version:-"1.7.4-00"}

cert_script_dir="${dir}/certs"
certs_dir="${dir}/certs/${k8s_version}"
k8s_dir="${dir}/k8s"
cilium_dir="${dir}/cilium"
rbac_yaml="${dir}/../../../examples/kubernetes/rbac.yaml"

function get_options(){
  log "beginning generation options"
  log "creating directory to store configuration at ${dir}/${k8s_version}"
  mkdir -p "${dir}/${k8s_version}"
  if [[ "${1}" == "ipv6" ]]; then
    log "setting IPv6 environment variables"
    cat <<'EOF' > "${dir}/${k8s_version}/env.bash"
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
    log "setting IPv4 environment variables"
    if [[ "${k8s_version}" == "1.7.4-00" ]]; then
      NUM="7"
    else
      NUM="6"
    fi
    cat <<'EOF' > "${dir}/${k8s_version}/env.bash"
# IPv4
# FIX ME
controller_ip="192.168.3${NUM}.11"
controller_ip_brackets="${controller_ip}"
local="127.0.0.1"
local_with_brackets="${local}"
cluster_cidr="10.2${NUM}.0.0/16"
cluster_dns_ip="172.2${NUM}.0.10"
cluster_name="cilium-k8s-tests-${NUM}"
node_cidr_mask_size="16"
service_cluster_ip_range="172.2${NUM}.0.0/16"
disable_ipv4=false
EOF
  fi

  log "setting k8s_version=${k8s_version} in ${dir}/${k8s_version}/env.bash"
  echo "k8s_version=${k8s_version}" >> "${dir}/${k8s_version}/env.bash"
  source "${dir}/${k8s_version}/env.bash"

  log "contents of ${dir}/${k8s_version}/env.bash"
  cat "${dir}/${k8s_version}/env.bash"
  log "output of \"env\""
  env

  log "creating master K8s configuration at ${dir}/${k8s_version}/kubeadm-master.conf"
  cat <<EOF > "${dir}/${k8s_version}/kubeadm-master.conf"
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
  log "contents of ${dir}/${k8s_version}/kubeadm-master.conf"
  cat ${dir}/${k8s_version}/kubeadm-master.conf
  log "done generating options"
}

function generate_certs(){
  log "generating K8s certificates"
  bash "${cert_script_dir}/generate-certs.sh"
  log "done generating K8s certificates"
}

function install_etcd(){
  log "downloading and installing etcd version ${etcd_version}"
  wget -nv https://github.com/coreos/etcd/releases/download/${etcd_version}/etcd-${etcd_version}-linux-amd64.tar.gz
  tar -xf etcd-${etcd_version}-linux-amd64.tar.gz
  sudo mv etcd-${etcd_version}-linux-amd64/etcd* /usr/bin/
  log "done downloading and installing etcd"
}

function copy_etcd_certs(){
  log "copying etcd certs"
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
  log "done copying etcd certs"
}

function generate_etcd_config(){
  log "generating etcd configuration"
  sudo mkdir -p /var/lib/etcd

  log "contents of /etc/systemd/system/etcd.service"
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
  log "done generating etcd configuration"
}

function start_kubeadm() {
  log "starting kubeadm"
  cd /home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/cluster

  log "generating kubelet DNS args"
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
    log "on master node, initializing kubeadm with kubeadm-master.conf"
    sudo kubeadm init --config ./${k8s_version}/kubeadm-master.conf

    log "copying kubeconfig for Cilium and Vagrant users"
    # copy kubeconfig for cilium and vagrant user
    sudo cp /etc/kubernetes/admin.conf /home/vagrant/.kube/config
    sudo cp /etc/kubernetes/admin.conf /var/lib/cilium/kubeconfig
    sudo chown 1000:1000 /home/vagrant/.kube/config

    log "copying kubeconfig for root user"
    # copy kubeconfig for root
    sudo cp /etc/kubernetes/admin.conf /root/.kube/config
    sudo chown vagrant.vagrant -R /home/vagrant/.kube

    log "copying kubeconfig onto path that is accessible on host machine so we can share it with worker node to directory ${dir}/${k8s_version}"
    # copy kubeconfig so we can share it with node-2
    sudo cp /etc/kubernetes/admin.conf ./${k8s_version}/kubelet.conf
    log "contents of ${PWD}/${k8s_version}"
    ls ./${k8s_version}
  else
    log "on worker node, joining cluster that was configured on master node (k8s-1)" 
    sudo kubeadm join --token 123456.abcdefghijklmnop ${controller_ip_brackets}:6443

    log "copying kubeconfig file that was previously copied from master node onto worker node"
    # copy kubeconfig file previously copied from the master
    log "contents of ${PWD}/${k8s_version}"
    ls ./${k8s_version}
    sudo cp ./${k8s_version}/kubelet.conf /home/vagrant/.kube/config
    sudo cp ./${k8s_version}/kubelet.conf /var/lib/cilium/kubeconfig
    sudo chown 1000:1000 /home/vagrant/.kube/config

    log "copying kubeconfig file for root user"
    # copy kubeconfig for root
    sudo cp ./${k8s_version}/kubelet.conf /root/.kube/config
    sudo chown vagrant.vagrant -R /home/vagrant/.kube

    log "tainting master node so that we can schedule pods on both master and worker nodes"
    # taint all node with the label master so we can schedule pods all nodes
    kubectl taint nodes --all node-role.kubernetes.io/master-
  fi
  log "done starting kubeadm"
}

function install_kubeadm_dependencies(){
  log "installing kubeadm dependencies"
  sudo touch /etc/apt/sources.list.d/kubernetes.list
  curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg  | sudo apt-key add -
  sudo bash -c "cat <<EOF > /etc/apt/sources.list.d/kubernetes.list
deb http://apt.kubernetes.io/ kubernetes-xenial main
EOF
"
  sudo apt-get -qq update && sudo apt-get -qq install -y apt-transport-https docker-engine
  sudo usermod -aG docker vagrant
  log "done installing kubeadm dependencies"
}

function install_kubeadm() {
  log "installing kubeadm"
  sudo apt-get -qq install --allow-downgrades -y kubelet=${k8s_version} kubeadm=${k8s_version} kubectl=${k8s_version} kubernetes-cni
  log "done installing kubeadm"
}

function install_cilium_config(){
  log "installing Cilium configuration so it can communicate with etcd"
  sudo mkdir -p /var/lib/cilium

  sudo cp "${certs_dir}/ca.pem" \
     "/var/lib/cilium/etcd-ca.pem"

  log "contents of /var/lib/cilium/etcd-config.yml"
  sudo tee /var/lib/cilium/etcd-config.yml <<EOF
---
endpoints:
- https://${controller_ip_brackets}:2379
ca-file: '/var/lib/cilium/etcd-ca.pem'
EOF

  log "done installing Cilium configuration"
}

function start_etcd(){
  log "staring etcd"
  sudo systemctl daemon-reload
  sudo systemctl enable etcd
  sudo systemctl start etcd
  sudo systemctl status etcd --no-pager
  log "done starting etcd"
}

function clean_etcd(){
  log "stopping etcd and removing all of its data"
  sudo service etcd stop
  sudo rm -fr /var/lib/etcd
  log "done stopping etcd and removing all of its data"
}

function clean_kubeadm(){
  log "resetting kubeadm and removing all Docker containers"
  sudo kubeadm reset
  sudo docker rm -f `sudo docker ps -aq` 2>/dev/null || true
  log "done resetting kubeadm"
}

function fresh_install(){
  log "beginning fresh install"
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
    generate_certs
    install_etcd
    copy_etcd_certs
    generate_etcd_config
    start_etcd
  fi
  install_kubeadm_dependencies
  install_kubeadm
    
  clean_kubeadm
  start_kubeadm

  install_cilium_config
  log "done with fresh install"
}

function reinstall(){
  log "beginning reinstall"
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
  log "deploying Cilium"
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
   
  log "using environment variables in ${dir}/${k8s_version}/env.bash" 
  source "${dir}/${k8s_version}/env.bash"

  log "removing old cilium daemonset files"
  rm "${cilium_dir}/cilium-lb-ds.yaml" \
     "${cilium_dir}/cilium-ds.yaml" \
      2>/dev/null || true

  if [[ -n "${lb}" ]]; then
    log "in loadbalancer mode, setting snoop / LB interface to enp0s8"
    # In loadbalancer mode we set the snoop and LB interface to
    # enp0s8, the interface with IP 192.168.36.11.
    iface='enp0s8'

    sed -e "s+\$disable_ipv4+${disable_ipv4}+g;\
            s+\$iface+${iface}+g" \
        "${cilium_dir}/cilium-lb-ds.yaml.sed" > "${cilium_dir}/cilium-lb-ds.yaml"

    kubectl create -f "${cilium_dir}"

    wait_for_daemon_set_ready kube-system cilium 1
  else
    log "not in loadbalancer mode; setting IPv4 options in Cilium daemonset"
    sed -e "s+\$disable_ipv4+${disable_ipv4}+g" \
        "${cilium_dir}/cilium-ds.yaml.sed" > "${cilium_dir}/cilium-ds.yaml"

    log "adding resources in ${rbac_yaml} directory"
    kubectl create -f "${rbac_yaml}"
    log "creating resources in ${cilium_dir}"
    kubectl create -f "${cilium_dir}"

    wait_for_daemon_set_ready kube-system cilium 2
  fi

  echo "lb='${lb}'" >> "${dir}/${k8s_version}/env.bash"
  log "done deploying Cilium"
}

function remove_cilium_ds(){
  log "deleting Cilium daemonset"
  kubectl delete -f "${cilium_dir}" || true
  log "done deleting Cilium daemonset"
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
  remove_cilium_ds)
    shift
    remove_cilium_ds "$@"
    ;;
  *)
    echo $"Usage: $0 {generate_certs | fresh_install [--ipv6] | \
reinstall [--yes-delete-all-data] [--yes-delete-etcd-data] [--yes-delete-kubeadm-data] \
[--ipv6] [--reinstall-kubeadm] | \
deploy_cilium [--lb-mode] | \
remove_cilium_ds}"
    exit 1
esac
