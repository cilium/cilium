#!/usr/bin/env bash
#
# Installs, configures and starts kubernetes worker, it will use default values
# from ./helpers.bash
# Globals:
#   INSTALL, if set installs k8s binaries, otherwise it will only configure k8s
#######################################

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"
source "${dir}/cert-gen-helpers.bash"

cache_dir="${dir}/../../../hack/cache"
k8s_cache_dir="${cache_dir}/k8s/${k8s_version}"
certs_dir="${dir}/certs"

function install_crio() {
   sudo apt-key adv --recv-key --keyserver keyserver.ubuntu.com 8BECF1637AD8C79D

   cat <<EOF > /etc/apt/sources.list.d/projectatomic-ubuntu-ppa-artful.list
deb http://ppa.launchpad.net/projectatomic/ppa/ubuntu bionic main
deb-src http://ppa.launchpad.net/projectatomic/ppa/ubuntu bionic main
EOF
   sudo apt-get update
   sudo apt-get remove cri-o-1.* -y || true
   sudo apt-get install cri-o-1.13 -y || true
   sudo ln -s /usr/sbin/runc /usr/local/sbin/runc || true
}

function install_containerd() {
    sudo service docker stop
    sudo apt remove containerd* -y
    download_to "${cache_dir}/containerd" "containerd-1.2.1.linux-amd64.tar.gz" \
       "https://github.com/containerd/containerd/releases/download/v1.2.1/containerd-1.2.1.linux-amd64.tar.gz"

    cp "${cache_dir}/containerd/containerd-1.2.1.linux-amd64.tar.gz" .

    sudo apt-get install runc -y
    sudo tar -xvf containerd-1.2.1.linux-amd64.tar.gz -C / --no-same-owner

    sudo rm -f /etc/systemd/system/containerd.service
    sudo ln -s /bin/containerd /usr/local/bin/containerd
    cat << EOF | sudo tee /etc/systemd/system/containerd.service
[Unit]
Description=containerd container runtime
Documentation=https://containerd.io
After=network.target

[Service]
ExecStartPre=-/sbin/modprobe overlay
ExecStart=/usr/local/bin/containerd

Delegate=yes
KillMode=process
# Having non-zero Limit*s causes performance problems due to accounting overhead
# in the kernel. We recommend using cgroups to do container-local accounting.
LimitNPROC=infinity
LimitCORE=infinity
LimitNOFILE=infinity
# Comment TasksMax if your systemd version does not supports it.
# Only systemd 226 and above support this version.
TasksMax=infinity

[Install]
WantedBy=multi-user.target
EOF

    cat << EOF | sudo tee /etc/containerd/config.toml
[plugins]
  [plugins.cri.containerd]
    snapshotter = "overlayfs"
    [plugins.cri.containerd.default_runtime]
      runtime_type = "io.containerd.runtime.v1.linux"
      runtime_engine = "/usr/sbin/runc"
      runtime_root = ""
EOF
    sudo systemctl daemon-reload
}

log "Installing kubernetes worker components..."

set -e

sudo mkdir -p /opt/cni/bin

if [ -n "${INSTALL}" ]; then
    for component in kubectl kubelet kube-proxy; do
        download_to "${k8s_cache_dir}" "${component}" \
            "https://dl.k8s.io/release/${k8s_version}/bin/linux/amd64/${component}"

        cp "${k8s_cache_dir}/${component}" .
    done

    download_to "${cache_dir}/cni" "cni-plugins-amd64-v0.7.5.tgz" \
        "https://github.com/containernetworking/plugins/releases/download/v0.7.5/cni-plugins-amd64-v0.7.5.tgz"

    cp "${cache_dir}/cni/cni-plugins-amd64-v0.7.5.tgz" .

    sudo tar -xvf cni-plugins-amd64-v0.7.5.tgz -C /opt/cni/bin

    chmod +x kubelet kubectl kube-proxy

    sudo cp kubelet kubectl kube-proxy /usr/bin/

fi

case "${RUNTIME}" in
    "containerd" | "containerD")
        cat <<EOF > /etc/crictl.yaml
runtime-endpoint: unix:///var/run/containerd/containerd.sock
EOF
        ;;
    "crio" | "cri-o")
        cat <<EOF > /etc/crictl.yaml
runtime-endpoint: unix:///var/run/crio/crio.sock
EOF
        ;;
    *)
        ;;
esac

log "Copying cilium certificates to /var/lib/cilium"
# Copy cilium certificates to /var/lib/cilium
sudo mkdir -p /var/lib/cilium

cp "${certs_dir}/ca-k8s.pem" \
   "${certs_dir}/ca-etcd.pem" \
   "${certs_dir}/etcd-cilium-key.pem" \
   "${certs_dir}/etcd-cilium.pem" \
   "${certs_dir}/k8s-cilium-key.pem" \
   "${certs_dir}/k8s-cilium.pem" \
   /var/lib/cilium

log "Copying nginx certificates to /var/lib/nginx"
# Copy nginx certificates to /var/lib/nginx
sudo mkdir -p /var/lib/nginx

cp "${certs_dir}/ca-k8s.pem" \
   "${certs_dir}/k8s-nginx-key.pem" \
   "${certs_dir}/k8s-nginx.pem" \
   /var/lib/nginx

log "Generating client kubelet and component certificates"

hostname=$(hostname)
current_path=$(echo $PWD)
cd "${certs_dir}"
generate_kubelet_client_certs k8s system:node:${hostname} k8s-kubelet-${hostname}
generate_k8s_component_certs kubelet ${hostname} kubelet-kubelet-${hostname}
generate_k8s_component_certs k8s ${hostname} k8s-kube-proxy-${hostname}
cd "${current_path}"

log "Copying kubelet certificates to /var/lib/kubelet"
# Copy kube-proxy certificates to /var/lib/kubelet
sudo mkdir -p /var/lib/kubelet/

cp "${certs_dir}/ca-k8s.pem" \
   "${certs_dir}/ca-kubelet.pem" \
   "${certs_dir}/k8s-kubelet-${hostname}-key.pem" \
   "${certs_dir}/k8s-kubelet-${hostname}.pem" \
   "${certs_dir}/kubelet-kubelet-${hostname}.pem" \
   "${certs_dir}/kubelet-kubelet-${hostname}-key.pem" \
   /var/lib/kubelet/

log "Copying kube-proxy certificates to /var/lib/kube-proxy"
# Copy kube-proxy certificates to /var/lib/kube-proxy
sudo mkdir -p /var/lib/kube-proxy/

cp "${certs_dir}/ca-k8s.pem" \
   "${certs_dir}/k8s-kube-proxy-${hostname}-key.pem" \
   "${certs_dir}/k8s-kube-proxy-${hostname}.pem" \
   /var/lib/kube-proxy/

log "Generating etc-docnfig file for cilium to contact etcd"
# Generate etcd-config file for cilium to contact etcd
sudo tee /var/lib/cilium/etcd-config.yml <<EOF
---
endpoints:
- https://${controllers_ips[0]}:2379
trusted-ca-file: '/var/lib/cilium/ca-etcd.pem'
key-file: '/var/lib/cilium/etcd-cilium-key.pem'
cert-file: '/var/lib/cilium/etcd-cilium.pem'
EOF

log "Generating kubeconfig file for cilium"
# Create dedicated kube-config file for cilium
kubectl config set-cluster kubernetes \
    --certificate-authority=/var/lib/cilium/ca-k8s.pem \
    --embed-certs=true \
    --server=https://${controllers_ips[0]}:6443 \
    --kubeconfig=cilium.kubeconfig

kubectl config set-credentials cilium \
    --client-certificate=/var/lib/cilium/k8s-cilium.pem \
    --client-key=/var/lib/cilium/k8s-cilium-key.pem \
    --embed-certs=true \
    --kubeconfig=cilium.kubeconfig

kubectl config set-context default \
    --cluster=kubernetes \
    --user=cilium \
    --kubeconfig=cilium.kubeconfig

kubectl config use-context default \
    --kubeconfig=cilium.kubeconfig

sudo cp ./cilium.kubeconfig /var/lib/cilium/cilium.kubeconfig


# Create dedicated kube-config file for nginx
log "creating kubeconfig file for nginx"
kubectl config set-cluster kubernetes \
    --certificate-authority=/var/lib/nginx/ca-k8s.pem \
    --embed-certs=true \
    --server=https://${controllers_ips[0]}:6443 \
    --kubeconfig=nginx.kubeconfig

kubectl config set-credentials nginx \
    --client-certificate=/var/lib/nginx/k8s-nginx.pem \
    --client-key=/var/lib/nginx/k8s-nginx-key.pem \
    --embed-certs=true \
    --kubeconfig=nginx.kubeconfig

kubectl config set-context default \
    --cluster=kubernetes \
    --user=nginx \
    --kubeconfig=nginx.kubeconfig

kubectl config use-context default \
    --kubeconfig=nginx.kubeconfig

sudo cp ./nginx.kubeconfig /var/lib/nginx/nginx.kubeconfig


log "creating kubeconfig file for kubelet"
# Create dedicated kube-config file for kubelet
sudo mkdir -p /var/lib/kubelet/

kubectl config set-cluster kubernetes \
    --certificate-authority=/var/lib/kubelet/ca-k8s.pem \
    --embed-certs=true \
    --server=https://${controllers_ips[0]}:6443 \
    --kubeconfig=kubelet.kubeconfig

kubectl config set-credentials kubelet \
    --client-certificate=/var/lib/kubelet/k8s-kubelet-${hostname}.pem \
    --client-key=/var/lib/kubelet/k8s-kubelet-${hostname}-key.pem \
    --embed-certs=true \
    --kubeconfig=kubelet.kubeconfig

kubectl config set-context default \
    --cluster=kubernetes \
    --user=kubelet \
    --kubeconfig=kubelet.kubeconfig

kubectl config use-context default \
    --kubeconfig=kubelet.kubeconfig

sudo cp ./kubelet.kubeconfig /var/lib/kubelet/kubelet.kubeconfig


log "creating kubeconfig file for kube-proxy"
# Create dedicated kube-config file for kube-proxy
sudo mkdir -p /var/lib/kube-proxy/

kubectl config set-cluster kubernetes \
    --certificate-authority=/var/lib/kube-proxy/ca-k8s.pem \
    --embed-certs=true \
    --server=https://${controllers_ips[0]}:6443 \
    --kubeconfig=kube-proxy.kubeconfig

kubectl config set-credentials kubelet \
    --client-certificate=/var/lib/kube-proxy/k8s-kube-proxy-${hostname}.pem \
    --client-key=/var/lib/kube-proxy/k8s-kube-proxy-${hostname}-key.pem \
    --embed-certs=true \
    --kubeconfig=kube-proxy.kubeconfig

kubectl config set-context default \
    --cluster=kubernetes \
    --user=kube-proxy \
    --kubeconfig=kube-proxy.kubeconfig

kubectl config use-context default \
    --kubeconfig=kube-proxy.kubeconfig

sudo cp ./kube-proxy.kubeconfig /var/lib/kube-proxy/kube-proxy.kubeconfig
# FIXME remove this once we know how to set up kube-proxy in RBAC properly
sudo cp ./cilium.kubeconfig /var/lib/kube-proxy/kube-proxy.kubeconfig

log "creating kube-proxy systemd service"
sudo tee /etc/systemd/system/kube-proxy.service <<EOF
[Unit]
Description=Kubernetes Kube-Proxy Server
Documentation=https://kubernetes.io/docs/concepts/overview/components/#kube-proxy https://kubernetes.io/docs/reference/generated/kube-proxy/
After=network.target

[Service]
ExecStart=/usr/bin/kube-proxy \\
  --cluster-cidr=${k8s_cluster_cidr} \\
  --kubeconfig=/var/lib/kube-proxy/kube-proxy.kubeconfig \\
  --proxy-mode=iptables \\
  --v=2

Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

log "reloading systemctl daemon and enabling and restarting kube-proxy"
sudo systemctl daemon-reload
sudo systemctl enable kube-proxy
sudo systemctl restart kube-proxy

sudo systemctl status kube-proxy --no-pager

log "creating systemd service for kubelet"
sudo tee /etc/systemd/system/kubelet.service <<EOF
[Unit]
Description=Kubernetes Kubelet
Documentation=https://kubernetes.io/docs/home
After=${container_runtime_name}.service
Requires=${container_runtime_name}.service

[Service]
# Mount BPF fs for cilium
ExecStartPre=/bin/bash -c ' \\
        if [[ \$(/bin/mount | /bin/grep /sys/fs/bpf -c) -eq 0 ]]; then \\
           /bin/mount bpffs /sys/fs/bpf -t bpf; \\
        fi'
ExecStart=/usr/bin/kubelet \\
  --client-ca-file=/var/lib/kubelet/ca-k8s.pem \\
  --cloud-provider= \\
  --cluster-dns=${cluster_dns_ip},${cluster_dns_ipv6} \\
  --cluster-domain=cluster.local \\
  --container-runtime=${container_runtime_kubelet} \\
  ${container_runtime_endpoint} \\
  ${cgroup_driver} \\
  --kubeconfig=/var/lib/kubelet/kubelet.kubeconfig \\
  --fail-swap-on=false \\
  --make-iptables-util-chains=false \\
  --network-plugin=cni \\
  --node-ip=${node_ip} \\
  --register-node=true \\
  --serialize-image-pulls=false \\
  --tls-cert-file=/var/lib/kubelet/kubelet-kubelet-${hostname}.pem \\
  --tls-private-key-file=/var/lib/kubelet/kubelet-kubelet-${hostname}-key.pem \\
  --v=2

Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

log "reloading systemctl daemon and enabling and restarting kubelet"
sudo systemctl daemon-reload
sudo systemctl enable kubelet
sudo systemctl restart kubelet

sudo systemctl status kubelet --no-pager

log "Installing kubernetes worker components... DONE!"
