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
   curl https://raw.githubusercontent.com/cri-o/cri-o/main/scripts/get | bash -s -- -t a68a72071e5004be78fe2b1b98cb3bfa0e51b74b
}

function install_containerd() {
    download_to "${cache_dir}/containerd" "cri-containerd-cni-1.6.3-linux-amd64.tar.gz" \
       "https://github.com/containerd/containerd/releases/download/v1.6.3/cri-containerd-cni-1.6.3-linux-amd64.tar.gz"

    cp "${cache_dir}/containerd/cri-containerd-cni-1.6.3-linux-amd64.tar.gz" .

    sudo tar -C / -xzf cri-containerd-cni-1.6.3-linux-amd64.tar.gz

    # Remove the default CNI config installed by containerd.
    sudo rm -f /etc/cni/net.d/10-containerd-net.conflist

    cat <<EOF > /etc/containerd/config.toml
root = "/tmp/containers"
state = "/run/containerd"
oom_score = 0

[grpc]
  address = "/run/containerd/containerd.sock"
  uid = 0
  gid = 0
  max_recv_message_size = 16777216
  max_send_message_size = 16777216

[plugins.cri.containerd]
  snapshotter = "native"

[debug]
  address = ""
  uid = 0
  gid = 0
  level = ""

[metrics]
  address = ""
  grpc_histogram = false
EOF

    sudo systemctl enable containerd
    sudo systemctl restart containerd

    sudo crictl -r unix:///run/containerd/containerd.sock ps

    sudo systemctl restart docker
    sudo docker ps
}

# node_ip_addresses returns the parameter for kubelet --node-ip
# need to cover 3 scenarios:
# 1. $node_ipv6 == "", this happens when ipv6 is disabled
# 2. $node_ip == $node_ipv6, this happens when IPV6_EXT=1
# 3. $node_ip != $node_ipv6 && $node_ipv6 != ""
# we concatenate two vars on scenario 3 and return the non-empty var for the others
function node_ip_addresses() {
    if [[ -z "$node_ipv6" ]]; then
        echo -n $node_ip
    elif [[ "$node_ipv6" == "$node_ip" ]]; then
        echo -n $node_ipv6
    else
        echo -n "$node_ip,$node_ipv6"
    fi
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

    case "${RUNTIME}" in
    "crio" | "cri-o")
        install_crio
        ;;
    *)
        install_containerd
        ;;
    esac

fi

case "${RUNTIME}" in
    "crio" | "cri-o")
        cat <<EOF > /etc/crictl.yaml
runtime-endpoint: unix:///var/run/crio/crio.sock
EOF
        ;;
    *)
        cat <<EOF > /etc/crictl.yaml
runtime-endpoint: unix:///var/run/containerd/containerd.sock
EOF
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
  --node-ip=$(node_ip_addresses) \\
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
