#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

sudo mkdir -p /var/lib/kubernetes

sudo cp ca.pem kubernetes-key.pem kubernetes.pem /var/lib/kubernetes/

sudo mkdir -p /var/lib/cilium

sudo tee /var/lib/cilium/etcd-config.yml <<EOF
---
endpoints:
- https://${controllers_ips[0]}:2379
ca-file: '/var/lib/kubernetes/ca.pem'
EOF

sudo mkdir -p /etc/cni/net.d

sudo tee /etc/cni/net.d/10-cilium-cni.conf <<EOF
{
    "name": "cilium",
    "type": "cilium-cni",
    "mtu": 1450
}
EOF

sudo mkdir -p /opt/cni

wget https://storage.googleapis.com/kubernetes-release/network-plugins/cni-07a8a28637e97b22eb8dfe710eeae1344f69d16e.tar.gz

sudo tar -xvf cni-07a8a28637e97b22eb8dfe710eeae1344f69d16e.tar.gz -C /opt/cni

wget https://storage.googleapis.com/kubernetes-release/release/${k8s_version}/bin/linux/amd64/kubelet

chmod +x kubelet

sudo mv kubelet /usr/bin/

sudo mkdir -p /var/lib/kubelet/

sudo tee /var/lib/kubelet/kubeconfig <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: /var/lib/kubernetes/ca.pem
    server: https://${controllers_ips[0]}:6443
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: kubelet
  name: kubelet
current-context: kubelet
users:
- name: kubelet
  user:
    token: chAng3m3
EOF

sudo tee /etc/systemd/system/kubelet.service <<EOF
[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=docker.service
Requires=docker.service

[Service]
ExecPre=/bin/mount bpffs /sys/fs/bpf -t bpf
ExecStart=/usr/bin/kubelet \\
  --allow-privileged=true \\
  --api-servers=https://${controllers_ips[0]}:6443 \\
  --cloud-provider= \\
  --make-iptables-util-chains=false \\
  --cluster-dns=${cluster_dns_ip} \\
  --cluster-domain=cluster.local \\
  --container-runtime=docker \\
  --docker=unix:///var/run/docker.sock \\
  --network-plugin=cni \\
  --kubeconfig=/var/lib/kubelet/kubeconfig \\
  --serialize-image-pulls=false \\
  --tls-cert-file=/var/lib/kubernetes/kubernetes.pem \\
  --tls-private-key-file=/var/lib/kubernetes/kubernetes-key.pem \\
  --v=2

Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kubelet
sudo systemctl restart kubelet

sudo systemctl status kubelet --no-pager
