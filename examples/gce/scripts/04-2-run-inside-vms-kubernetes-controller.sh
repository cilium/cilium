#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

sudo mkdir -p /var/lib/kubernetes
sudo cp ca.pem kubernetes-key.pem kubernetes.pem /var/lib/kubernetes/

wget https://storage.googleapis.com/kubernetes-release/release/${k8s_version}/bin/linux/amd64/kube-apiserver

wget https://storage.googleapis.com/kubernetes-release/release/${k8s_version}/bin/linux/amd64/kube-controller-manager

wget https://storage.googleapis.com/kubernetes-release/release/${k8s_version}/bin/linux/amd64/kube-scheduler

wget https://storage.googleapis.com/kubernetes-release/release/${k8s_version}/bin/linux/amd64/kubectl

chmod +x kube-apiserver kube-controller-manager kube-scheduler kubectl

sudo mv kube-apiserver kube-controller-manager kube-scheduler kubectl /usr/bin/

wget https://raw.githubusercontent.com/cilium/cilium/gce-example/examples/gce/deployments/token.csv

sudo mv token.csv /var/lib/kubernetes/

wget https://raw.githubusercontent.com/cilium/cilium/gce-example/examples/gce/deployments/authorization-policy.jsonl

sudo mv authorization-policy.jsonl /var/lib/kubernetes/

INTERNAL_IP=$(curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip)

sudo tee /etc/systemd/system/kube-apiserver.service <<EOF
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
ExecStart=/usr/bin/kube-apiserver \\
  --admission-control=NamespaceLifecycle,LimitRanger,SecurityContextDeny,ServiceAccount,ResourceQuota \\
  --advertise-address=${INTERNAL_IP} \\
  --allow-privileged=true \\
  --apiserver-count=3 \\
  --authorization-mode=ABAC \\
  --authorization-policy-file=/var/lib/kubernetes/authorization-policy.jsonl \\
  --bind-address=0.0.0.0 \\
  --enable-swagger-ui=true \\
  --etcd-cafile=/var/lib/kubernetes/ca.pem \\
  --insecure-bind-address=0.0.0.0 \\
  --kubelet-certificate-authority=/var/lib/kubernetes/ca.pem \\
  --etcd-servers=https://${controllers_ips[0]}:2379,controller1=https://${controllers_ips[1]}:2379,controller2=https://${controllers_ips[2]}:2379 \\
  --service-account-key-file=/var/lib/kubernetes/kubernetes-key.pem \\
  --service-cluster-ip-range=${k8s_service_cluster_ip_range} \\
  --service-node-port-range=30000-32767 \\
  --tls-cert-file=/var/lib/kubernetes/kubernetes.pem \\
  --tls-private-key-file=/var/lib/kubernetes/kubernetes-key.pem \\
  --token-auth-file=/var/lib/kubernetes/token.csv \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kube-apiserver
sudo systemctl start kube-apiserver

sudo systemctl status kube-apiserver --no-pager


sudo tee /etc/systemd/system/kube-controller-manager.service <<EOF
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
ExecStart=/usr/bin/kube-controller-manager \\
  --allocate-node-cidrs \\
  --cluster-cidr=${k8s_cluster_cidr} \\
  --node-cidr-mask-size ${k8s_node_cidr_mask_size} \\
  --cluster-name=kubernetes \\
  --leader-elect=true \\
  --master=http://${INTERNAL_IP}:8080 \\
  --root-ca-file=/var/lib/kubernetes/ca.pem \\
  --service-account-private-key-file=/var/lib/kubernetes/kubernetes-key.pem \\
  --service-cluster-ip-range=${k8s_service_cluster_ip_range} \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kube-controller-manager
sudo systemctl start kube-controller-manager

sudo systemctl status kube-controller-manager --no-pager

sudo tee /etc/systemd/system/kube-scheduler.service <<EOF
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
ExecStart=/usr/bin/kube-scheduler \\
  --leader-elect=true \\
  --master=http://${INTERNAL_IP}:8080 \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kube-scheduler
sudo systemctl start kube-scheduler


sudo systemctl status kube-scheduler --no-pager

sleep 2s

kubectl get componentstatuses
