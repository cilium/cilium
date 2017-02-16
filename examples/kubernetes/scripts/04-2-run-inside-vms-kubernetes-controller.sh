#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

sudo mkdir -p /var/lib/kubernetes

wget https://storage.googleapis.com/kubernetes-release/release/${k8s_version}/bin/linux/amd64/kube-apiserver

wget https://storage.googleapis.com/kubernetes-release/release/${k8s_version}/bin/linux/amd64/kube-controller-manager

wget https://storage.googleapis.com/kubernetes-release/release/${k8s_version}/bin/linux/amd64/kube-scheduler

wget https://storage.googleapis.com/kubernetes-release/release/${k8s_version}/bin/linux/amd64/kubectl

chmod +x kube-apiserver kube-controller-manager kube-scheduler kubectl

sudo mv kube-apiserver kube-controller-manager kube-scheduler kubectl /usr/bin/

sudo cp "${dir}/../deployments/token.csv" /var/lib/kubernetes/
sudo cp "${dir}/../deployments/authorization-policy.jsonl" /var/lib/kubernetes/

sudo tee /etc/systemd/system/kube-apiserver.service <<EOF
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
ExecStart=/usr/bin/kube-apiserver \\
  --admission-control=NamespaceLifecycle,LimitRanger,SecurityContextDeny,ResourceQuota \\
  --advertise-address=${controllers_ips[1]} \\
  --allow-privileged=true \\
  --apiserver-count=3 \\
  --authorization-mode=ABAC \\
  --authorization-policy-file=/var/lib/kubernetes/authorization-policy.jsonl \\
  --bind-address=0.0.0.0 \\
  --enable-swagger-ui=true \\
  --insecure-bind-address=0.0.0.0 \\
  --etcd-servers=http://${controllers_ips[0]}:2379 \\
  --service-cluster-ip-range=${k8s_service_cluster_ip_range} \\
  --service-node-port-range=30000-32767 \\
  --token-auth-file=/var/lib/kubernetes/token.csv \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kube-apiserver
sudo systemctl restart kube-apiserver

sudo systemctl status kube-apiserver --no-pager


sudo tee /etc/systemd/system/kube-controller-manager.service <<EOF
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
ExecStart=/usr/bin/kube-controller-manager \\
  --cluster-cidr=${k8s_cluster_cidr} \\
  --node-cidr-mask-size ${k8s_node_cidr_mask_size} \\
  --cluster-name=kubernetes \\
  --leader-elect=true \\
  --master=http://${controllers_ips[0]}:8080 \\
  --service-cluster-ip-range=${k8s_service_cluster_ip_range} \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kube-controller-manager
sudo systemctl restart kube-controller-manager

sudo systemctl status kube-controller-manager --no-pager

sudo tee /etc/systemd/system/kube-scheduler.service <<EOF
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
ExecStart=/usr/bin/kube-scheduler \\
  --leader-elect=true \\
  --master=http://${controllers_ips[0]}:8080 \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kube-scheduler
sudo systemctl restart kube-scheduler

sudo systemctl status kube-scheduler --no-pager

sleep 2s

kubectl -s http://${controllers_ips[0]}:8080 get componentstatuses
