#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

sudo mkdir -p /etc/etcd/

wget https://github.com/coreos/etcd/releases/download/${etcd_version}/etcd-${etcd_version}-linux-amd64.tar.gz

tar -xvf etcd-${etcd_version}-linux-amd64.tar.gz

sudo mv etcd-${etcd_version}-linux-amd64/etcd* /usr/bin/

sudo mkdir -p /var/lib/etcd

ETCD_NAME=controller0

sudo tee /etc/systemd/system/etcd.service <<EOF
[Unit]
Description=etcd
Documentation=https://github.com/coreos

[Service]
ExecStart=/usr/bin/etcd --name ${ETCD_NAME} \\
  --initial-advertise-peer-urls http://${controllers_ips[0]}:2380 \\
  --listen-peer-urls http://${controllers_ips[0]}:2380 \\
  --listen-client-urls http://${controllers_ips[0]}:2379,http://127.0.0.1:2379 \\
  --advertise-client-urls http://${controllers_ips[0]}:2379 \\
  --initial-cluster-token etcd-cluster-0 \\
  --initial-cluster controller0=http://${controllers_ips[0]}:2380 \\
  --initial-cluster-state new \\
  --data-dir=/var/lib/etcd
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload

sudo systemctl enable etcd

sudo systemctl restart etcd

sudo systemctl status etcd --no-pager

sudo etcdctl cluster-health
