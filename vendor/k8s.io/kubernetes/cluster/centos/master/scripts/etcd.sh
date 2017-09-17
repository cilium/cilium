#!/bin/bash

# Copyright 2014 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

## Create etcd.conf, etcd.service, and start etcd service.


etcd_data_dir=/var/lib/etcd
mkdir -p ${etcd_data_dir}

ETCD_NAME=${1:-"default"}
ETCD_LISTEN_IP=${2:-"0.0.0.0"}
ETCD_INITIAL_CLUSTER=${3:-}

cat <<EOF >/opt/kubernetes/cfg/etcd.conf
# [member]
ETCD_NAME="${ETCD_NAME}"
ETCD_DATA_DIR="${etcd_data_dir}/default.etcd"
#ETCD_SNAPSHOT_COUNTER="10000"
#ETCD_HEARTBEAT_INTERVAL="100"
#ETCD_ELECTION_TIMEOUT="1000"
ETCD_LISTEN_PEER_URLS="https://${ETCD_LISTEN_IP}:2380"
ETCD_LISTEN_CLIENT_URLS="https://${ETCD_LISTEN_IP}:2379,https://127.0.0.1:2379"
#ETCD_MAX_SNAPSHOTS="5"
#ETCD_MAX_WALS="5"
#ETCD_CORS=""
#
#[cluster]
ETCD_INITIAL_ADVERTISE_PEER_URLS="https://${ETCD_LISTEN_IP}:2380"
# if you use different ETCD_NAME (e.g. test),
# set ETCD_INITIAL_CLUSTER value for this name, i.e. "test=http://..."
ETCD_INITIAL_CLUSTER="${ETCD_INITIAL_CLUSTER}"
ETCD_INITIAL_CLUSTER_STATE="new"
ETCD_INITIAL_CLUSTER_TOKEN="k8s-etcd-cluster"
ETCD_ADVERTISE_CLIENT_URLS="https://${ETCD_LISTEN_IP}:2379"
#ETCD_DISCOVERY=""
#ETCD_DISCOVERY_SRV=""
#ETCD_DISCOVERY_FALLBACK="proxy"
#ETCD_DISCOVERY_PROXY=""
#
#[proxy]
#ETCD_PROXY="off"
#
#[security]
CLIENT_CERT_AUTH="true"
ETCD_CA_FILE="/srv/kubernetes/etcd/ca.pem"
ETCD_CERT_FILE="/srv/kubernetes/etcd/server-${ETCD_NAME}.pem"
ETCD_KEY_FILE="/srv/kubernetes/etcd/server-${ETCD_NAME}-key.pem"
PEER_CLIENT_CERT_AUTH="true"
ETCD_PEER_CA_FILE="/srv/kubernetes/etcd/ca.pem"
ETCD_PEER_CERT_FILE="/srv/kubernetes/etcd/peer-${ETCD_NAME}.pem"
ETCD_PEER_KEY_FILE="/srv/kubernetes/etcd/peer-${ETCD_NAME}-key.pem"
EOF

cat <<EOF >//usr/lib/systemd/system/etcd.service
[Unit]
Description=Etcd Server
After=network.target

[Service]
Type=simple
WorkingDirectory=${etcd_data_dir}
EnvironmentFile=-/opt/kubernetes/cfg/etcd.conf
# set GOMAXPROCS to number of processors
ExecStart=/bin/bash -c "GOMAXPROCS=\$(nproc) /opt/kubernetes/bin/etcd"
Type=notify

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable etcd
systemctl restart etcd
