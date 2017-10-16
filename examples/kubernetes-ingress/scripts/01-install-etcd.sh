#!/usr/bin/env bash
#
# Installs, configures and starts etcd, it will use default values from
# ./helpers.bash
# Globals:
#   INSTALL, if set installs ETCD binaries, otherwise it will only configure etcd
#   ETCD_CLEAN, if set it will clean up ETCD directory `/var/lib/etcd`
#######################################

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

log "Installing etcd..."

certs_dir="${dir}/certs"

set -e

sudo mkdir -p /etc/etcd/

cp "${certs_dir}/etcd-server.pem" \
   "${certs_dir}/etcd-server-key.pem" \
   "${certs_dir}/ca-etcd.pem" \
   /etc/etcd/

if [ -n "${INSTALL}" ]; then
    log "Downloading etcd..."

    wget -nv https://github.com/coreos/etcd/releases/download/${etcd_version}/etcd-${etcd_version}-linux-amd64.tar.gz

    log "Downloading etcd... Done!"

    tar -xvf etcd-${etcd_version}-linux-amd64.tar.gz

    sudo mv etcd-${etcd_version}-linux-amd64/etcd* /usr/bin/
fi

if [ -n "${ETCD_CLEAN}" ] && [ -n "${RELOAD}" ]; then
    sudo service etcd stop
    sudo rm -fr /var/lib/etcd
fi

sudo mkdir -p /var/lib/etcd

ETCD_NAME=master

sudo tee /etc/systemd/system/etcd.service <<EOF
[Unit]
Description=etcd-${etcd_version}
Documentation=https://coreos.com/etcd/docs/${etcd_version:1}/index.html

[Service]
ExecStart=/usr/bin/etcd --name ${ETCD_NAME} \\
  --advertise-client-urls https://${controllers_ips[0]}:2379 \\
  --data-dir=/var/lib/etcd \\
  --initial-advertise-peer-urls https://${controllers_ips[0]}:2380 \\
  --initial-cluster-state new \\
  --initial-cluster-token etcd-cluster-0 \\
  --initial-cluster ${ETCD_NAME}=https://${controllers_ips[0]}:2380 \\
  --listen-client-urls https://${controllers_ips[0]}:2379,http://127.0.0.1:2379 \\
  --client-cert-auth \\
  --cert-file='/etc/etcd/etcd-server.pem' \\
  --key-file='/etc/etcd/etcd-server-key.pem' \\
  --trusted-ca-file='/etc/etcd/ca-etcd.pem'
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload

sudo systemctl enable etcd

sudo systemctl restart etcd

sudo systemctl status etcd --no-pager

log "Installing etcd... DONE!"
