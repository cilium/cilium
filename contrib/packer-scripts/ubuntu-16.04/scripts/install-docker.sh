#!/bin/bash

set -e
docker_version="1.12.5"
wget https://get.docker.com/builds/Linux/x86_64/docker-${docker_version}.tgz

tar -xvf docker-${docker_version}.tgz

sudo cp docker/docker* /usr/bin/

sudo tee /etc/systemd/system/docker.service <<EOF
[Unit]
Description=Docker Application Container Engine
Documentation=http://docs.docker.io

[Service]
ExecStart=/usr/bin/docker daemon \\
  --iptables=false \\
  --ip-masq=false \\
  --host=unix:///var/run/docker.sock \\
  --log-level=error \\
  --storage-driver=overlay
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable docker
sudo systemctl restart docker

sudo groupadd docker
sudo usermod -aG docker vagrant
