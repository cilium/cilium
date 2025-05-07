#!/usr/bin/env bash
set -e

CILIUM_EXTRA_OPTS=${@}

HOST=$(hostname)
PROVISIONSRC="/tmp/provision"

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${PROVISIONSRC}/helpers.bash"

sudo bash -c "echo MaxSessions 200 >> /etc/ssh/sshd_config"
sudo systemctl restart ssh

"${PROVISIONSRC}"/dns.sh

sudo systemctl status systemd-resolved.service || true
# Remove symlinked resolv.conf to systemd-resolved
rm /etc/resolv.conf
# Remove systemd-resolvd resolv.conf to avoid being read by docker
rm /run/systemd/resolve/stub-resolv.conf || true
# Explicitly set nameserver 1.1.1.1 for runtime tests
# to avoid chases with Cilium DNS
echo "nameserver 1.1.1.1" > /etc/resolv.conf
cat /etc/resolv.conf

# Ensure default config file exists
sudo apt-get update
sudo apt-get install containerd -y
sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml > /dev/null

# Set bin_dir and conf_dir for the CNI plugin
sudo sed -i 's|^#* *\(bin_dir = \).*|\1"/opt/cni/bin"|' /etc/containerd/config.toml
sudo sed -i 's|^#* *\(conf_dir = \).*|\1"/etc/cni/net.d"|' /etc/containerd/config.toml

sudo mkdir -p /etc/cni/net.d

"${PROVISIONSRC}"/compile.sh ${CILIUM_EXTRA_OPTS}
sudo systemctl restart containerd.service