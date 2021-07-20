#!/bin/bash
set -e

if ! [[ -z $DOCKER_LOGIN && -z $DOCKER_PASSWORD ]]; then
    echo "${DOCKER_PASSWORD}" | docker login -u "${DOCKER_LOGIN}" --password-stdin
fi

HOST=$(hostname)
PROVISIONSRC="/tmp/provision"

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${PROVISIONSRC}/helpers.bash"

sudo bash -c "echo MaxSessions 200 >> /etc/ssh/sshd_config"
sudo systemctl restart ssh

"${PROVISIONSRC}"/dns.sh

# Temporary fix until https://github.com/cilium/packer-ci-build/pull/278 is
# merged. Necessary as Cilium now needs ipset for iptables masquerading.
sudo apt-get install -y ipset

if [[ "${PROVISION_EXTERNAL_WORKLOAD}" == "false" ]]; then
    "${PROVISIONSRC}"/compile.sh
    "${PROVISIONSRC}"/wait-cilium.sh
else
    "${PROVISIONSRC}"/externalworkload_install.sh
fi
