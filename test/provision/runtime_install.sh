#!/bin/bash
set -e

HOST=$(hostname)
PROVISIONSRC="/tmp/provision"

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${PROVISIONSRC}/helpers.bash"

sudo bash -c "echo MaxSessions 200 >> /etc/ssh/sshd_config"
sudo systemctl restart ssh

"${PROVISIONSRC}"/dns.sh

if [[ "${PROVISION_EXTERNAL_WORKLOAD}" == "false" ]]; then
    "${PROVISIONSRC}"/compile.sh
else
    "${PROVISIONSRC}"/externalworkload_install.sh
fi

"${PROVISIONSRC}"/wait-cilium.sh
