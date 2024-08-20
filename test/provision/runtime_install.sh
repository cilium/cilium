#!/usr/bin/env bash
set -e

CILIUM_EXTRA_OPTS=${@}

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

sudo systemctl status systemd-resolved.service || true
# Remove symlinked resolv.conf to systemd-resolved
rm /etc/resolv.conf
# Remove systemd-resolvd resolv.conf to avoid being read by docker
rm /run/systemd/resolve/stub-resolv.conf || true
# Explicitly set nameserver 1.1.1.1 for runtime tests
# to avoid chases with Cilium DNS
echo "nameserver 1.1.1.1" > /etc/resolv.conf
cat /etc/resolv.conf

# Restarting docker to use correct nameserver
service docker restart

if [[ "${PROVISION_EXTERNAL_WORKLOAD}" == "false" ]]; then
    "${PROVISIONSRC}"/compile.sh ${CILIUM_EXTRA_OPTS}
    "${PROVISIONSRC}"/wait-cilium-in-docker.sh
else
    "${PROVISIONSRC}"/externalworkload_install.sh
fi
