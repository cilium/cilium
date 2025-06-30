#!/usr/bin/env bash
set -e

CILIUM_EXTRA_OPTS=${@}

export VMUSER=${VMUSER:-vagrant}
export PROVISIONSRC=${PROVISIONSRC:-/tmp/provision}
export GOPATH="/home/${VMUSER}/go"

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

cd ${GOPATH}/src/github.com/cilium/cilium

echo "Installing docker-plugin..."
if [[ "${CILIUM_DOCKER_PLUGIN_IMAGE}" == "" ]]; then
    make -C plugins/cilium-docker
    sudo make -C plugins/cilium-docker install
else
    ${PROVISIONSRC}/docker-run-cilium-docker-plugin.sh
fi

if [[ "${CILIUM_IMAGE}" == "" ]]; then
    export CILIUM_IMAGE=cilium/cilium:latest
    echo "Building Cilium..."
    make docker-cilium-image LOCKDEBUG=1
fi
sudo cp ${PROVISIONSRC}/docker-run-cilium.sh /usr/bin/docker-run-cilium

sudo mkdir -p /etc/sysconfig/
sed -e "s|CILIUM_IMAGE[^[:space:]]*$|CILIUM_IMAGE=${CILIUM_IMAGE}|" \
    -e "s|HOME=/home/vagrant|HOME=/home/${VMUSER}|" \
    -e "s|CILIUM_EXTRA_OPTS=.*|CILIUM_EXTRA_OPTS=${CILIUM_EXTRA_OPTS}|" contrib/systemd/cilium | sudo tee /etc/sysconfig/cilium

sudo cp -f contrib/systemd/*.* /etc/systemd/system/
# Use dockerized Cilium with runtime tests
sudo cp -f contrib/systemd/cilium.service-with-docker /etc/systemd/system/cilium.service

services_pattern="cilium*.service"
if ! mount | grep /sys/fs/bpf; then
    services_pattern+=" sys-fs-bpf.mount"
fi
services=$(cd /etc/systemd/system; ls -1 ${services_pattern})
for service in ${services}; do
    echo "installing service $service"
    sudo systemctl enable $service || echo "service $service failed"
    sudo systemctl restart $service || echo "service $service failed to restart"
done

echo "running \"sudo adduser ${VMUSER} cilium\" "
# Add group explicitly to avoid the case where the group was not added yet
getent group cilium >/dev/null || sudo groupadd -r cilium
sudo adduser ${VMUSER} cilium

# Download all images needed for runtime tests.
if [ -z "${SKIP_TEST_IMAGE_DOWNLOAD}" ]; then
    ./test/provision/container-images.sh test_images test/helpers
fi
