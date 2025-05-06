#!/usr/bin/env bash

# all args are passed as cilium-agent options (except for "uninstall" below)
CILIUM_OPTS=$@
# Default kvstore to etcd
if [[ "${CILIUM_OPTS}" != *--kvstore* ]]; then
    CILIUM_OPTS+=" --kvstore etcd --kvstore-opt etcd.address=127.0.0.1:4001"
fi

CILIUM_IMAGE=${CILIUM_IMAGE:-quay.io/cilium/cilium:latest}

set -e
shopt -s extglob

# Run without sudo if not available (e.g., running as root)
SUDO=
if [ ! "$(whoami)" = "root" ] ; then
    SUDO=sudo
fi

CONTAINER_NAME="cilium"
HOST_BIN_DIR="/usr/bin" # Target directory for binaries on the host

# Helper function to check if container exists
container_exists() {
    ${SUDO} ctr c ls -q | grep -q "^${CONTAINER_NAME}$"
}

# Helper function to check if task exists/is running
task_exists() {
    ${SUDO} ctr task ls -q | grep -q "^${CONTAINER_NAME}$"
}

if [ "$1" = "uninstall" ] ; then
    echo "Shutting down running Cilium agent task (if any)..."
    # Force kill the task, ignore errors if not found
    ${SUDO} ctr task kill -s SIGKILL ${CONTAINER_NAME} > /dev/null 2>&1 || true
    # Wait briefly for task to terminate
    sleep 1
    echo "Removing Cilium container (if any)..."
    # Remove the container, ignore errors if not found
    ${SUDO} ctr c rm ${CONTAINER_NAME} > /dev/null 2>&1 || true

    if [ -f ${HOST_BIN_DIR}/cilium ] ; then
        echo "Removing ${HOST_BIN_DIR}/cilium"
        ${SUDO} rm -f ${HOST_BIN_DIR}/cilium
        echo "Removing ${HOST_BIN_DIR}/cilium-dbg"
        ${SUDO} rm -f ${HOST_BIN_DIR}/cilium-dbg
        echo "Removing ${HOST_BIN_DIR}/cilium-bugtool"
        ${SUDO} rm -f ${HOST_BIN_DIR}/cilium-bugtool
        echo "Removing ${HOST_BIN_DIR}/hubble"
        ${SUDO} rm -f ${HOST_BIN_DIR}/hubble
    fi
    exit 0
fi

# Check if container or task exists and clean up if necessary
if task_exists || container_exists; then
    echo "Shutting down running Cilium agent task (if any)..."
    ${SUDO} ctr task kill -s SIGKILL ${CONTAINER_NAME} > /dev/null 2>&1 || true
    sleep 1
    echo "Removing existing Cilium container (if any)..."
    ${SUDO} ctr c rm ${CONTAINER_NAME} > /dev/null 2>&1 || true
fi

# Ensure image exists locally
if ! ${SUDO} ctr image check ${CILIUM_IMAGE} > /dev/null 2>&1; then
    echo "Pulling Cilium image ${CILIUM_IMAGE}..."
    ${SUDO} ctr image pull ${CILIUM_IMAGE}
fi

echo "Launching Cilium agent ${CILIUM_IMAGE} with params ${CILIUM_OPTS}"

# Define mounts for ctr run
mkdir -p /var/lib/cilium/etcd
mkdir -p /var/run/cilium
mkdir -p /opt/cni/bin/

MOUNTS=""
MOUNTS+=" --mount type=bind,src=/var/lib/cilium/etcd,dst=/var/lib/cilium/etcd,options=rbind:rw"
MOUNTS+=" --mount type=bind,src=/var/run/cilium,dst=/var/run/cilium,options=rbind:rw"
MOUNTS+=" --mount type=bind,src=/boot,dst=/boot,options=rbind:ro"
MOUNTS+=" --mount type=bind,src=/lib/modules,dst=/lib/modules,options=rbind:ro"
MOUNTS+=" --mount type=bind,src=/sys/fs/bpf,dst=/sys/fs/bpf,options=rbind:rw"
MOUNTS+=" --mount type=bind,src=/run/xtables.lock,dst=/run/xtables.lock,options=rbind:rw"

echo "Copying Cilium binaries from container to ${HOST_BIN_DIR}"
# Use a temporary container to copy binaries out
# Mount the host's bin directory to /target inside the temp container
COPY_CMD="cp /usr/bin/cilium /opt/cni/bin/cilium-cni /etc/cni/net.d/05-cilium-cni.conf /usr/bin/cilium-dbg /usr/bin/cilium-bugtool /usr/bin/hubble /target/"
# Add optional binaries if clang is not present on host
if ! command -v "clang" >/dev/null 2>&1; then
  COPY_CMD+=" && cp /usr/local/bin/clang /usr/local/bin/llc /usr/sbin/tc /target/"
fi

${SUDO} ctr run --rm \
    --mount type=bind,src=${HOST_BIN_DIR},dst=/target,options=rbind:rw \
    ${CILIUM_IMAGE} \
    cilium-copy-$$ \
    sh -c "${COPY_CMD}"

${SUDO} mv ${HOST_BIN_DIR}/cilium-cni /opt/cni/bin/cilium-cni
${SUDO} mv ${HOST_BIN_DIR}/05-cilium-cni.conf /etc/cni/net.d/05-cilium-cni.conf

echo "Cilium binaries copied."

# ctr run command
# --restart is handled by systemd service file
# --log-driver is not applicable, logs go to stdout/stderr
# --cgroupns=host might be implicitly handled by --privileged or --net-host, or use --cgroup ""
# Using --privileged, --net-host, specific capabilities
${SUDO} ctr run \
    --privileged \
    --net-host \
    --cap-add CAP_NET_ADMIN \
    --cap-add CAP_SYS_MODULE \
    --cgroup "" \
    ${MOUNTS} \
    ${CILIUM_IMAGE} \
    ${CONTAINER_NAME} \
    /bin/bash -c "groupadd -f cilium && cilium-agent ${CILIUM_OPTS}"
