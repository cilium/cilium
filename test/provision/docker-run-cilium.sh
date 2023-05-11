#!/usr/bin/env bash

# all args are passed as cilium-agent options (except for "uninstall" below)
CILIUM_OPTS=$@
# Default kvstore to consul
if [[ "${CILIUM_OPTS}" != *--kvstore* ]]; then
    CILIUM_OPTS+=" --kvstore consul --kvstore-opt consul.address=127.0.0.1:8500"
fi

CILIUM_IMAGE=${CILIUM_IMAGE:-cilium/cilium:latest}

set -e
shopt -s extglob

# Run without sudo if not available (e.g., running as root)
SUDO=
if [ ! "$(whoami)" = "root" ] ; then
    SUDO=sudo
fi

if [ "$1" = "uninstall" ] ; then
    if [ -n "$(${SUDO} docker ps -a -q -f label=app=cilium)" ]; then
        echo "Shutting down running Cilium agent"
        ${SUDO} docker rm -f cilium || true
    fi
    if [ -f /usr/bin/cilium ] ; then
        echo "Removing /usr/bin/cilium"
        ${SUDO} rm /usr/bin/cilium
        echo "Removing /usr/bin/cilium-bugtool"
        ${SUDO} rm /usr/bin/cilium-bugtool
    fi
    exit 0
fi

DOCKER_OPTS=" -d --log-driver local --restart always"
DOCKER_OPTS+=" --privileged --network host --cap-add NET_ADMIN --cap-add SYS_MODULE"
# Run cilium agent in the host's cgroup namespace so that
# socket-based load balancing works as expected.
# See https://github.com/cilium/cilium/pull/16259 for more details.
DOCKER_OPTS+=" --cgroupns=host"
DOCKER_OPTS+=" --volume /var/lib/cilium/etcd:/var/lib/cilium/etcd"
DOCKER_OPTS+=" --volume /var/run/cilium:/var/run/cilium"
DOCKER_OPTS+=" --volume /boot:/boot"
DOCKER_OPTS+=" --volume /lib/modules:/lib/modules"
DOCKER_OPTS+=" --volume /sys/fs/bpf:/sys/fs/bpf"
DOCKER_OPTS+=" --volume /run/xtables.lock:/run/xtables.lock"
DOCKER_OPTS+=" --label app=cilium"

if [ -n "$(${SUDO} docker ps -a -q -f label=app=cilium)" ]; then
    echo "Shutting down running Cilium agent"
    ${SUDO} docker rm -f cilium || true
fi

echo "Launching Cilium agent $CILIUM_IMAGE with params $CILIUM_OPTS"
${SUDO} docker run --name cilium $DOCKER_OPTS $CILIUM_IMAGE /bin/bash -c "groupadd -f cilium && cilium-agent $CILIUM_OPTS"

# Copy Cilium CLI
${SUDO} docker cp cilium:/usr/bin/cilium /usr/bin/
${SUDO} docker cp cilium:/usr/bin/cilium-bugtool /usr/bin/
${SUDO} docker cp cilium:/usr/bin/hubble /usr/bin/
# These programs are not statically linked so they might break in the case
# of GHA runners are upgraded.
if ! command -v "clang" >/dev/null 2>&1; then
  ${SUDO} docker cp cilium:/usr/local/bin/clang /usr/bin/
  ${SUDO} docker cp cilium:/usr/local/bin/llc /usr/bin/
  ${SUDO} docker cp cilium:/usr/local/bin/tc /usr/bin/
fi
