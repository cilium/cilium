#!/bin/sh

set -eu

HOST_PREFIX=${HOST_PREFIX:-/host}
if [ -z "${CILIUM_POLICY_ENFORCEMENT_INTERFACE}" ]; then
    CNI_CONF_NAME=${CNI_CONF_NAME:-05-cilium.conf}
else
    until ip link show "${CILIUM_POLICY_ENFORCEMENT_INTERFACE}" &>/dev/null ; do
        echo "Waiting for ${CILIUM_POLICY_ENFORCEMENT_INTERFACE} to be initialized"
        sleep 1s
    done
    CNI_CONF_NAME=${CNI_CONF_NAME:-04-cilium.conflist}
fi
MTU=${MTU:-1500}

BIN_NAME=cilium-cni
CNI_DIR=${CNI_DIR:-${HOST_PREFIX}/opt/cni}
CILIUM_CNI_CONF=${CILIUM_CNI_CONF:-${HOST_PREFIX}/etc/cni/net.d/${CNI_CONF_NAME}}

if [ ! -d ${CNI_DIR}/bin ]; then
	mkdir -p ${CNI_DIR}/bin
fi

# Install the CNI loopback driver if not installed already
if [ ! -f ${CNI_DIR}/bin/loopback ]; then
	echo "Installing loopback driver..."

	# Don't fail hard if this fails as it is usually not required
	cp /cni/loopback ${CNI_DIR}/bin/ || true
fi

echo "Installing ${BIN_NAME} to ${CNI_DIR}/bin/ ..."

# Move an eventual old existing binary out of the way, we can't delete it
# as it might be in use right now.
if [ -f "${CNI_DIR}/bin/${BIN_NAME}" ]; then
        rm -f ${CNI_DIR}/bin/${BIN_NAME}.old || true
        mv ${CNI_DIR}/bin/${BIN_NAME} ${CNI_DIR}/bin/${BIN_NAME}.old
fi

cp /opt/cni/bin/${BIN_NAME} ${CNI_DIR}/bin/

if [ -f "${CILIUM_CNI_CONF}" ]; then
	echo "Using existing ${CILIUM_CNI_CONF}..."
else
	echo "Installing new ${CILIUM_CNI_CONF}..."
    if [ -z "${CILIUM_POLICY_ENFORCEMENT_INTERFACE}" ]; then
        cat > ${CNI_CONF_NAME} <<EOF
{
    "name": "cilium",
    "type": "cilium-cni"
}
EOF
    else
        cat > ${CNI_CONF_NAME} <<EOF
{
  "cniVersion": "0.3.1",
  "name": "flannel-cilium",
  "plugins": [
    {
      "type": "flannel",
      "delegate": {
         "hairpinMode": true,
         "isDefaultGateway": true
      }
    },
    {
      "type": "portmap",
      "capabilities": {
        "portMappings": true
      }
    },
    {
       "name": "cilium",
       "type": "cilium-cni"
    }
  ]
}
EOF
    fi
	if [ ! -d $(dirname $CILIUM_CNI_CONF) ]; then
		mkdir -p $(dirname $CILIUM_CNI_CONF)
	fi

	mv ${CNI_CONF_NAME} ${CILIUM_CNI_CONF}
fi
