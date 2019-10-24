#!/bin/sh

set -e

# Backwards compatibility
if [ ! -z "${CILIUM_FLANNEL_MASTER_DEVICE}" ]; then
	CILIUM_CNI_CHAINING_MODE="flannel"
fi

HOST_PREFIX=${HOST_PREFIX:-/host}

case "$CILIUM_CNI_CHAINING_MODE" in
"flannel")
	until ip link show "${CILIUM_FLANNEL_MASTER_DEVICE}" &>/dev/null ; do
		echo "Waiting for ${CILIUM_FLANNEL_MASTER_DEVICE} to be initialized"
		sleep 1s
	done
	CNI_CONF_NAME=${CNI_CONF_NAME:-04-flannel-cilium-cni.conflist}
	;;
"generic-veth")
	CNI_CONF_NAME=${CNI_CONF_NAME:-05-cilium.conflist}
	;;
"portmap")
	CNI_CONF_NAME=${CNI_CONF_NAME:-05-cilium.conflist}
	;;
"aws-cni")
	CNI_CONF_NAME=${CNI_CONF_NAME:-05-cilium.conflist}
	;;
*)
	CNI_CONF_NAME=${CNI_CONF_NAME:-05-cilium.conf}
	;;
esac

ENABLE_DEBUG=false
while test $# -gt 0; do
  case "$1" in
    --enable-debug*)
      ENABLE_DEBUG=`echo $1 | sed -e 's/^[^=]*=//g'`
      shift
      ;;
    *)
      break
      ;;
  esac
done

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

if [ "${CILIUM_CUSTOM_CNI_CONF}" = "true" ]; then
	echo "Using custom ${CILIUM_CNI_CONF}..."
	exit 0
fi

echo "Installing new ${CILIUM_CNI_CONF}..."
case "$CILIUM_CNI_CHAINING_MODE" in
"flannel")
	cat > ${CNI_CONF_NAME} <<EOF
{
  "cniVersion": "0.3.1",
  "name": "cbr0",
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
       "type": "cilium-cni",
       "enable-debug": ${ENABLE_DEBUG}
    }
  ]
}
EOF
	;;

"portmap")
	cat > ${CNI_CONF_NAME} <<EOF
{
  "cniVersion": "0.3.1",
  "name": "portmap",
  "plugins": [
    {
       "name": "cilium",
       "type": "cilium-cni",
       "enable-debug": ${ENABLE_DEBUG}
    },
    {
      "type": "portmap",
      "capabilities": {"portMappings": true}
    }
  ]
}
EOF
	;;

"aws-cni")
	cat > ${CNI_CONF_NAME} <<EOF
{
  "cniVersion": "0.3.1",
  "name": "aws-cni",
  "plugins": [
    {
      "name": "aws-cni",
      "type": "aws-cni",
      "vethPrefix": "eni"
    },
    {
      "type": "portmap",
      "capabilities": {"portMappings": true},
      "snat": true
    },
    {
       "name": "cilium",
       "type": "cilium-cni",
       "enable-debug": ${ENABLE_DEBUG}
    }
  ]
}
EOF
	;;

*)
	cat > ${CNI_CONF_NAME} <<EOF
{
  "cniVersion": "0.3.1",
  "name": "cilium",
  "type": "cilium-cni",
  "enable-debug": ${ENABLE_DEBUG}
}
EOF
	;;
esac

if [ ! -d $(dirname $CILIUM_CNI_CONF) ]; then
	mkdir -p $(dirname $CILIUM_CNI_CONF)
fi

mv ${CNI_CONF_NAME} ${CILIUM_CNI_CONF}

# Allow switching between chaining and direct CNI mode by removing the
# currently unused configuration file
case "${CNI_CONF_NAME}" in
"05-cilium.conf")
	rm ${HOST_PREFIX}/etc/cni/net.d/05-cilium.conflist || true
	;;
"05-cilium.conflist")
	rm ${HOST_PREFIX}/etc/cni/net.d/05-cilium.conf || true
	;;
esac
