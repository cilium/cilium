#!/bin/bash

set -e

HOST_PREFIX=${HOST_PREFIX:-/host}

case "$CILIUM_CNI_CHAINING_MODE" in
"flannel")
	CNI_CONF_NAME=${CNI_CONF_NAME:-05-cilium.conflist}
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
CNI_EXCLUSIVE=true
while test $# -gt 0; do
  case "$1" in
    --enable-debug*)
      # shellcheck disable=SC2001
      ENABLE_DEBUG=$(echo "$1" | sed -e 's/^[^=]*=//g')
      shift
      ;;
    --cni-exclusive*)
      # shellcheck disable=SC2001
      CNI_EXCLUSIVE=$(echo "$1" | sed -e 's/^[^=]*=//g')
      shift
      ;;
    *)
      break
      ;;
  esac
done

CILIUM_CNI_CONF=${CILIUM_CNI_CONF:-${HOST_PREFIX}/etc/cni/net.d/${CNI_CONF_NAME}}
CNI_CONF_DIR="$(dirname "$CILIUM_CNI_CONF")"
CILIUM_CUSTOM_CNI_CONF=${CILIUM_CUSTOM_CNI_CONF:-false}

# The CILIUM_CUSTOM_CNI_CONF env is set by the `cni.customConf` Helm option.
# It stops this script from touching the host's CNI config directory.
# However, the agent will still write to the location specified by the
# `--write-cni-conf-when-ready` flag when `cni.configMap` is set.
if [ "${CILIUM_CUSTOM_CNI_CONF}" == "true" ]; then
	echo "User is managing Cilium's CNI config externally, exiting..."
	exit 0
fi

# Remove any active Cilium CNI configurations left over from previous installs
# to make sure the one we're installing later will take effect.
# Ignore the file specified by CNI_CONF_NAME. The agent will use this
# filename to write a user-specified CNI config and races against this script.
echo "Removing active Cilium CNI configurations from ${CNI_CONF_DIR}})..."
find "${CNI_CONF_DIR}" -maxdepth 1 -type f \
  -name '*cilium*' -and \( \
    -name '*.conf' -or \
    -name '*.conflist' \
  \) \
  -not -name "${CNI_CONF_NAME}" \
  -delete

# Rename all remaining CNI configurations to *.cilium_bak. This ensures only
# Cilium's CNI plugin will remain active. This makes sure Pods are not
# scheduled by another CNI when the Cilium agent is down during upgrades
# or restarts. See GH-14128 and related issues for more context.
if [ "${CNI_EXCLUSIVE}" != "false" ]; then
  find "$(dirname "${CILIUM_CNI_CONF}")" \
     -maxdepth 1 \
     -type f \
     \( -name '*.conf' \
     -or -name '*.conflist' \
     -or -name '*.json' \
     \) \
     -not \( -name '*.cilium_bak' \
     -or -name "${CNI_CONF_NAME}" \) \
     -exec mv {} {}.cilium_bak \;
fi

echo "Installing new ${CILIUM_CNI_CONF}..."
case "$CILIUM_CNI_CHAINING_MODE" in
"flannel")
	cat > "${CNI_CONF_NAME}" <<EOF
{
  "cniVersion": "0.3.1",
  "name": "flannel",
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
	cat > "${CNI_CONF_NAME}" <<EOF
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
	cat > "${CNI_CONF_NAME}" <<EOF
{
  "cniVersion": "0.3.1",
  "name": "aws-cni",
  "plugins": [
    {
      "name": "aws-cni",
      "type": "aws-cni",
      "vethPrefix": "eni",
      "mtu": "9001",
      "pluginLogFile": "/var/log/aws-routed-eni/plugin.log",
      "pluginLogLevel": "DEBUG"
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
	cat > "${CNI_CONF_NAME}" <<EOF
{
  "cniVersion": "0.3.1",
  "name": "cilium",
  "type": "cilium-cni",
  "enable-debug": ${ENABLE_DEBUG}
}
EOF
	;;
esac

if [ ! -d "$(dirname "$CILIUM_CNI_CONF")" ]; then
	mkdir -p "$(dirname "$CILIUM_CNI_CONF")"
fi

mv "${CNI_CONF_NAME}" "${CILIUM_CNI_CONF}"
