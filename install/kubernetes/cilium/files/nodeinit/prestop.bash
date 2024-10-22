#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

{{ .Values.nodeinit.prestop.preScript }}

if stat /tmp/node-deinit.cilium.io > /dev/null 2>&1; then
  exit 0
fi

echo "Waiting on pods to stop..."
if [ ! -f /etc/crictl.yaml ] || grep -q 'docker' /etc/crictl.yaml; then
  # Works for COS, ubuntu
  while docker ps | grep -v "node-init" | grep -q "POD_cilium"; do sleep 1; done
else
  # COS-beta (with containerd). Some versions of COS have crictl in /home/kubernetes/bin.
  while PATH="${PATH}:/home/kubernetes/bin" crictl ps | grep -v "node-init" | grep -q "POD_cilium"; do sleep 1; done
fi

if ip link show cilium_host; then
  echo "Deleting cilium_host interface..."
  ip link del cilium_host
fi

{{- if not (eq .Values.nodeinit.bootstrapFile "") }}
rm -f {{ .Values.nodeinit.bootstrapFile | quote }}
{{- end }}

rm -f /tmp/node-init.cilium.io
touch /tmp/node-deinit.cilium.io

{{- if .Values.nodeinit.reconfigureKubelet }}
# Check if we're running on a GKE containerd flavor.
GKE_KUBERNETES_BIN_DIR="/home/kubernetes/bin"
if [[ -f "${GKE_KUBERNETES_BIN_DIR}/gke" ]] && command -v containerd &>/dev/null; then
  CONTAINERD_CONFIG="/etc/containerd/config.toml"
  echo "Reverting changes to the containerd configuration"
  sed -Ei "s/^\#(\s+conf_template)/\1/g" "${CONTAINERD_CONFIG}"
  echo "Removing the kubelet wrapper"
  [[ -f "${GKE_KUBERNETES_BIN_DIR}/the-kubelet" ]] && mv "${GKE_KUBERNETES_BIN_DIR}/the-kubelet" "${GKE_KUBERNETES_BIN_DIR}/kubelet"
else
  echo "Changing kubelet configuration to --network-plugin=kubenet"
  sed -i "s:--network-plugin=cni\ --cni-bin-dir={{ .Values.cni.binPath }}:--network-plugin=kubenet:g" /etc/default/kubelet
fi
echo "Restarting the kubelet"
systemctl restart kubelet
{{- end }}

{{- if (and .Values.gke.enabled (or .Values.enableIPv4Masquerade .Values.gke.disableDefaultSnat))}}
# If the IP-MASQ chain exists, add back default jump rule from the GKE instance configure script
if iptables -w -t nat -L IP-MASQ > /dev/null; then
  iptables -w -t nat -A POSTROUTING -m comment --comment "ip-masq: ensure nat POSTROUTING directs all non-LOCAL destination traffic to our custom IP-MASQ chain" -m addrtype ! --dst-type LOCAL -j IP-MASQ
fi
{{- end }}

{{ .Values.nodeinit.prestop.postScript }}

echo "Node de-initialization complete"
