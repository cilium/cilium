#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

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

systemctl disable sys-fs-bpf.mount || true
systemctl stop sys-fs-bpf.mount || true

if ip link show cilium_host; then
  echo "Deleting cilium_host interface..."
  ip link del cilium_host
fi

{{- if not (eq .Values.nodeinit.bootstrapFile "") }}
rm -f {{ .Values.nodeinit.bootstrapFile }}
{{- end }}

rm -f /tmp/node-init.cilium.io
touch /tmp/node-deinit.cilium.io

{{- if .Values.nodeinit.reconfigureKubelet }}
echo "Changing kubelet configuration to --network-plugin=kubenet"
sed -i "s:--network-plugin=cni\ --cni-bin-dir={{ .Values.cni.binPath }}:--network-plugin=kubenet:g" /etc/default/kubelet
echo "Restarting kubelet..."
systemctl restart kubelet
{{- end }}

{{- if (and .Values.gke.enabled (or .Values.masquerade .Values.gke.disableDefaultSnat))}}
# If the IP-MASQ chain exists, add back default jump rule from the GKE instance configure script
if iptables -w -t nat -L IP-MASQ > /dev/null; then
  iptables -w -t nat -A POSTROUTING -m comment --comment "ip-masq: ensure nat POSTROUTING directs all non-LOCAL destination traffic to our custom IP-MASQ chain" -m addrtype ! --dst-type LOCAL -j IP-MASQ
fi
{{- end }}

echo "Node de-initialization complete"
