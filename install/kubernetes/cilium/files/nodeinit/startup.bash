#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

echo "Link information:"
ip link

echo "Routing table:"
ip route

echo "Addressing:"
ip -4 a
ip -6 a

{{- if .Values.nodeinit.removeCbrBridge }}
if ip link show cbr0; then
  echo "Detected cbr0 bridge. Deleting interface..."
  ip link del cbr0
fi
{{- end }}

{{- if .Values.nodeinit.reconfigureKubelet }}
# GKE: Alter the kubelet configuration to run in CNI mode
echo "Changing kubelet configuration to --network-plugin=cni --cni-bin-dir={{ .Values.cni.binPath }}"
mkdir -p {{ .Values.cni.binPath }}
sed -i "s:--network-plugin=kubenet:--network-plugin=cni\ --cni-bin-dir={{ .Values.cni.binPath }}:g" /etc/default/kubelet
echo "Restarting kubelet..."
systemctl restart kubelet
{{- end }}

{{- if (and .Values.gke.enabled (or .Values.masquerade .Values.gke.disableDefaultSnat))}}
# If Cilium is configured to manage masquerading of traffic leaving the node,
# we need to disable the IP-MASQ chain because even if ip-masq-agent
# is not installed, the node init script installs some default rules into
# the IP-MASQ chain.
# If we remove the jump to that ip-masq chain, then we ensure the ip masquerade
# configuration is solely managed by Cilium.
# Also, if Cilium is installed, it may be expected that it would be solely responsible
# for the networking configuration on that node. So provide the same functionality
# as the --disable-snat-flag for existing GKE clusters.
iptables -w -t nat -D POSTROUTING -m comment --comment "ip-masq: ensure nat POSTROUTING directs all non-LOCAL destination traffic to our custom IP-MASQ chain" -m addrtype ! --dst-type LOCAL -j IP-MASQ || true
{{- end }}

{{- if not (eq .Values.nodeinit.bootstrapFile "") }}
date > {{ .Values.nodeinit.bootstrapFile }}
{{- end }}

{{- if .Values.azure.enabled }}
# AKS: If azure-vnet is installed on the node, and (still) configured in bridge mode,
# configure it as 'transparent' to be consistent with Cilium's CNI chaining config.
# If the azure-vnet CNI config is not removed, kubelet will execute CNI CHECK commands
# against it every 5 seconds and write 'bridge' to its state file, causing inconsistent
# behaviour when Pods are removed.
if [ -f /etc/cni/net.d/10-azure.conflist ]; then
  echo "Ensuring azure-vnet is configured in 'transparent' mode..."
  sed -i 's/"mode":\s*"bridge"/"mode":"transparent"/g' /etc/cni/net.d/10-azure.conflist
fi

# The azure0 interface being present means the node was booted with azure-vnet configured
# in bridge mode. This means there might be ebtables rules and neight entries interfering
# with pod connectivity if we deploy with Azure IPAM.
if ip l show dev azure0 >/dev/null 2>&1; then

  # In Azure IPAM mode, also remove the azure-vnet state file, otherwise ebtables rules get
  # restored by the azure-vnet CNI plugin on every CNI CHECK, which can cause connectivity
  # issues in Cilium-managed Pods. Since azure-vnet is no longer called on scheduling events,
  # this file can be removed.
  rm -f /var/run/azure-vnet.json

  # This breaks connectivity for existing workload Pods when Cilium is scheduled, but we need
  # to flush these to prevent Cilium-managed Pod IPs conflicting with Pod IPs previously allocated
  # by azure-vnet. These ebtables DNAT rules contain fixed MACs that are no longer bound on the node,
  # causing packets for these Pods to be redirected back out to the gateway, where they are dropped.
  echo 'Flushing ebtables pre/postrouting rules in nat table.. (disconnecting non-Cilium Pods!)'
  ebtables -t nat -F PREROUTING || true
  ebtables -t nat -F POSTROUTING || true

  # ip-masq-agent periodically injects PERM neigh entries towards the gateway
  # for all other k8s nodes in the cluster. These are safe to flush, as ARP can
  # resolve these nodes as usual. PERM entries will be automatically restored later.
  echo 'Deleting all permanent neighbour entries on azure0...'
  ip neigh show dev azure0 nud permanent | cut -d' ' -f1 | xargs -r -n1 ip neigh del dev azure0 to || true
fi
{{- end }}

{{- if .Values.nodeinit.revertReconfigureKubelet }}
rm -f /tmp/node-deinit.cilium.io
{{- end }}
echo "Node initialization complete"
