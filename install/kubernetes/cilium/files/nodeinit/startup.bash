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

{{ .Values.nodeinit.startup.preScript }}

{{- if .Values.nodeinit.removeCbrBridge }}
if ip link show cbr0; then
  echo "Detected cbr0 bridge. Deleting interface..."
  ip link del cbr0
fi
{{- end }}

{{- if .Values.nodeinit.reconfigureKubelet }}
# Check if we're running on a GKE containerd flavor as indicated by the presence
# of the '--container-runtime-endpoint' flag in '/etc/default/kubelet'.
GKE_KUBERNETES_BIN_DIR="/home/kubernetes/bin"
KUBELET_DEFAULTS_FILE="/etc/default/kubelet"
if [[ -f "${GKE_KUBERNETES_BIN_DIR}/gke" ]] && [[ $(grep -cF -- '--container-runtime-endpoint' "${KUBELET_DEFAULTS_FILE}") == "1" ]]; then
  echo "GKE *_containerd flavor detected..."

  # (GKE *_containerd) Upon node restarts, GKE's containerd images seem to reset
  # the /etc directory and our changes to the kubelet and Cilium's CNI
  # configuration are removed. This leaves room for containerd and its CNI to
  # take over pods previously managed by Cilium, causing Cilium to lose
  # ownership over these pods. We rely on the empirical observation that
  # /home/kubernetes/bin/kubelet is not changed across node reboots, and replace
  # it with a wrapper script that performs some initialization steps when
  # required and then hands over control to the real kubelet.

  # Only create the kubelet wrapper if we haven't previously done so.
  if [[ ! -f "${GKE_KUBERNETES_BIN_DIR}/the-kubelet" ]];
  then
    echo "Installing the kubelet wrapper..."

    # Rename the real kubelet.
    mv "${GKE_KUBERNETES_BIN_DIR}/kubelet" "${GKE_KUBERNETES_BIN_DIR}/the-kubelet"

    # Initialize the kubelet wrapper which lives in the place of the real kubelet.
    touch "${GKE_KUBERNETES_BIN_DIR}/kubelet"
    chmod a+x "${GKE_KUBERNETES_BIN_DIR}/kubelet"

    # Populate the kubelet wrapper. It will perform the initialization steps we
    # need and then become the kubelet.
    cat <<'EOF' | tee "${GKE_KUBERNETES_BIN_DIR}/kubelet"
#!/bin/bash

set -euo pipefail

CNI_CONF_DIR="/etc/cni/net.d"
CONTAINERD_CONFIG="/etc/containerd/config.toml"

# kubelet version string format is "Kubernetes v1.24-gke.900"
K8S_VERSION=$(/home/kubernetes/bin/the-kubelet --version)

# Helper to check if a version string, passed as first parameter, is greater than or
# equal the one passed as second parameter.
function version_gte() {
	[[ "$(printf '%s\n' "${2}" "${1}" | sort -V | head -n1)" = "${2}" ]] && return
}

# Only stop and start containerd if the Cilium CNI configuration does not exist,
# or if the 'conf_template' property is present in the containerd config file,
# in order to avoid unnecessarily restarting containerd.
if [[ -z "$(find "${CNI_CONF_DIR}" -type f -name '*cilium*')" || \
      "$(grep -cE '^\s+conf_template' "${CONTAINERD_CONFIG}")" != "0" ]];
then
  # Stop containerd as it starts by creating a CNI configuration from a template
  # causing pods to start with IPs assigned by GKE's CNI.
  # 'disable --now' is used instead of stop as this script runs concurrently
  # with containerd on node startup, and hence containerd might not have been
  # started yet, in which case 'disable' prevents it from starting.
  echo "Disabling and stopping containerd"
  systemctl disable --now containerd

  # Remove any pre-existing files in the CNI configuration directory. We skip
  # any possibly existing Cilium configuration file for the obvious reasons.
  echo "Removing undesired CNI configuration files"
  find "${CNI_CONF_DIR}" -type f -not -name '*cilium*' -exec rm {} \;

  # As mentioned above, the containerd configuration needs a little tweak in
  # order not to create the default CNI configuration, so we update its config.
  echo "Fixing containerd configuration"
  sed -Ei 's/^(\s+conf_template)/\#\1/g' "${CONTAINERD_CONFIG}"

  if version_gte "${K8S_VERSION#"Kubernetes "}" "v1.24"; then
    # Starting from GKE node version 1.24, containerd version used is 1.6.
    # Since that version containerd no longer allows missing configuration for the CNI,
    # not even for pods with hostNetwork set to true. Thus, we add a temporary one.
    # This will be replaced with the real config by the agent pod.
    echo -e '{\n\t"cniVersion": "0.3.1",\n\t"name": "cilium",\n\t"type": "cilium-cni"\n}' > /etc/cni/net.d/05-cilium.conf
  fi

  # Start containerd. It won't create it's CNI configuration file anymore.
  echo "Enabling and starting containerd"
  systemctl enable --now containerd
fi

# Become the real kubelet and, for k8s < 1.24, pass it additional dockershim
# flags (and place these last so they have precedence).
if version_gte "${K8S_VERSION#"Kubernetes "}" "v1.24"; then
  exec /home/kubernetes/bin/the-kubelet "${@}"
else
  exec /home/kubernetes/bin/the-kubelet "${@}" --network-plugin=cni --cni-bin-dir={{ .Values.cni.binPath }}
fi
EOF
  else
    echo "Kubelet wrapper already exists, skipping..."
  fi
else
  # kubelet version string format is "Kubernetes v1.24-gke.900"
  K8S_VERSION=$(kubelet --version)

  # Helper to check if a version string, passed as first parameter, is greater than or
  # equal the one passed as second parameter.
  function version_gte() {
    [[ "$(printf '%s\n' "${2}" "${1}" | sort -V | head -n1)" = "${2}" ]] && return
  }

  # Dockershim flags have been removed since k8s 1.24.
  if ! version_gte "${K8S_VERSION#"Kubernetes "}" "v1.24"; then
    # (Generic) Alter the kubelet configuration to run in CNI mode
    echo "Changing kubelet configuration to --network-plugin=cni --cni-bin-dir={{ .Values.cni.binPath }}"
    mkdir -p {{ .Values.cni.binPath }}
    sed -i "s:--network-plugin=kubenet:--network-plugin=cni\ --cni-bin-dir={{ .Values.cni.binPath }}:g" "${KUBELET_DEFAULTS_FILE}"
  fi
fi
echo "Restarting the kubelet..."
systemctl restart kubelet
{{- end }}

{{- if (and .Values.gke.enabled (or .Values.enableIPv4Masquerade .Values.gke.disableDefaultSnat))}}
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
mkdir -p {{ .Values.nodeinit.bootstrapFile | dir | quote }}
date > {{ .Values.nodeinit.bootstrapFile | quote }}
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

{{ .Values.nodeinit.startup.postScript }}

echo "Node initialization complete"
