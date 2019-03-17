# Replace the Istio sidecar proxy image with the Cilium-specific image.

/{{ .Values.global.hub }}\/{{ .Values.global.proxy.image }}/ {
	indent = $0 ; gsub(/[^ ].*/, "", indent)
	print indent "{{ if eq .Values.global.proxy.image \"proxy_debug\" -}}"
	print indent "docker.io/cilium/istio_proxy_debug:{{ .Values.global.tag }}"
	print indent "{{ else -}}"
	print indent "docker.io/cilium/istio_proxy:{{ .Values.global.tag }}"
	$0 = indent "{{ end -}}"
}

{ print }

# Add an init container to delay the start of the application containers,
# to reduce the chance of dropping early traffic.
/initContainers:/ {
	indent = $0 ; gsub(/[^ ].*/, "", indent)
	print indent "- name: sleep"
	print indent "  image: busybox:1.28.4"
	print indent "  imagePullPolicy: IfNotPresent"
	print indent "  command: ['sh', '-c', 'max=120; i=0; until nslookup kube-dns.kube-system.svc.cluster.local; do i=$((i + 1)); if [ $i -eq $max ]; then echo timed-out; exit 1; else sleep 1; fi done ']"
}

# Mount the Cilium state directory to give Cilium's Envoy filters access to the
# Cilium API.
/volumeMounts:/ {
	indent = $0 ; gsub(/[^ ].*/, "", indent)
	print indent "- mountPath: /var/run/cilium"
	print indent "  name: cilium-unix-sock-dir"
}

# Define the Cilium state directory which contains the Cilium Unix domain
# sockets required by Cilium's Envoy filters.
/volumes:/ {
	indent = $0 ; gsub(/[^ ]*/, "", indent)
	print indent "- hostPath:"
	print indent "    path: /var/run/cilium"
	print indent "  name: cilium-unix-sock-dir"
}
