{ print }

# Add an init container to delay the start of the application containers for
# 10 seconds, to reduce the chance of dropping early traffic.
/initContainers:/ {
	indent = $0 ; sub(/[^ ].*/, "", indent)
	print indent "- name: sleep"
	print indent "  image: busybox:1.28.4"
	print indent "  imagePullPolicy: IfNotPresent"
	print indent "  command: ['sh', '-c', 'until nslookup kube-dns.kube-system.svc.cluster.local; do sleep 1; done']"
}

# Mount the Cilium state directory to give Cilium's Envoy filters access to the
# Cilium API.
/volumeMounts:/ {
	indent = $0 ; sub(/[^ ].*/, "", indent)
	print indent "- mountPath: /var/run/cilium"
	print indent "  name: cilium-unix-sock-dir"
}

# Define the Cilium state directory which contains the Cilium Unix domain
# sockets required by Cilium's Envoy filters.
/volumes:/ {
	indent = $0 ; sub(/[^ ].*/, "", indent)
	print indent "- hostPath:"
	print indent "    path: /var/run/cilium"
	print indent "  name: cilium-unix-sock-dir"
}
