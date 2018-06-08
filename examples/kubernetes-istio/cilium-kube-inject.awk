# Replace the Istio sidecar proxy image with the Cilium-specific image.
/proxy:/ || /proxy_debug:/ || /proxyv2:/ {
	gsub(/[^" ]*proxy:/, "docker.io/cilium/istio_proxy:")
	gsub(/[^" ]*proxy_debug:/, "docker.io/cilium/istio_proxy_debug:")
	gsub(/[^" ]*proxyv2:/, "docker.io/cilium/istio_proxy:")
}

{ print }

# Mount the Cilium state directory to give Cilium's Envoy filters access to the
# Cilium API.
/volumeMounts:/ {
	indent = $0 ; gsub(/[^ ]*/, "", indent)
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
