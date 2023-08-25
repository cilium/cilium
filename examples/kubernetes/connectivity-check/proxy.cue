package connectivity_check

// deployment (defaults.cue) implicitly configures the deployments below such
// that deployments with names matching 'pod-to-<X>', '*-[intra|multi]-node'
// and '*-headless' will contact the related echo server via the related
// service and will be scheduled with affinity / anti-affinity to that server.
_proxyResource: {
	_enableMultipleContainers: true

	metadata: labels: component: "proxy-check"
}

_egressL7Policy: {
	_allowDNS: true

	_port:   *"8080" | string
	_target: *"" | string
	_rules: [{
		if _target != "" {
			toEndpoints: [{
				matchLabels: {
					name: _target
				}
			}]
		}
		toPorts: [{
			ports: [{
				port:     _port
				protocol: "TCP"
			}]
			rules: {
				http: [{
					method: "GET"
					path:   "/public$"
				}]
			}
		}]
	}]
}

// Pod-to-a (egress policy, no ingress policy)
_egressEchoAPolicy: _egressL7Policy & {
	_target: "echo-a"
	metadata: labels: component: "proxy-check"
}
deployment: "pod-to-a-intra-node-proxy-egress-policy": _proxyResource
egressCNP: "pod-to-a-intra-node-proxy-egress-policy":  _proxyResource & _egressEchoAPolicy
deployment: "pod-to-a-multi-node-proxy-egress-policy": _proxyResource
egressCNP: "pod-to-a-multi-node-proxy-egress-policy":  _proxyResource & _egressEchoAPolicy

// Pod-to-c (no egress policy, ingress policy via echo-servers.cue)
deployment: "pod-to-c-intra-node-proxy-ingress-policy": _proxyResource
deployment: "pod-to-c-multi-node-proxy-ingress-policy": _proxyResource

// Pod-to-c (egress + ingress policy)
_egressEchoCPolicy: _egressL7Policy & {
	_target: "echo-c"
	metadata: labels: component: "proxy-check"
}
deployment: "pod-to-c-intra-node-proxy-to-proxy-policy": _proxyResource
egressCNP: "pod-to-c-intra-node-proxy-to-proxy-policy":  _proxyResource & _egressEchoCPolicy
deployment: "pod-to-c-multi-node-proxy-to-proxy-policy": _proxyResource
egressCNP: "pod-to-c-multi-node-proxy-to-proxy-policy":  _proxyResource & _egressEchoCPolicy

// Pod-to-hostport (egress policy, no ingress policy)
_hostPortProxyResource: {
	_enableMultipleContainers: true
	_probeTarget:              "echo-c-host-headless:40001"

	metadata: labels: {
		component:  "hostport-check"
		quarantine: "true"
	}
}
_hostPortProxyPolicy: _egressL7Policy & {
	_port: "40001"
	metadata: labels: {
		component:  "hostport-check"
		quarantine: "true"
	}
}
// Pod-to-a (egress policy, no ingress policy)
deployment: "pod-to-a-multi-node-hostport-proxy-egress": _hostPortProxyResource
egressCNP: "pod-to-a-multi-node-hostport-proxy-egress":  _hostPortProxyPolicy
deployment: "pod-to-a-intra-node-hostport-proxy-egress": _hostPortProxyResource
egressCNP: "pod-to-a-intra-node-hostport-proxy-egress":  _hostPortProxyPolicy

// Pod-to-c (no egress policy, ingress policy via echo-servers.cue)
deployment: "pod-to-c-multi-node-hostport-proxy-ingress": _hostPortProxyResource
deployment: "pod-to-c-intra-node-hostport-proxy-ingress": _hostPortProxyResource

// Pod-to-c (egress + ingress policy)
deployment: "pod-to-c-multi-node-hostport-proxy-to-proxy": _hostPortProxyResource
egressCNP: "pod-to-c-multi-node-hostport-proxy-to-proxy":  _hostPortProxyPolicy
deployment: "pod-to-c-intra-node-hostport-proxy-to-proxy": _hostPortProxyResource
egressCNP: "pod-to-c-intra-node-hostport-proxy-to-proxy":  _hostPortProxyPolicy
