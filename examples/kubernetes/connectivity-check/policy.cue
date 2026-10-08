package connectivity_check

// deployment (defaults.cue) implicitly configures the deployments below such
// that deployments with names matching 'pod-to-<X>', '*-[intra|multi]-node'
// and '*-headless' will contact the related echo server via the related
// service and will be scheduled with affinity / anti-affinity to that server.
_policyResource: {
	_allowDNS: true

	metadata: labels: component: "policy-check"
}
deployment: "pod-to-a-denied-cnp": _policyResource & {
	_probeExpectFail: true
}

_trafficCheck: {
	metadata: labels: traffic: "external"
}

egressCNP: "pod-to-a-denied-cnp":   _policyResource
deployment: "pod-to-a-allowed-cnp": _policyResource
egressCNP: "pod-to-a-allowed-cnp":  _policyResource & {
	_rules: [{
		toEndpoints: [{
			matchLabels: {
				name: "echo-a"
			}
		}]
		toPorts: [{
			ports: [{
				port:     "8080"
				protocol: "TCP"
			}]
		}]
	}]
}

deployment: "pod-to-external-fqdn-allow-google-cnp": _policyResource & _trafficCheck & {
	_probeTarget: "www.google.com"
	_probePath:   ""
}
egressCNP: "pod-to-external-fqdn-allow-google-cnp": _policyResource & _trafficCheck & {
	// _allowDNS (default true) + 'toFQDNs' rules automatically applies
	// DNS policy visibility via resources.cue.
	_rules: [{
		toFQDNs: [{matchPattern: "*.google.com"}]
	}]
}
