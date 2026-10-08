package connectivity_check

// deployment (defaults.cue) implicitly configures the deployments below such
// that deployments with names matching 'pod-to-<X>', '*-[intra|multi]-node'
// and '*-headless' will contact the related echo server via the related
// service and will be scheduled with affinity / anti-affinity to that server.
_networkCheck: {
	metadata: labels: component: "network-check"
}

_trafficCheck: {
	metadata: labels: traffic: "external"
}

deployment: "pod-to-a":             _networkCheck
deployment: "pod-to-external-1111": _networkCheck & _trafficCheck & {
	_probeTarget: "https://1.1.1.1"
	_probePath:   ""
}
