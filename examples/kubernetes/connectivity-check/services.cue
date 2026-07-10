package connectivity_check

deployment: [ID=_]: {
	if ID =~ "^[-_a-zA-Z0-9]*-headless$" {
		_probeTarget: "echo-b-headless:8080"
	}
}

// deployment (defaults.cue) implicitly configures the deployments below such
// that deployments with names matching 'pod-to-<X>', '*-[intra|multi]-node'
// and '*-headless' will contact the related echo server via the related
// service and will be scheduled with affinity / anti-affinity to that server.
_serviceDeployment: {
	metadata: labels: component: "services-check"
}

// Service checks
deployment: "pod-to-b-multi-node-clusterip": _serviceDeployment
deployment: "pod-to-b-multi-node-headless":  _serviceDeployment
//deployment: "pod-to-b-intra-node-clusterip": _serviceDeployment
//deployment: "pod-to-b-intra-node-headless":  _serviceDeployment

_hostnetDeployment: _serviceDeployment & {
	spec: template: spec: {
		hostNetwork: true
		dnsPolicy:   "ClusterFirstWithHostNet"
	}
}
deployment: "host-to-b-multi-node-clusterip": _hostnetDeployment
deployment: "host-to-b-multi-node-headless":  _hostnetDeployment

// Hostport checks
_hostPortDeployment: {
	metadata: labels: component: "hostport-check"
	_probeTarget: "echo-b-host-headless:40000"
}
deployment: "pod-to-b-multi-node-hostport": _hostPortDeployment
deployment: "pod-to-b-intra-node-hostport": _hostPortDeployment

// NodePort checks
_nodePortDeployment: {
	metadata: labels: component: "nodeport-check"
	_probeTarget: "echo-b-host-headless:31414"
}
deployment: "pod-to-b-multi-node-nodeport": _nodePortDeployment
deployment: "pod-to-b-intra-node-nodeport": _nodePortDeployment
