package connectivity_check

// Default parameters for echo servers (may be overridden).
_echoDeployment: {
	_image:       "docker.io/cilium/json-mock:1.2"
	_probeTarget: *"localhost" | string
	_probePath:   ""
}

_echoDeploymentWithHostPort: _echoDeployment & {
	_exposeHeadless: true

	spec: template: spec: hostNetwork: true
}

// Regular service exposed via ClusterIP.
deployment: "echo-a": _echoDeployment & {
	_exposeClusterIP: true
	metadata: labels: component: "network-check"
	spec: template: spec: containers: [{ports: [{_expose: true, containerPort: 80}]}]
}

// Service exposed via NodePort + headless svc.
deployment: "echo-b": _echoDeployment & {
	_exposeNodePort: true
	_exposeHeadless: true
	_nodePort:       31313

	metadata: labels: component: "services-check"
	spec: template: spec: containers: [{ports: [{_expose: true, containerPort: 80, hostPort: 40000}]}]
}
// Expose hostport by deploying a host pod and adding a headless service with no port.
deployment: "echo-b-host": _echoDeploymentWithHostPort & {
	_serverPort: "41000"
	_affinity:   "echo-b"

	metadata: labels: component: "services-check"
}
