package connectivity_check

// Default parameters for echo servers (may be overridden).
_echoDeployment: {
	_image:       "quay.io/cilium/json-mock:v1.4.1@sha256:6a66df90808a39c02e7a9d58af7bf0e54d8f8b7d4bc528f48c891969a7049195"
	_probeTarget: *"localhost:8080" | string
	_probePath:   ""
}

_echoDeploymentWithHostPort: _echoDeployment & {
	_exposeHeadless: true

	spec: template: spec: hostNetwork: true
}

// Regular service exposed via ClusterIP.
deployment: "echo-a": _echoDeployment & {
	_serverPort:      "8080"
	_exposeClusterIP: true
	metadata: labels: component: "network-check"
	spec: template: spec: containers: [{ports: [{_expose: true, containerPort: 8080, _portName: "http"}]}]
}

// Service exposed via NodePort + headless svc.
deployment: "echo-b": _echoDeployment & {
	_serverPort:     "8080"
	_exposeNodePort: true
	_exposeHeadless: true
	_nodePort:       31414

	metadata: labels: component: "services-check"
	spec: template: spec: containers: [{ports: [{_expose: true, containerPort: 8080, _portName: "http", hostPort: 40000}]}]
}
// Expose hostport by deploying a host pod and adding a headless service with no port.
deployment: "echo-b-host": _echoDeploymentWithHostPort & {
	_serverPort: "21000"
	_affinity:   "echo-b"

	metadata: labels: component: "services-check"
}

ingressL7Policy: {
	_allowDNS: true
	_port:     *"8080" | string
	_rules: [{
		toPorts: [{
			ports: [{
				port:     _port
				protocol: "TCP"
			}]
			rules:
				http: [{
					method: "GET"
					path:   "/public$"
				}]
		}]
	}]

	metadata: labels: component: "proxy-check"
}

// Service with policy applied.
deployment: "echo-c": _echoDeployment & {
	_serverPort:      "8080"
	_exposeClusterIP: true
	_exposeHeadless:  true

	metadata: labels: component: "proxy-check"
	spec: template: spec: containers: [{ports: [{_expose: true, containerPort: 8080, _portName: "http", hostPort: 40001}]}]
}
ingressCNP: "echo-c": ingressL7Policy & {}
// Expose hostport by deploying a host pod and adding a headless service with no port.
// No ingress policy will apply in this case.
deployment: "echo-c-host": _echoDeploymentWithHostPort & {
	_serverPort: "21002"
	_affinity:   "echo-c"
	metadata: labels: component: "proxy-check"
}
