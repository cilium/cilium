package connectivity_check

_probeFailureTimeout: 5 // seconds

_spec: {
	_name:  string
	_image: string
	_command: [...string]
	_traffic: *"internal" | "external" | "any"

	_affinity:     *"" | string
	_antiAffinity: *"" | string
	_serverPort:   *"" | string

	_probeTarget:     string
	_probePath:       *"/public" | string
	_probeExpectFail: *false | true
	_allowProbe:      [] | [...string]
	_rejectProbe:     [] | [...string]

	_containers: [...{}]
	_enableMultipleContainers: *false | true

	_container: {
		image:           _image
		imagePullPolicy: "IfNotPresent"
		if len(_command) > 0 {
			command: _command
		}
		if _serverPort != "" {
			env: [{
				name:  "PORT"
				value: _serverPort
			}]
		}
		ports: [...{
			_expose: *false | true
		}]
	}

	if len(_allowProbe) == 0 {
		_allowProbe: [ "curl", "-sS", "--fail", "--connect-timeout", "\(_probeFailureTimeout)", "-o", "/dev/null", "\(_probeTarget)\(_probePath)"]
	}
	if len(_rejectProbe) == 0 {
		_rejectProbe: [ "ash", "-c", "! curl -s --fail --connect-timeout \(_probeFailureTimeout) -o /dev/null \(_probeTarget)/private"]
	}
	if !_enableMultipleContainers {
		_c1: _container & {
			name: "\(_name)-container"
			if _probeExpectFail {
				readinessProbe: {
					timeoutSeconds: _probeFailureTimeout + 2
					exec: command: _rejectProbe
				}
				livenessProbe: {
					timeoutSeconds: _probeFailureTimeout + 2
					exec: command: _rejectProbe
				}
			}
			if !_probeExpectFail {
				readinessProbe: {
					timeoutSeconds: _probeFailureTimeout + 2
					exec: command: _allowProbe
				}
				livenessProbe: {
					timeoutSeconds: _probeFailureTimeout + 2
					exec: command: _allowProbe
				}
			}
		}
		_containers: [_c1]
	}
	if _enableMultipleContainers {
		_c1: _container & {
			name: "\(_name)-allow-container"
			readinessProbe: exec: command: _allowProbe
			livenessProbe: exec: command:  _allowProbe
		}
		_c2: _container & {
			name: "\(_name)-reject-container"
			livenessProbe: {
				timeoutSeconds: _probeFailureTimeout + 2
				exec: command: _rejectProbe
			}
			livenessProbe: {
				timeoutSeconds: _probeFailureTimeout + 2
				exec: command: _rejectProbe
			}
		}
		_containers: [_c1] + [_c2]
	}

	apiVersion: "apps/v1"
	kind:       "Deployment"
	metadata: {
		name: _name
		labels: {
			name:       _name
			topology:   *"any" | string
			type:       *"autocheck" | string
			component:  *"invalid" | string
			quarantine: *"false" | "true"
			traffic:    _traffic
		}
	}
	spec: {
		selector: matchLabels: name: _name
		template: {
			metadata: labels: name: _name
			spec: containers: _containers
			if _affinity != "" {
				spec: affinity: podAffinity: requiredDuringSchedulingIgnoredDuringExecution: [{
					labelSelector: matchExpressions: [{
						key:      "name"
						operator: "In"
						values: [
							_affinity,
						]
					}]
					topologyKey: "kubernetes.io/hostname"
				}]
			}
			if _antiAffinity != "" {
				spec: affinity: podAntiAffinity: requiredDuringSchedulingIgnoredDuringExecution: [{
					labelSelector: matchExpressions: [{
						key:      "name"
						operator: "In"
						values: [
							_antiAffinity,
						]
					}]
					topologyKey: "kubernetes.io/hostname"
				}]
			}
		}
	}
}

deployment: [ID=_]: _spec & {
	_name:  ID
	_image: string

	// Expose services
	_exposeClusterIP: *false | true
	_exposeNodePort:  *false | true
	_exposeHeadless:  *false | true

	// Pod ports
	_serverPort: *"" | string
	if _serverPort != "" {
		_probeTarget: "localhost:\(_serverPort)"
	}

	spec: {
		replicas: *1 | int
		template: spec: {
			hostNetwork: *false | true
		}
	}
}

service: [ID=_]: {
	_name:     ID
	_selector: ID | string
	_traffic:  *"internal" | "external" | "any"

	apiVersion: "v1"
	kind:       "Service"
	metadata: {
		name: ID
		labels: {
			name:       _name
			topology:   *"any" | string
			type:       *"autocheck" | string
			component:  *"invalid" | string
			quarantine: *"false" | "true"
			traffic:    _traffic
		}
	}
	spec: {
		type: *"ClusterIP" | string
		selector: name: _selector
	}
}

_cnp: {
	_name:    string
	_traffic: *"internal" | "external" | "any"

	apiVersion: "cilium.io/v2"
	kind:       "CiliumNetworkPolicy"
	metadata: {
		name: _name
		labels: {
			name:       _name
			topology:   *"any" | string
			type:       *"autocheck" | string
			component:  *"invalid" | string
			quarantine: *"false" | "true"
			traffic:    _traffic
		}
	}
	spec: endpointSelector: matchLabels: name: _name
}

egressCNP: [ID=_]: _cnp & {
	_name: ID
	_rules: [...{}]
	_allowDNS: *true | false

	// Implicitly open DNS visibility if FQDN rule is specified.
	_enableDNSVisibility: *false | true
	for r in _rules if len(r.toFQDNs) > 0 {
		_enableDNSVisibility: true
	}

	if !_allowDNS {
		spec: egress: _rules
	}
	if _allowDNS {
		spec: egress: _rules + [
				{
				toEndpoints: [
					{
						matchLabels: {
							"k8s:io.kubernetes.pod.namespace": "kube-system"
							"k8s:k8s-app":                     "kube-dns"
						}
					},
					{
						// Allows connectivity to NodeLocal DNSCache when deployed with Local Redirect Policy.
						matchLabels: {
							"k8s:io.kubernetes.pod.namespace": "kube-system"
							"k8s:k8s-app":                     "node-local-dns"
						}
					},
				]
				toPorts: [{
					ports: [{
						port:     "53"
						protocol: "ANY"
					}]
					if _enableDNSVisibility {
						rules: dns: [{matchPattern: "*"}]
					}
				}]
			},
			{
				toEndpoints: [{
					matchLabels: {
						"k8s:io.kubernetes.pod.namespace":             "openshift-dns"
						"k8s:dns.operator.openshift.io/daemonset-dns": "default"
					}
				}]
				toPorts: [{
					ports: [{
						port:     "5353"
						protocol: "UDP"
					}]
					if _enableDNSVisibility {
						rules: dns: [{matchPattern: "*"}]
					}
				}]
			},
		]
	}
}

ingressCNP: [ID=_]: _cnp & {
	_name: ID
	_rules: [...{}]

	spec: ingress: _rules
}

// Create services for each deployment that have relevant configuration.
for x in [deployment] for k, v in x {
	if v._exposeClusterIP || v._exposeNodePort {
		service: "\(k)": {
			metadata: v.metadata
			spec: selector: v.spec.template.metadata.labels
			if v._exposeNodePort {
				spec: type: "NodePort"
			}
			spec: ports: [
				for c in v.spec.template.spec.containers
				for p in c.ports
				if p._expose {
					let Port = p.containerPort // Port is an alias
					port: *Port | int
					name: p._portName
					if v._exposeNodePort {
						nodePort: v._nodePort
					}
				},
			]
		}
	}
	if v._exposeHeadless {
		service: "\(k)-headless": {
			_selector: k
			metadata: name: "\(v.metadata.name)-headless"
			metadata: labels: {
				name:       "\(v.metadata.name)-headless"
				component:  v.metadata.labels.component
				topology:   *"any" | string
				type:       *"autocheck" | string
				quarantine: *"false" | "true"
				traffic:    *"internal" | "external" | "any"
			}
			spec: selector:  v.spec.template.metadata.labels
			spec: clusterIP: "None"
			spec: ports: [
				for c in v.spec.template.spec.containers
				for p in c.ports
				if p._expose {
					let Port = p.containerPort // Port is an alias
					port: *Port | int
					name: p._portName
				},
			]
		}
	}
}
