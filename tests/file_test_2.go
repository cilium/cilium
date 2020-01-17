package table

var (
	// Running from host
	expectedResult = map[string]map[string]struct {
		description string
		expected    string
	}{
		"svc-a-external-ips-k8s1-public": {
			"svc-a-external-ips-svc-port": {
				description: "svc-a-external-ips-k8s1-public:svc-a-external-ips-svc-port",
				expected:    "No route to host",
			},
			"svc-b-external-ips-svc-port": {
				description: "svc-a-external-ips-k8s1-public:svc-b-external-ips-svc-port",
				expected:    "No route to host",
			},
			"svc-c-node-port-svc-port": {
				description: "svc-a-external-ips-k8s1-public:svc-c-node-port-svc-port",
				expected:    "No route to host",
			},
			"svc-c-node-port-node-port": {
				description: "svc-a-external-ips-k8s1-public:svc-c-node-port-node-port",
				expected:    "No route to host",
			},
		},
		"svc-a-external-ips-k8s1-host-public": {
			"svc-a-external-ips-svc-port": {
				description: "svc-a-external-ips-k8s1-host-public:svc-a-external-ips-svc-port",
				expected:    "app1",
			},
			"svc-b-external-ips-svc-port": {
				description: "svc-a-external-ips-k8s1-host-public:svc-b-external-ips-svc-port",
				expected:    "app1",
			},
			"svc-c-node-port-svc-port": {
				description: "svc-a-external-ips-k8s1-host-public:svc-c-node-port-svc-port",
				expected:    "connection refused",
			},
			"svc-c-node-port-node-port": {
				description: "svc-a-external-ips-k8s1-host-public:svc-c-node-port-node-port",
				expected:    "app2",
			},
		},
		"svc-a-external-ips-k8s1-host-private": {
			"svc-a-external-ips-svc-port": {
				description: "svc-a-external-ips-k8s1-host-private:svc-a-external-ips-svc-port",
				expected:    "app1",
			},
			"svc-b-external-ips-svc-port": {
				description: "svc-a-external-ips-k8s1-host-private:svc-b-external-ips-svc-port",
				expected:    "app1",
			},
			"svc-c-node-port-svc-port": {
				description: "svc-a-external-ips-k8s1-host-private:svc-c-node-port-svc-port",
				expected:    "connection refused",
			},
			"svc-c-node-port-node-port": {
				description: "svc-a-external-ips-k8s1-host-private:svc-c-node-port-node-port",
				expected:    "app2",
			},
		},
		"svc-b-external-ips-k8s1-public": {
			"svc-a-external-ips-svc-port": {
				description: "svc-b-external-ips-k8s1-public:svc-a-external-ips-svc-port",
				expected:    "No route to host",
			},
			"svc-b-external-ips-svc-port": {
				description: "svc-b-external-ips-k8s1-public:svc-b-external-ips-svc-port",
				expected:    "No route to host",
			},
			"svc-c-node-port-svc-port": {
				description: "svc-b-external-ips-k8s1-public:svc-c-node-port-svc-port",
				expected:    "No route to host",
			},
			"svc-c-node-port-node-port": {
				description: "svc-b-external-ips-k8s1-public:svc-c-node-port-node-port",
				expected:    "No route to host",
			},
		},
		"svc-b-external-ips-k8s2-host-public": {
			"svc-a-external-ips-svc-port": {
				description: "svc-b-external-ips-k8s2-host-public:svc-a-external-ips-svc-port",
				expected:    "app1",
			},
			"svc-b-external-ips-svc-port": {
				description: "svc-b-external-ips-k8s2-host-public:svc-b-external-ips-svc-port",
				expected:    "app1",
			},
			"svc-c-node-port-svc-port": {
				description: "svc-b-external-ips-k8s2-host-public:svc-c-node-port-svc-port",
				expected:    "connection refused",
			},
			"svc-c-node-port-node-port": {
				description: "svc-b-external-ips-k8s2-host-public:svc-c-node-port-node-port",
				expected:    "app2",
			},
		},
		"svc-b-external-ips-k8s1-host-private": {
			"svc-a-external-ips-svc-port": {
				description: "svc-b-external-ips-k8s1-host-private:svc-a-external-ips-svc-port",
				expected:    "app1",
			},
			"svc-b-external-ips-svc-port": {
				description: "svc-b-external-ips-k8s1-host-private:svc-b-external-ips-svc-port",
				expected:    "app1",
			},
			"svc-c-node-port-svc-port": {
				description: "svc-b-external-ips-k8s1-host-private:svc-c-node-port-svc-port",
				expected:    "connection refused",
			},
			"svc-c-node-port-node-port": {
				description: "svc-b-external-ips-k8s1-host-private:svc-c-node-port-node-port",
				expected:    "app2",
			},
		},
		"localhost": {
			"svc-a-external-ips-svc-port": {
				description: "localhost:svc-a-external-ips-svc-port",
				expected:    "connection refused",
			},
			"svc-b-external-ips-svc-port": {
				description: "localhost:svc-b-external-ips-svc-port",
				expected:    "connection refused",
			},
			"svc-c-node-port-svc-port": {
				description: "localhost:svc-c-node-port-svc-port",
				expected:    "connection refused",
			},
			"svc-c-node-port-node-port": {
				description: "localhost:svc-c-node-port-node-port",
				expected:    "app2",
			},
		},
		"svc-a-external-ips-cluster-ip": {
			"svc-a-external-ips-svc-port": {
				description: "svc-a-external-ips-cluster-ip:svc-a-external-ips-svc-port",
				expected:    "app1",
			},
			"svc-b-external-ips-svc-port": {
				description: "svc-a-external-ips-cluster-ip:svc-b-external-ips-svc-port",
				expected:    "No route to host",
			},
			"svc-c-node-port-svc-port": {
				description: "svc-a-external-ips-cluster-ip:svc-c-node-port-svc-port",
				expected:    "No route to host",
			},
			"svc-c-node-port-node-port": {
				description: "svc-a-external-ips-cluster-ip:svc-c-node-port-node-port",
				expected:    "No route to host",
			},
		},
		"svc-b-external-ips-cluster-ip": {
			"svc-a-external-ips-svc-port": {
				description: "svc-b-external-ips-cluster-ip:svc-a-external-ips-svc-port",
				expected:    "No route to host",
			},
			"svc-b-external-ips-svc-port": {
				description: "svc-b-external-ips-cluster-ip:svc-b-external-ips-svc-port",
				expected:    "app1",
			},
			"svc-c-node-port-svc-port": {
				description: "svc-b-external-ips-cluster-ip:svc-c-node-port-svc-port",
				expected:    "No route to host",
			},
			"svc-c-node-port-node-port": {
				description: "svc-b-external-ips-cluster-ip:svc-c-node-port-node-port",
				expected:    "No route to host",
			},
		},
		"svc-c-node-port-cluster-ip": {
			"svc-a-external-ips-svc-port": {
				description: "svc-c-node-port-cluster-ip:svc-a-external-ips-svc-port",
				expected:    "No route to host",
			},
			"svc-b-external-ips-svc-port": {
				description: "svc-c-node-port-cluster-ip:svc-b-external-ips-svc-port",
				expected:    "No route to host",
			},
			"svc-c-node-port-svc-port": {
				description: "svc-c-node-port-cluster-ip:svc-c-node-port-svc-port",
				expected:    "app2",
			},
			"svc-c-node-port-node-port": {
				description: "svc-c-node-port-cluster-ip:svc-c-node-port-node-port",
				expected:    "No route to host",
			},
		},
	}
)
