// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package external_ips

var (
	expectedResultFromPodInNode1 = map[string]map[string]entryTestArgs{
		"svc-a-external-ips-k8s1-public": {
			"svc-a-external-ips-svc-port": {
				description: "svc-a-external-ips-k8s1-public:svc-a-external-ips-svc-port",
				ip:          "192.0.2.233",
				port:        "82",
				expected:    "app1",
			},
			"svc-b-external-ips-svc-port": {
				description: "svc-a-external-ips-k8s1-public:svc-b-external-ips-svc-port",
				ip:          "192.0.2.233",
				port:        "30002",
				expected:    "app1",
			},
			"svc-c-node-port-svc-port": {
				description: "svc-a-external-ips-k8s1-public:svc-c-node-port-svc-port",
				ip:          "192.0.2.233",
				port:        "83",
				expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-svc-port": {
				description: "svc-a-external-ips-k8s1-public:svc-d-node-port-svc-port",
				ip:          "192.0.2.233",
				port:        "84",
				expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-svc-port": {
				description: "svc-a-external-ips-k8s1-public:svc-e-node-port-svc-port",
				ip:          "192.0.2.233",
				port:        "85",
				expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-node-port": {
				description: "svc-a-external-ips-k8s1-public:svc-c-node-port-node-port",
				ip:          "192.0.2.233",
				port:        "30003",
				expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-node-port": {
				description: "svc-a-external-ips-k8s1-public:svc-d-node-port-node-port",
				ip:          "192.0.2.233",
				port:        "30004",
				expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-node-port": {
				description: "svc-a-external-ips-k8s1-public:svc-e-node-port-node-port",
				ip:          "192.0.2.233",
				port:        "30005",
				expected:    "No route to host / connection timed out",
			},
		},
		"svc-a-external-ips-k8s1-host-public": {
			"svc-a-external-ips-svc-port": {
				description: "svc-a-external-ips-k8s1-host-public:svc-a-external-ips-svc-port",
				ip:          "192.168.34.11",
				port:        "82",
				expected:    "app1",
			},
			"svc-b-external-ips-svc-port": {
				description: "svc-a-external-ips-k8s1-host-public:svc-b-external-ips-svc-port",
				ip:          "192.168.34.11",
				port:        "30002",
				expected:    "app1",
			},
			"svc-c-node-port-svc-port": {
				description: "svc-a-external-ips-k8s1-host-public:svc-c-node-port-svc-port",
				ip:          "192.168.34.11",
				port:        "83",
				expected:    "connection refused",
			},
			"svc-d-node-port-svc-port": {
				description: "svc-a-external-ips-k8s1-host-public:svc-d-node-port-svc-port",
				ip:          "192.168.34.11",
				port:        "84",
				expected:    "connection refused",
			},
			"svc-e-node-port-svc-port": {
				description: "svc-a-external-ips-k8s1-host-public:svc-e-node-port-svc-port",
				ip:          "192.168.34.11",
				port:        "85",
				expected:    "connection refused",
			},
			"svc-c-node-port-node-port": {
				description: "svc-a-external-ips-k8s1-host-public:svc-c-node-port-node-port",
				ip:          "192.168.34.11",
				port:        "30003",
				expected:    "app2",
			},
			"svc-d-node-port-node-port": {
				description: "svc-a-external-ips-k8s1-host-public:svc-d-node-port-node-port",
				ip:          "192.168.34.11",
				port:        "30004",
				expected:    "app4",
			},
			"svc-e-node-port-node-port": {
				description: "svc-a-external-ips-k8s1-host-public:svc-e-node-port-node-port",
				ip:          "192.168.34.11",
				port:        "30005",
				expected:    "app6",
			},
		},
		"svc-a-external-ips-k8s1-host-private": {
			"svc-a-external-ips-svc-port": {
				description: "svc-a-external-ips-k8s1-host-private:svc-a-external-ips-svc-port",
				ip:          "192.168.33.11",
				port:        "82",
				expected:    "app1",
			},
			"svc-b-external-ips-svc-port": {
				description: "svc-a-external-ips-k8s1-host-private:svc-b-external-ips-svc-port",
				ip:          "192.168.33.11",
				port:        "30002",
				expected:    "app1",
			},
			"svc-c-node-port-svc-port": {
				description: "svc-a-external-ips-k8s1-host-private:svc-c-node-port-svc-port",
				ip:          "192.168.33.11",
				port:        "83",
				expected:    "connection refused",
			},
			"svc-d-node-port-svc-port": {
				description: "svc-a-external-ips-k8s1-host-private:svc-d-node-port-svc-port",
				ip:          "192.168.33.11",
				port:        "84",
				expected:    "connection refused",
			},
			"svc-e-node-port-svc-port": {
				description: "svc-a-external-ips-k8s1-host-private:svc-e-node-port-svc-port",
				ip:          "192.168.33.11",
				port:        "85",
				expected:    "connection refused",
			},
			"svc-c-node-port-node-port": {
				description: "svc-a-external-ips-k8s1-host-private:svc-c-node-port-node-port",
				ip:          "192.168.33.11",
				port:        "30003",
				expected:    "app2",
			},
			"svc-d-node-port-node-port": {
				description: "svc-a-external-ips-k8s1-host-private:svc-d-node-port-node-port",
				ip:          "192.168.33.11",
				port:        "30004",
				expected:    "app4",
			},
			"svc-e-node-port-node-port": {
				description: "svc-a-external-ips-k8s1-host-private:svc-e-node-port-node-port",
				ip:          "192.168.33.11",
				port:        "30005",
				expected:    "app6",
			},
		},
		"svc-b-external-ips-k8s1-public": {
			"svc-a-external-ips-svc-port": {
				description: "svc-b-external-ips-k8s1-public:svc-a-external-ips-svc-port",
				ip:          "192.0.2.233",
				port:        "82",
				expected:    "app1",
			},
			"svc-b-external-ips-svc-port": {
				description: "svc-b-external-ips-k8s1-public:svc-b-external-ips-svc-port",
				ip:          "192.0.2.233",
				port:        "30002",
				expected:    "app1",
			},
			"svc-c-node-port-svc-port": {
				description: "svc-b-external-ips-k8s1-public:svc-c-node-port-svc-port",
				ip:          "192.0.2.233",
				port:        "83",
				expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-svc-port": {
				description: "svc-b-external-ips-k8s1-public:svc-d-node-port-svc-port",
				ip:          "192.0.2.233",
				port:        "84",
				expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-svc-port": {
				description: "svc-b-external-ips-k8s1-public:svc-e-node-port-svc-port",
				ip:          "192.0.2.233",
				port:        "85",
				expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-node-port": {
				description: "svc-b-external-ips-k8s1-public:svc-c-node-port-node-port",
				ip:          "192.0.2.233",
				port:        "30003",
				expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-node-port": {
				description: "svc-b-external-ips-k8s1-public:svc-d-node-port-node-port",
				ip:          "192.0.2.233",
				port:        "30004",
				expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-node-port": {
				description: "svc-b-external-ips-k8s1-public:svc-e-node-port-node-port",
				ip:          "192.0.2.233",
				port:        "30005",
				expected:    "No route to host / connection timed out",
			},
		},
		"svc-b-external-ips-k8s1-host-public": {
			"svc-a-external-ips-svc-port": {
				description: "svc-b-external-ips-k8s1-host-public:svc-a-external-ips-svc-port",
				ip:          "192.168.34.11",
				port:        "82",
				expected:    "app1",
			},
			"svc-b-external-ips-svc-port": {
				description: "svc-b-external-ips-k8s1-host-public:svc-b-external-ips-svc-port",
				ip:          "192.168.34.11",
				port:        "30002",
				expected:    "app1",
			},
			"svc-c-node-port-svc-port": {
				description: "svc-b-external-ips-k8s1-host-public:svc-c-node-port-svc-port",
				ip:          "192.168.34.11",
				port:        "83",
				expected:    "connection refused",
			},
			"svc-d-node-port-svc-port": {
				description: "svc-b-external-ips-k8s1-host-public:svc-d-node-port-svc-port",
				ip:          "192.168.34.11",
				port:        "84",
				expected:    "connection refused",
			},
			"svc-e-node-port-svc-port": {
				description: "svc-b-external-ips-k8s1-host-public:svc-e-node-port-svc-port",
				ip:          "192.168.34.11",
				port:        "85",
				expected:    "connection refused",
			},
			"svc-c-node-port-node-port": {
				description: "svc-b-external-ips-k8s1-host-public:svc-c-node-port-node-port",
				ip:          "192.168.34.11",
				port:        "30003",
				expected:    "app2",
			},
			"svc-d-node-port-node-port": {
				description: "svc-b-external-ips-k8s1-host-public:svc-d-node-port-node-port",
				ip:          "192.168.34.11",
				port:        "30004",
				expected:    "app4",
			},
			"svc-e-node-port-node-port": {
				description: "svc-b-external-ips-k8s1-host-public:svc-e-node-port-node-port",
				ip:          "192.168.34.11",
				port:        "30005",
				expected:    "app6",
			},
		},
		"svc-b-external-ips-k8s1-host-private": {
			"svc-a-external-ips-svc-port": {
				description: "svc-b-external-ips-k8s1-host-private:svc-a-external-ips-svc-port",
				ip:          "192.168.33.11",
				port:        "82",
				expected:    "app1",
			},
			"svc-b-external-ips-svc-port": {
				description: "svc-b-external-ips-k8s1-host-private:svc-b-external-ips-svc-port",
				ip:          "192.168.33.11",
				port:        "30002",
				expected:    "app1",
			},
			"svc-c-node-port-svc-port": {
				description: "svc-b-external-ips-k8s1-host-private:svc-c-node-port-svc-port",
				ip:          "192.168.33.11",
				port:        "83",
				expected:    "connection refused",
			},
			"svc-d-node-port-svc-port": {
				description: "svc-b-external-ips-k8s1-host-private:svc-d-node-port-svc-port",
				ip:          "192.168.33.11",
				port:        "84",
				expected:    "connection refused",
			},
			"svc-e-node-port-svc-port": {
				description: "svc-b-external-ips-k8s1-host-private:svc-e-node-port-svc-port",
				ip:          "192.168.33.11",
				port:        "85",
				expected:    "connection refused",
			},
			"svc-c-node-port-node-port": {
				description: "svc-b-external-ips-k8s1-host-private:svc-c-node-port-node-port",
				ip:          "192.168.33.11",
				port:        "30003",
				expected:    "app2",
			},
			"svc-d-node-port-node-port": {
				description: "svc-b-external-ips-k8s1-host-private:svc-d-node-port-node-port",
				ip:          "192.168.33.11",
				port:        "30004",
				expected:    "app4",
			},
			"svc-e-node-port-node-port": {
				description: "svc-b-external-ips-k8s1-host-private:svc-e-node-port-node-port",
				ip:          "192.168.33.11",
				port:        "30005",
				expected:    "app6",
			},
		},
		"localhost": {
			"svc-a-external-ips-svc-port": {
				description: "localhost:svc-a-external-ips-svc-port",
				ip:          "127.0.0.1",
				port:        "82",
				expected:    "connection refused",
			},
			"svc-b-external-ips-svc-port": {
				description: "localhost:svc-b-external-ips-svc-port",
				ip:          "127.0.0.1",
				port:        "30002",
				expected:    "connection refused",
			},
			"svc-c-node-port-svc-port": {
				description: "localhost:svc-c-node-port-svc-port",
				ip:          "127.0.0.1",
				port:        "83",
				expected:    "connection refused",
			},
			"svc-d-node-port-svc-port": {
				description: "localhost:svc-d-node-port-svc-port",
				ip:          "127.0.0.1",
				port:        "84",
				expected:    "connection refused",
			},
			"svc-e-node-port-svc-port": {
				description: "localhost:svc-e-node-port-svc-port",
				ip:          "127.0.0.1",
				port:        "85",
				expected:    "connection refused",
			},
			"svc-c-node-port-node-port": {
				description: "localhost:svc-c-node-port-node-port",
				ip:          "127.0.0.1",
				port:        "30003",
				expected:    "connection refused",
				skipReason:  "needs kernel changes as we can't distinguish between pod traffic and host traffic",
			},
			"svc-d-node-port-node-port": {
				description: "localhost:svc-d-node-port-node-port",
				ip:          "127.0.0.1",
				port:        "30004",
				expected:    "connection refused",
				skipReason:  "needs kernel changes as we can't distinguish between pod traffic and host traffic",
			},
			"svc-e-node-port-node-port": {
				description: "localhost:svc-e-node-port-node-port",
				ip:          "127.0.0.1",
				port:        "30005",
				expected:    "connection refused",
				skipReason:  "needs kernel changes as we can't distinguish between pod traffic and host traffic",
			},
		},
		"svc-a-external-ips-cluster-ip": {
			"svc-a-external-ips-svc-port": {
				description: "svc-a-external-ips-cluster-ip:svc-a-external-ips-svc-port",
				ip:          "172.20.0.112",
				port:        "82",
				expected:    "app1",
			},
			"svc-b-external-ips-svc-port": {
				description: "svc-a-external-ips-cluster-ip:svc-b-external-ips-svc-port",
				ip:          "172.20.0.112",
				port:        "30002",
				expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-svc-port": {
				description: "svc-a-external-ips-cluster-ip:svc-c-node-port-svc-port",
				ip:          "172.20.0.112",
				port:        "83",
				expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-svc-port": {
				description: "svc-a-external-ips-cluster-ip:svc-d-node-port-svc-port",
				ip:          "172.20.0.112",
				port:        "84",
				expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-svc-port": {
				description: "svc-a-external-ips-cluster-ip:svc-e-node-port-svc-port",
				ip:          "172.20.0.112",
				port:        "85",
				expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-node-port": {
				description: "svc-a-external-ips-cluster-ip:svc-c-node-port-node-port",
				ip:          "172.20.0.112",
				port:        "30003",
				expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-node-port": {
				description: "svc-a-external-ips-cluster-ip:svc-d-node-port-node-port",
				ip:          "172.20.0.112",
				port:        "30004",
				expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-node-port": {
				description: "svc-a-external-ips-cluster-ip:svc-e-node-port-node-port",
				ip:          "172.20.0.112",
				port:        "30005",
				expected:    "No route to host / connection timed out",
			},
		},
		"svc-b-external-ips-cluster-ip": {
			"svc-a-external-ips-svc-port": {
				description: "svc-b-external-ips-cluster-ip:svc-a-external-ips-svc-port",
				ip:          "172.20.0.173",
				port:        "82",
				expected:    "No route to host / connection timed out",
			},
			"svc-b-external-ips-svc-port": {
				description: "svc-b-external-ips-cluster-ip:svc-b-external-ips-svc-port",
				ip:          "172.20.0.173",
				port:        "30002",
				expected:    "app1",
			},
			"svc-c-node-port-svc-port": {
				description: "svc-b-external-ips-cluster-ip:svc-c-node-port-svc-port",
				ip:          "172.20.0.173",
				port:        "83",
				expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-svc-port": {
				description: "svc-b-external-ips-cluster-ip:svc-d-node-port-svc-port",
				ip:          "172.20.0.173",
				port:        "84",
				expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-svc-port": {
				description: "svc-b-external-ips-cluster-ip:svc-e-node-port-svc-port",
				ip:          "172.20.0.173",
				port:        "85",
				expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-node-port": {
				description: "svc-b-external-ips-cluster-ip:svc-c-node-port-node-port",
				ip:          "172.20.0.173",
				port:        "30003",
				expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-node-port": {
				description: "svc-b-external-ips-cluster-ip:svc-d-node-port-node-port",
				ip:          "172.20.0.173",
				port:        "30004",
				expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-node-port": {
				description: "svc-b-external-ips-cluster-ip:svc-e-node-port-node-port",
				ip:          "172.20.0.173",
				port:        "30005",
				expected:    "No route to host / connection timed out",
			},
		},
		"svc-c-node-port-cluster-ip": {
			"svc-a-external-ips-svc-port": {
				description: "svc-c-node-port-cluster-ip:svc-a-external-ips-svc-port",
				ip:          "172.20.0.100",
				port:        "82",
				expected:    "No route to host / connection timed out",
			},
			"svc-b-external-ips-svc-port": {
				description: "svc-c-node-port-cluster-ip:svc-b-external-ips-svc-port",
				ip:          "172.20.0.100",
				port:        "30002",
				expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-svc-port": {
				description: "svc-c-node-port-cluster-ip:svc-c-node-port-svc-port",
				ip:          "172.20.0.100",
				port:        "83",
				expected:    "app2",
			},
			"svc-d-node-port-svc-port": {
				description: "svc-c-node-port-cluster-ip:svc-d-node-port-svc-port",
				ip:          "172.20.0.100",
				port:        "84",
				expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-svc-port": {
				description: "svc-c-node-port-cluster-ip:svc-e-node-port-svc-port",
				ip:          "172.20.0.100",
				port:        "85",
				expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-node-port": {
				description: "svc-c-node-port-cluster-ip:svc-c-node-port-node-port",
				ip:          "172.20.0.100",
				port:        "30003",
				expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-node-port": {
				description: "svc-c-node-port-cluster-ip:svc-d-node-port-node-port",
				ip:          "172.20.0.100",
				port:        "30004",
				expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-node-port": {
				description: "svc-c-node-port-cluster-ip:svc-e-node-port-node-port",
				ip:          "172.20.0.100",
				port:        "30005",
				expected:    "No route to host / connection timed out",
			},
		},
		"svc-d-node-port-cluster-ip": {
			"svc-a-external-ips-svc-port": {
				description: "svc-d-node-port-cluster-ip:svc-a-external-ips-svc-port",
				ip:          "172.20.0.74",
				port:        "82",
				expected:    "No route to host / connection timed out",
			},
			"svc-b-external-ips-svc-port": {
				description: "svc-d-node-port-cluster-ip:svc-b-external-ips-svc-port",
				ip:          "172.20.0.74",
				port:        "30002",
				expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-svc-port": {
				description: "svc-d-node-port-cluster-ip:svc-c-node-port-svc-port",
				ip:          "172.20.0.74",
				port:        "83",
				expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-svc-port": {
				description: "svc-d-node-port-cluster-ip:svc-d-node-port-svc-port",
				ip:          "172.20.0.74",
				port:        "84",
				expected:    "app4",
			},
			"svc-e-node-port-svc-port": {
				description: "svc-d-node-port-cluster-ip:svc-e-node-port-svc-port",
				ip:          "172.20.0.74",
				port:        "85",
				expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-node-port": {
				description: "svc-d-node-port-cluster-ip:svc-c-node-port-node-port",
				ip:          "172.20.0.74",
				port:        "30003",
				expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-node-port": {
				description: "svc-d-node-port-cluster-ip:svc-d-node-port-node-port",
				ip:          "172.20.0.74",
				port:        "30004",
				expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-node-port": {
				description: "svc-d-node-port-cluster-ip:svc-e-node-port-node-port",
				ip:          "172.20.0.74",
				port:        "30005",
				expected:    "No route to host / connection timed out",
			},
		},
		"svc-e-node-port-cluster-ip": {
			"svc-a-external-ips-svc-port": {
				description: "svc-e-node-port-cluster-ip:svc-a-external-ips-svc-port",
				ip:          "172.20.0.213",
				port:        "82",
				expected:    "No route to host / connection timed out",
			},
			"svc-b-external-ips-svc-port": {
				description: "svc-e-node-port-cluster-ip:svc-b-external-ips-svc-port",
				ip:          "172.20.0.213",
				port:        "30002",
				expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-svc-port": {
				description: "svc-e-node-port-cluster-ip:svc-c-node-port-svc-port",
				ip:          "172.20.0.213",
				port:        "83",
				expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-svc-port": {
				description: "svc-e-node-port-cluster-ip:svc-d-node-port-svc-port",
				ip:          "172.20.0.213",
				port:        "84",
				expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-svc-port": {
				description: "svc-e-node-port-cluster-ip:svc-e-node-port-svc-port",
				ip:          "172.20.0.213",
				port:        "85",
				expected:    "app6",
			},
			"svc-c-node-port-node-port": {
				description: "svc-e-node-port-cluster-ip:svc-c-node-port-node-port",
				ip:          "172.20.0.213",
				port:        "30003",
				expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-node-port": {
				description: "svc-e-node-port-cluster-ip:svc-d-node-port-node-port",
				ip:          "172.20.0.213",
				port:        "30004",
				expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-node-port": {
				description: "svc-e-node-port-cluster-ip:svc-e-node-port-node-port",
				ip:          "172.20.0.213",
				port:        "30005",
				expected:    "No route to host / connection timed out",
			},
		},
	}
)
