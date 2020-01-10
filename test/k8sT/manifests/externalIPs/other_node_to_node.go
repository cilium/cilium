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
	ExpectedResultFromNode2 = map[string]map[string]EntryTestArgs{
		"svc-a-external-ips-k8s1-public": {
			"svc-a-external-ips-svc-port": {
				Description: "svc-a-external-ips-k8s1-public:svc-a-external-ips-svc-port",
				IP:          "192.0.2.233",
				Port:        "82",
				Expected:    "No route to host / connection timed out",
			},
			"svc-b-external-ips-svc-port": {
				Description: "svc-a-external-ips-k8s1-public:svc-b-external-ips-svc-port",
				IP:          "192.0.2.233",
				Port:        "30002",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-svc-port": {
				Description: "svc-a-external-ips-k8s1-public:svc-c-node-port-svc-port",
				IP:          "192.0.2.233",
				Port:        "83",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-svc-port": {
				Description: "svc-a-external-ips-k8s1-public:svc-d-node-port-svc-port",
				IP:          "192.0.2.233",
				Port:        "84",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-svc-port": {
				Description: "svc-a-external-ips-k8s1-public:svc-e-node-port-svc-port",
				IP:          "192.0.2.233",
				Port:        "85",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-node-port": {
				Description: "svc-a-external-ips-k8s1-public:svc-c-node-port-node-port",
				IP:          "192.0.2.233",
				Port:        "30003",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-node-port": {
				Description: "svc-a-external-ips-k8s1-public:svc-d-node-port-node-port",
				IP:          "192.0.2.233",
				Port:        "30004",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-node-port": {
				Description: "svc-a-external-ips-k8s1-public:svc-e-node-port-node-port",
				IP:          "192.0.2.233",
				Port:        "30005",
				Expected:    "No route to host / connection timed out",
			},
		},
		"svc-a-external-ips-k8s1-host-public": {
			"svc-a-external-ips-svc-port": {
				Description: "svc-a-external-ips-k8s1-host-public:svc-a-external-ips-svc-port",
				IP:          "192.168.34.11",
				Port:        "82",
				Expected:    "app1",
			},
			"svc-b-external-ips-svc-port": {
				Description: "svc-a-external-ips-k8s1-host-public:svc-b-external-ips-svc-port",
				IP:          "192.168.34.11",
				Port:        "30002",
				Expected:    "app1",
			},
			"svc-c-node-port-svc-port": {
				Description: "svc-a-external-ips-k8s1-host-public:svc-c-node-port-svc-port",
				IP:          "192.168.34.11",
				Port:        "83",
				Expected:    "connection refused",
			},
			"svc-d-node-port-svc-port": {
				Description: "svc-a-external-ips-k8s1-host-public:svc-d-node-port-svc-port",
				IP:          "192.168.34.11",
				Port:        "84",
				Expected:    "connection refused",
			},
			"svc-e-node-port-svc-port": {
				Description: "svc-a-external-ips-k8s1-host-public:svc-e-node-port-svc-port",
				IP:          "192.168.34.11",
				Port:        "85",
				Expected:    "connection refused",
			},
			"svc-c-node-port-node-port": {
				Description: "svc-a-external-ips-k8s1-host-public:svc-c-node-port-node-port",
				IP:          "192.168.34.11",
				Port:        "30003",
				Expected:    "app2",
			},
			"svc-d-node-port-node-port": {
				Description: "svc-a-external-ips-k8s1-host-public:svc-d-node-port-node-port",
				IP:          "192.168.34.11",
				Port:        "30004",
				Expected:    "app4",
			},
			"svc-e-node-port-node-port": {
				Description: "svc-a-external-ips-k8s1-host-public:svc-e-node-port-node-port",
				IP:          "192.168.34.11",
				Port:        "30005",
				Expected:    "app6",
				SkipReason:  "Because we SNAT the request. @dborkmann will fix it",
			},
		},
		"svc-a-external-ips-k8s1-host-private": {
			"svc-a-external-ips-svc-port": {
				Description: "svc-a-external-ips-k8s1-host-private:svc-a-external-ips-svc-port",
				IP:          "192.168.33.11",
				Port:        "82",
				Expected:    "app1",
				SkipReason: "on the receiving node we only install a BPF program " +
					"on the interface with the IP 192.168.34.11 so we can't translate " +
					"traffic incoming into this interface",
			},
			"svc-b-external-ips-svc-port": {
				Description: "svc-a-external-ips-k8s1-host-private:svc-b-external-ips-svc-port",
				IP:          "192.168.33.11",
				Port:        "30002",
				Expected:    "app1",
				SkipReason: "on the receiving node we only install a BPF program " +
					"on the interface with the IP 192.168.34.11 so we can't translate " +
					"traffic incoming into this interface",
			},
			"svc-c-node-port-svc-port": {
				Description: "svc-a-external-ips-k8s1-host-private:svc-c-node-port-svc-port",
				IP:          "192.168.33.11",
				Port:        "83",
				Expected:    "connection refused",
			},
			"svc-d-node-port-svc-port": {
				Description: "svc-a-external-ips-k8s1-host-private:svc-d-node-port-svc-port",
				IP:          "192.168.33.11",
				Port:        "84",
				Expected:    "connection refused",
			},
			"svc-e-node-port-svc-port": {
				Description: "svc-a-external-ips-k8s1-host-private:svc-e-node-port-svc-port",
				IP:          "192.168.33.11",
				Port:        "85",
				Expected:    "connection refused",
			},
			"svc-c-node-port-node-port": {
				Description: "svc-a-external-ips-k8s1-host-private:svc-c-node-port-node-port",
				IP:          "192.168.33.11",
				Port:        "30003",
				Expected:    "app2",
				SkipReason: "on the receiving node we only install a BPF program " +
					"on the interface with the IP 192.168.34.11 so we can't translate " +
					"traffic incoming into this interface",
			},
			"svc-d-node-port-node-port": {
				Description: "svc-a-external-ips-k8s1-host-private:svc-d-node-port-node-port",
				IP:          "192.168.33.11",
				Port:        "30004",
				Expected:    "app4",
				SkipReason: "on the receiving node we only install a BPF program " +
					"on the interface with the IP 192.168.34.11 so we can't translate " +
					"traffic incoming into this interface",
			},
			"svc-e-node-port-node-port": {
				Description: "svc-a-external-ips-k8s1-host-private:svc-e-node-port-node-port",
				IP:          "192.168.33.11",
				Port:        "30005",
				Expected:    "app6",
				SkipReason: "on the receiving node we only install a BPF program " +
					"on the interface with the IP 192.168.34.11 so we can't translate " +
					"traffic incoming into this interface",
			},
		},
		"svc-b-external-ips-k8s1-public": {
			"svc-a-external-ips-svc-port": {
				Description: "svc-b-external-ips-k8s1-public:svc-a-external-ips-svc-port",
				IP:          "192.0.2.233",
				Port:        "82",
				Expected:    "No route to host / connection timed out",
			},
			"svc-b-external-ips-svc-port": {
				Description: "svc-b-external-ips-k8s1-public:svc-b-external-ips-svc-port",
				IP:          "192.0.2.233",
				Port:        "30002",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-svc-port": {
				Description: "svc-b-external-ips-k8s1-public:svc-c-node-port-svc-port",
				IP:          "192.0.2.233",
				Port:        "83",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-svc-port": {
				Description: "svc-b-external-ips-k8s1-public:svc-d-node-port-svc-port",
				IP:          "192.0.2.233",
				Port:        "84",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-svc-port": {
				Description: "svc-b-external-ips-k8s1-public:svc-e-node-port-svc-port",
				IP:          "192.0.2.233",
				Port:        "85",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-node-port": {
				Description: "svc-b-external-ips-k8s1-public:svc-c-node-port-node-port",
				IP:          "192.0.2.233",
				Port:        "30003",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-node-port": {
				Description: "svc-b-external-ips-k8s1-public:svc-d-node-port-node-port",
				IP:          "192.0.2.233",
				Port:        "30004",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-node-port": {
				Description: "svc-b-external-ips-k8s1-public:svc-e-node-port-node-port",
				IP:          "192.0.2.233",
				Port:        "30005",
				Expected:    "No route to host / connection timed out",
			},
		},
		"svc-b-external-ips-k8s1-host-public": {
			"svc-a-external-ips-svc-port": {
				Description: "svc-b-external-ips-k8s1-host-public:svc-a-external-ips-svc-port",
				IP:          "192.168.34.11",
				Port:        "82",
				Expected:    "app1",
			},
			"svc-b-external-ips-svc-port": {
				Description: "svc-b-external-ips-k8s1-host-public:svc-b-external-ips-svc-port",
				IP:          "192.168.34.11",
				Port:        "30002",
				Expected:    "app1",
			},
			"svc-c-node-port-svc-port": {
				Description: "svc-b-external-ips-k8s1-host-public:svc-c-node-port-svc-port",
				IP:          "192.168.34.11",
				Port:        "83",
				Expected:    "connection refused",
			},
			"svc-d-node-port-svc-port": {
				Description: "svc-b-external-ips-k8s1-host-public:svc-d-node-port-svc-port",
				IP:          "192.168.34.11",
				Port:        "84",
				Expected:    "connection refused",
			},
			"svc-e-node-port-svc-port": {
				Description: "svc-b-external-ips-k8s1-host-public:svc-e-node-port-svc-port",
				IP:          "192.168.34.11",
				Port:        "85",
				Expected:    "connection refused",
			},
			"svc-c-node-port-node-port": {
				Description: "svc-b-external-ips-k8s1-host-public:svc-c-node-port-node-port",
				IP:          "192.168.34.11",
				Port:        "30003",
				Expected:    "app2",
			},
			"svc-d-node-port-node-port": {
				Description: "svc-b-external-ips-k8s1-host-public:svc-d-node-port-node-port",
				IP:          "192.168.34.11",
				Port:        "30004",
				Expected:    "app4",
			},
			"svc-e-node-port-node-port": {
				Description: "svc-b-external-ips-k8s1-host-public:svc-e-node-port-node-port",
				IP:          "192.168.34.11",
				Port:        "30005",
				Expected:    "app6",
				SkipReason:  "Because we SNAT the request. @dborkmann will fix it",
			},
		},
		"svc-b-external-ips-k8s1-host-private": {
			"svc-a-external-ips-svc-port": {
				Description: "svc-b-external-ips-k8s1-host-private:svc-a-external-ips-svc-port",
				IP:          "192.168.33.11",
				Port:        "82",
				Expected:    "app1",
				SkipReason: "on the receiving node we only install a BPF program " +
					"on the interface with the IP 192.168.34.11 so we can't translate " +
					"traffic incoming into this interface",
			},
			"svc-b-external-ips-svc-port": {
				Description: "svc-b-external-ips-k8s1-host-private:svc-b-external-ips-svc-port",
				IP:          "192.168.33.11",
				Port:        "30002",
				Expected:    "app1",
				SkipReason: "on the receiving node we only install a BPF program " +
					"on the interface with the IP 192.168.34.11 so we can't translate " +
					"traffic incoming into this interface",
			},
			"svc-c-node-port-svc-port": {
				Description: "svc-b-external-ips-k8s1-host-private:svc-c-node-port-svc-port",
				IP:          "192.168.33.11",
				Port:        "83",
				Expected:    "connection refused",
			},
			"svc-d-node-port-svc-port": {
				Description: "svc-b-external-ips-k8s1-host-private:svc-d-node-port-svc-port",
				IP:          "192.168.33.11",
				Port:        "84",
				Expected:    "connection refused",
			},
			"svc-e-node-port-svc-port": {
				Description: "svc-b-external-ips-k8s1-host-private:svc-e-node-port-svc-port",
				IP:          "192.168.33.11",
				Port:        "85",
				Expected:    "connection refused",
			},
			"svc-c-node-port-node-port": {
				Description: "svc-b-external-ips-k8s1-host-private:svc-c-node-port-node-port",
				IP:          "192.168.33.11",
				Port:        "30003",
				Expected:    "app2",
				SkipReason: "on the receiving node we only install a BPF program " +
					"on the interface with the IP 192.168.34.11 so we can't translate " +
					"traffic incoming into this interface",
			},
			"svc-d-node-port-node-port": {
				Description: "svc-b-external-ips-k8s1-host-private:svc-d-node-port-node-port",
				IP:          "192.168.33.11",
				Port:        "30004",
				Expected:    "app4",
				SkipReason: "on the receiving node we only install a BPF program " +
					"on the interface with the IP 192.168.34.11 so we can't translate " +
					"traffic incoming into this interface",
			},
			"svc-e-node-port-node-port": {
				Description: "svc-b-external-ips-k8s1-host-private:svc-e-node-port-node-port",
				IP:          "192.168.33.11",
				Port:        "30005",
				Expected:    "app6",
				SkipReason: "on the receiving node we only install a BPF program " +
					"on the interface with the IP 192.168.34.11 so we can't translate " +
					"traffic incoming into this interface",
			},
		},
		"localhost": {
			"svc-a-external-ips-svc-port": {
				Description: "localhost:svc-a-external-ips-svc-port",
				IP:          "127.0.0.1",
				Port:        "82",
				Expected:    "connection refused",
			},
			"svc-b-external-ips-svc-port": {
				Description: "localhost:svc-b-external-ips-svc-port",
				IP:          "127.0.0.1",
				Port:        "30002",
				Expected:    "connection refused",
			},
			"svc-c-node-port-svc-port": {
				Description: "localhost:svc-c-node-port-svc-port",
				IP:          "127.0.0.1",
				Port:        "83",
				Expected:    "connection refused",
			},
			"svc-d-node-port-svc-port": {
				Description: "localhost:svc-d-node-port-svc-port",
				IP:          "127.0.0.1",
				Port:        "84",
				Expected:    "connection refused",
			},
			"svc-e-node-port-svc-port": {
				Description: "localhost:svc-e-node-port-svc-port",
				IP:          "127.0.0.1",
				Port:        "85",
				Expected:    "connection refused",
			},
			"svc-c-node-port-node-port": {
				Description: "localhost:svc-c-node-port-node-port",
				IP:          "127.0.0.1",
				Port:        "30003",
				Expected:    "app2",
			},
			"svc-d-node-port-node-port": {
				Description: "localhost:svc-d-node-port-node-port",
				IP:          "127.0.0.1",
				Port:        "30004",
				Expected:    "app4",
			},
			"svc-e-node-port-node-port": {
				Description: "localhost:svc-e-node-port-node-port",
				IP:          "127.0.0.1",
				Port:        "30005",
				Expected:    "app6",
				SkipReason:  "needs kernel changes as we can't distinguish between pod traffic and host traffic",
			},
		},
		"svc-a-external-ips-cluster-ip": {
			"svc-a-external-ips-svc-port": {
				Description: "svc-a-external-ips-cluster-ip:svc-a-external-ips-svc-port",
				IP:          "172.20.0.223",
				Port:        "82",
				Expected:    "app1",
			},
			"svc-b-external-ips-svc-port": {
				Description: "svc-a-external-ips-cluster-ip:svc-b-external-ips-svc-port",
				IP:          "172.20.0.223",
				Port:        "30002",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-svc-port": {
				Description: "svc-a-external-ips-cluster-ip:svc-c-node-port-svc-port",
				IP:          "172.20.0.223",
				Port:        "83",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-svc-port": {
				Description: "svc-a-external-ips-cluster-ip:svc-d-node-port-svc-port",
				IP:          "172.20.0.223",
				Port:        "84",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-svc-port": {
				Description: "svc-a-external-ips-cluster-ip:svc-e-node-port-svc-port",
				IP:          "172.20.0.223",
				Port:        "85",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-node-port": {
				Description: "svc-a-external-ips-cluster-ip:svc-c-node-port-node-port",
				IP:          "172.20.0.223",
				Port:        "30003",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-node-port": {
				Description: "svc-a-external-ips-cluster-ip:svc-d-node-port-node-port",
				IP:          "172.20.0.223",
				Port:        "30004",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-node-port": {
				Description: "svc-a-external-ips-cluster-ip:svc-e-node-port-node-port",
				IP:          "172.20.0.223",
				Port:        "30005",
				Expected:    "No route to host / connection timed out",
			},
		},
		"svc-b-external-ips-cluster-ip": {
			"svc-a-external-ips-svc-port": {
				Description: "svc-b-external-ips-cluster-ip:svc-a-external-ips-svc-port",
				IP:          "172.20.0.111",
				Port:        "82",
				Expected:    "No route to host / connection timed out",
			},
			"svc-b-external-ips-svc-port": {
				Description: "svc-b-external-ips-cluster-ip:svc-b-external-ips-svc-port",
				IP:          "172.20.0.111",
				Port:        "30002",
				Expected:    "app1",
			},
			"svc-c-node-port-svc-port": {
				Description: "svc-b-external-ips-cluster-ip:svc-c-node-port-svc-port",
				IP:          "172.20.0.111",
				Port:        "83",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-svc-port": {
				Description: "svc-b-external-ips-cluster-ip:svc-d-node-port-svc-port",
				IP:          "172.20.0.111",
				Port:        "84",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-svc-port": {
				Description: "svc-b-external-ips-cluster-ip:svc-e-node-port-svc-port",
				IP:          "172.20.0.111",
				Port:        "85",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-node-port": {
				Description: "svc-b-external-ips-cluster-ip:svc-c-node-port-node-port",
				IP:          "172.20.0.111",
				Port:        "30003",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-node-port": {
				Description: "svc-b-external-ips-cluster-ip:svc-d-node-port-node-port",
				IP:          "172.20.0.111",
				Port:        "30004",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-node-port": {
				Description: "svc-b-external-ips-cluster-ip:svc-e-node-port-node-port",
				IP:          "172.20.0.111",
				Port:        "30005",
				Expected:    "No route to host / connection timed out",
			},
		},
		"svc-c-node-port-cluster-ip": {
			"svc-a-external-ips-svc-port": {
				Description: "svc-c-node-port-cluster-ip:svc-a-external-ips-svc-port",
				IP:          "172.20.0.141",
				Port:        "82",
				Expected:    "No route to host / connection timed out",
			},
			"svc-b-external-ips-svc-port": {
				Description: "svc-c-node-port-cluster-ip:svc-b-external-ips-svc-port",
				IP:          "172.20.0.141",
				Port:        "30002",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-svc-port": {
				Description: "svc-c-node-port-cluster-ip:svc-c-node-port-svc-port",
				IP:          "172.20.0.141",
				Port:        "83",
				Expected:    "app2",
			},
			"svc-d-node-port-svc-port": {
				Description: "svc-c-node-port-cluster-ip:svc-d-node-port-svc-port",
				IP:          "172.20.0.141",
				Port:        "84",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-svc-port": {
				Description: "svc-c-node-port-cluster-ip:svc-e-node-port-svc-port",
				IP:          "172.20.0.141",
				Port:        "85",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-node-port": {
				Description: "svc-c-node-port-cluster-ip:svc-c-node-port-node-port",
				IP:          "172.20.0.141",
				Port:        "30003",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-node-port": {
				Description: "svc-c-node-port-cluster-ip:svc-d-node-port-node-port",
				IP:          "172.20.0.141",
				Port:        "30004",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-node-port": {
				Description: "svc-c-node-port-cluster-ip:svc-e-node-port-node-port",
				IP:          "172.20.0.141",
				Port:        "30005",
				Expected:    "No route to host / connection timed out",
			},
		},
		"svc-d-node-port-cluster-ip": {
			"svc-a-external-ips-svc-port": {
				Description: "svc-d-node-port-cluster-ip:svc-a-external-ips-svc-port",
				IP:          "172.20.0.101",
				Port:        "82",
				Expected:    "No route to host / connection timed out",
			},
			"svc-b-external-ips-svc-port": {
				Description: "svc-d-node-port-cluster-ip:svc-b-external-ips-svc-port",
				IP:          "172.20.0.101",
				Port:        "30002",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-svc-port": {
				Description: "svc-d-node-port-cluster-ip:svc-c-node-port-svc-port",
				IP:          "172.20.0.101",
				Port:        "83",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-svc-port": {
				Description: "svc-d-node-port-cluster-ip:svc-d-node-port-svc-port",
				IP:          "172.20.0.101",
				Port:        "84",
				Expected:    "app4",
			},
			"svc-e-node-port-svc-port": {
				Description: "svc-d-node-port-cluster-ip:svc-e-node-port-svc-port",
				IP:          "172.20.0.101",
				Port:        "85",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-node-port": {
				Description: "svc-d-node-port-cluster-ip:svc-c-node-port-node-port",
				IP:          "172.20.0.101",
				Port:        "30003",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-node-port": {
				Description: "svc-d-node-port-cluster-ip:svc-d-node-port-node-port",
				IP:          "172.20.0.101",
				Port:        "30004",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-node-port": {
				Description: "svc-d-node-port-cluster-ip:svc-e-node-port-node-port",
				IP:          "172.20.0.101",
				Port:        "30005",
				Expected:    "No route to host / connection timed out",
			},
		},
		"svc-e-node-port-cluster-ip": {
			"svc-a-external-ips-svc-port": {
				Description: "svc-e-node-port-cluster-ip:svc-a-external-ips-svc-port",
				IP:          "172.20.0.80",
				Port:        "82",
				Expected:    "No route to host / connection timed out",
			},
			"svc-b-external-ips-svc-port": {
				Description: "svc-e-node-port-cluster-ip:svc-b-external-ips-svc-port",
				IP:          "172.20.0.80",
				Port:        "30002",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-port-svc-port": {
				Description: "svc-e-node-port-cluster-ip:svc-c-node-port-svc-port",
				IP:          "172.20.0.80",
				Port:        "83",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-svc-port": {
				Description: "svc-e-node-port-cluster-ip:svc-d-node-port-svc-port",
				IP:          "172.20.0.80",
				Port:        "84",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-svc-port": {
				Description: "svc-e-node-port-cluster-ip:svc-e-node-port-svc-port",
				IP:          "172.20.0.80",
				Port:        "85",
				Expected:    "app6",
				SkipReason:  "Because we SNAT the request. @dborkmann will fix it",
			},
			"svc-c-node-port-node-port": {
				Description: "svc-e-node-port-cluster-ip:svc-c-node-port-node-port",
				IP:          "172.20.0.80",
				Port:        "30003",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-port-node-port": {
				Description: "svc-e-node-port-cluster-ip:svc-d-node-port-node-port",
				IP:          "172.20.0.80",
				Port:        "30004",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-port-node-port": {
				Description: "svc-e-node-port-cluster-ip:svc-e-node-port-node-port",
				IP:          "172.20.0.80",
				Port:        "30005",
				Expected:    "No route to host / connection timed out",
			},
		},
	}
)
