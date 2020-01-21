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
	ExpectedResultFromNode1 = map[string]map[string]EntryTestArgs{
		"svc-a-external-ips-k8s1-public": {
			"svc-a-external-ips-svc-Port": {
				Description: "svc-a-external-ips-k8s1-public:svc-a-external-ips-svc-Port",
				IP:          "192.0.2.233",
				Port:        "82",
				Expected:    "No route to host / connection timed out",
			},
			"svc-b-external-ips-svc-Port": {
				Description: "svc-a-external-ips-k8s1-public:svc-b-external-ips-svc-Port",
				IP:          "192.0.2.233",
				Port:        "30002",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-Port-svc-Port": {
				Description: "svc-a-external-ips-k8s1-public:svc-c-node-Port-svc-Port",
				IP:          "192.0.2.233",
				Port:        "83",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-Port-svc-Port": {
				Description: "svc-a-external-ips-k8s1-public:svc-d-node-Port-svc-Port",
				IP:          "192.0.2.233",
				Port:        "84",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-Port-svc-Port": {
				Description: "svc-a-external-ips-k8s1-public:svc-e-node-Port-svc-Port",
				IP:          "192.0.2.233",
				Port:        "85",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-Port-node-Port": {
				Description: "svc-a-external-ips-k8s1-public:svc-c-node-Port-node-Port",
				IP:          "192.0.2.233",
				Port:        "30003",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-Port-node-Port": {
				Description: "svc-a-external-ips-k8s1-public:svc-d-node-Port-node-Port",
				IP:          "192.0.2.233",
				Port:        "30004",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-Port-node-Port": {
				Description: "svc-a-external-ips-k8s1-public:svc-e-node-Port-node-Port",
				IP:          "192.0.2.233",
				Port:        "30005",
				Expected:    "No route to host / connection timed out",
			},
		},
		"svc-a-external-ips-k8s1-host-public": {
			"svc-a-external-ips-svc-Port": {
				Description: "svc-a-external-ips-k8s1-host-public:svc-a-external-ips-svc-Port",
				IP:          "192.168.34.11",
				Port:        "82",
				Expected:    "app1",
			},
			"svc-b-external-ips-svc-Port": {
				Description: "svc-a-external-ips-k8s1-host-public:svc-b-external-ips-svc-Port",
				IP:          "192.168.34.11",
				Port:        "30002",
				Expected:    "app1",
			},
			"svc-c-node-Port-svc-Port": {
				Description: "svc-a-external-ips-k8s1-host-public:svc-c-node-Port-svc-Port",
				IP:          "192.168.34.11",
				Port:        "83",
				Expected:    "connection refused",
			},
			"svc-d-node-Port-svc-Port": {
				Description: "svc-a-external-ips-k8s1-host-public:svc-d-node-Port-svc-Port",
				IP:          "192.168.34.11",
				Port:        "84",
				Expected:    "connection refused",
			},
			"svc-e-node-Port-svc-Port": {
				Description: "svc-a-external-ips-k8s1-host-public:svc-e-node-Port-svc-Port",
				IP:          "192.168.34.11",
				Port:        "85",
				Expected:    "connection refused",
			},
			"svc-c-node-Port-node-Port": {
				Description: "svc-a-external-ips-k8s1-host-public:svc-c-node-Port-node-Port",
				IP:          "192.168.34.11",
				Port:        "30003",
				Expected:    "app2",
			},
			"svc-d-node-Port-node-Port": {
				Description: "svc-a-external-ips-k8s1-host-public:svc-d-node-Port-node-Port",
				IP:          "192.168.34.11",
				Port:        "30004",
				Expected:    "app4",
			},
			"svc-e-node-Port-node-Port": {
				Description: "svc-a-external-ips-k8s1-host-public:svc-e-node-Port-node-Port",
				IP:          "192.168.34.11",
				Port:        "30005",
				Expected:    "app6",
			},
		},
		"svc-a-external-ips-k8s1-host-private": {
			"svc-a-external-ips-svc-Port": {
				Description: "svc-a-external-ips-k8s1-host-private:svc-a-external-ips-svc-Port",
				IP:          "192.168.33.11",
				Port:        "82",
				Expected:    "app1",
			},
			"svc-b-external-ips-svc-Port": {
				Description: "svc-a-external-ips-k8s1-host-private:svc-b-external-ips-svc-Port",
				IP:          "192.168.33.11",
				Port:        "30002",
				Expected:    "app1",
			},
			"svc-c-node-Port-svc-Port": {
				Description: "svc-a-external-ips-k8s1-host-private:svc-c-node-Port-svc-Port",
				IP:          "192.168.33.11",
				Port:        "83",
				Expected:    "connection refused",
			},
			"svc-d-node-Port-svc-Port": {
				Description: "svc-a-external-ips-k8s1-host-private:svc-d-node-Port-svc-Port",
				IP:          "192.168.33.11",
				Port:        "84",
				Expected:    "connection refused",
			},
			"svc-e-node-Port-svc-Port": {
				Description: "svc-a-external-ips-k8s1-host-private:svc-e-node-Port-svc-Port",
				IP:          "192.168.33.11",
				Port:        "85",
				Expected:    "connection refused",
			},
			"svc-c-node-Port-node-Port": {
				Description: "svc-a-external-ips-k8s1-host-private:svc-c-node-Port-node-Port",
				IP:          "192.168.33.11",
				Port:        "30003",
				Expected:    "app2",
			},
			"svc-d-node-Port-node-Port": {
				Description: "svc-a-external-ips-k8s1-host-private:svc-d-node-Port-node-Port",
				IP:          "192.168.33.11",
				Port:        "30004",
				Expected:    "app4",
			},
			"svc-e-node-Port-node-Port": {
				Description: "svc-a-external-ips-k8s1-host-private:svc-e-node-Port-node-Port",
				IP:          "192.168.33.11",
				Port:        "30005",
				Expected:    "app6",
			},
		},
		"svc-b-external-ips-k8s1-public": {
			"svc-a-external-ips-svc-Port": {
				Description: "svc-b-external-ips-k8s1-public:svc-a-external-ips-svc-Port",
				IP:          "192.0.2.233",
				Port:        "82",
				Expected:    "No route to host / connection timed out",
			},
			"svc-b-external-ips-svc-Port": {
				Description: "svc-b-external-ips-k8s1-public:svc-b-external-ips-svc-Port",
				IP:          "192.0.2.233",
				Port:        "30002",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-Port-svc-Port": {
				Description: "svc-b-external-ips-k8s1-public:svc-c-node-Port-svc-Port",
				IP:          "192.0.2.233",
				Port:        "83",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-Port-svc-Port": {
				Description: "svc-b-external-ips-k8s1-public:svc-d-node-Port-svc-Port",
				IP:          "192.0.2.233",
				Port:        "84",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-Port-svc-Port": {
				Description: "svc-b-external-ips-k8s1-public:svc-e-node-Port-svc-Port",
				IP:          "192.0.2.233",
				Port:        "85",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-Port-node-Port": {
				Description: "svc-b-external-ips-k8s1-public:svc-c-node-Port-node-Port",
				IP:          "192.0.2.233",
				Port:        "30003",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-Port-node-Port": {
				Description: "svc-b-external-ips-k8s1-public:svc-d-node-Port-node-Port",
				IP:          "192.0.2.233",
				Port:        "30004",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-Port-node-Port": {
				Description: "svc-b-external-ips-k8s1-public:svc-e-node-Port-node-Port",
				IP:          "192.0.2.233",
				Port:        "30005",
				Expected:    "No route to host / connection timed out",
			},
		},
		"svc-b-external-ips-k8s1-host-public": {
			"svc-a-external-ips-svc-Port": {
				Description: "svc-b-external-ips-k8s1-host-public:svc-a-external-ips-svc-Port",
				IP:          "192.168.34.11",
				Port:        "82",
				Expected:    "app1",
			},
			"svc-b-external-ips-svc-Port": {
				Description: "svc-b-external-ips-k8s1-host-public:svc-b-external-ips-svc-Port",
				IP:          "192.168.34.11",
				Port:        "30002",
				Expected:    "app1",
			},
			"svc-c-node-Port-svc-Port": {
				Description: "svc-b-external-ips-k8s1-host-public:svc-c-node-Port-svc-Port",
				IP:          "192.168.34.11",
				Port:        "83",
				Expected:    "connection refused",
			},
			"svc-d-node-Port-svc-Port": {
				Description: "svc-b-external-ips-k8s1-host-public:svc-d-node-Port-svc-Port",
				IP:          "192.168.34.11",
				Port:        "84",
				Expected:    "connection refused",
			},
			"svc-e-node-Port-svc-Port": {
				Description: "svc-b-external-ips-k8s1-host-public:svc-e-node-Port-svc-Port",
				IP:          "192.168.34.11",
				Port:        "85",
				Expected:    "connection refused",
			},
			"svc-c-node-Port-node-Port": {
				Description: "svc-b-external-ips-k8s1-host-public:svc-c-node-Port-node-Port",
				IP:          "192.168.34.11",
				Port:        "30003",
				Expected:    "app2",
			},
			"svc-d-node-Port-node-Port": {
				Description: "svc-b-external-ips-k8s1-host-public:svc-d-node-Port-node-Port",
				IP:          "192.168.34.11",
				Port:        "30004",
				Expected:    "app4",
			},
			"svc-e-node-Port-node-Port": {
				Description: "svc-b-external-ips-k8s1-host-public:svc-e-node-Port-node-Port",
				IP:          "192.168.34.11",
				Port:        "30005",
				Expected:    "app6",
			},
		},
		"svc-b-external-ips-k8s1-host-private": {
			"svc-a-external-ips-svc-Port": {
				Description: "svc-b-external-ips-k8s1-host-private:svc-a-external-ips-svc-Port",
				IP:          "192.168.33.11",
				Port:        "82",
				Expected:    "app1",
			},
			"svc-b-external-ips-svc-Port": {
				Description: "svc-b-external-ips-k8s1-host-private:svc-b-external-ips-svc-Port",
				IP:          "192.168.33.11",
				Port:        "30002",
				Expected:    "app1",
			},
			"svc-c-node-Port-svc-Port": {
				Description: "svc-b-external-ips-k8s1-host-private:svc-c-node-Port-svc-Port",
				IP:          "192.168.33.11",
				Port:        "83",
				Expected:    "connection refused",
			},
			"svc-d-node-Port-svc-Port": {
				Description: "svc-b-external-ips-k8s1-host-private:svc-d-node-Port-svc-Port",
				IP:          "192.168.33.11",
				Port:        "84",
				Expected:    "connection refused",
			},
			"svc-e-node-Port-svc-Port": {
				Description: "svc-b-external-ips-k8s1-host-private:svc-e-node-Port-svc-Port",
				IP:          "192.168.33.11",
				Port:        "85",
				Expected:    "connection refused",
			},
			"svc-c-node-Port-node-Port": {
				Description: "svc-b-external-ips-k8s1-host-private:svc-c-node-Port-node-Port",
				IP:          "192.168.33.11",
				Port:        "30003",
				Expected:    "app2",
			},
			"svc-d-node-Port-node-Port": {
				Description: "svc-b-external-ips-k8s1-host-private:svc-d-node-Port-node-Port",
				IP:          "192.168.33.11",
				Port:        "30004",
				Expected:    "app4",
			},
			"svc-e-node-Port-node-Port": {
				Description: "svc-b-external-ips-k8s1-host-private:svc-e-node-Port-node-Port",
				IP:          "192.168.33.11",
				Port:        "30005",
				Expected:    "app6",
			},
		},
		"localhost": {
			"svc-a-external-ips-svc-Port": {
				Description: "localhost:svc-a-external-ips-svc-Port",
				IP:          "127.0.0.1",
				Port:        "82",
				Expected:    "connection refused",
			},
			"svc-b-external-ips-svc-Port": {
				Description: "localhost:svc-b-external-ips-svc-Port",
				IP:          "127.0.0.1",
				Port:        "30002",
				Expected:    "connection refused",
			},
			"svc-c-node-Port-svc-Port": {
				Description: "localhost:svc-c-node-Port-svc-Port",
				IP:          "127.0.0.1",
				Port:        "83",
				Expected:    "connection refused",
			},
			"svc-d-node-Port-svc-Port": {
				Description: "localhost:svc-d-node-Port-svc-Port",
				IP:          "127.0.0.1",
				Port:        "84",
				Expected:    "connection refused",
			},
			"svc-e-node-Port-svc-Port": {
				Description: "localhost:svc-e-node-Port-svc-Port",
				IP:          "127.0.0.1",
				Port:        "85",
				Expected:    "connection refused",
			},
			"svc-c-node-Port-node-Port": {
				Description: "localhost:svc-c-node-Port-node-Port",
				IP:          "127.0.0.1",
				Port:        "30003",
				Expected:    "app2",
			},
			"svc-d-node-Port-node-Port": {
				Description: "localhost:svc-d-node-Port-node-Port",
				IP:          "127.0.0.1",
				Port:        "30004",
				Expected:    "app4",
			},
			"svc-e-node-Port-node-Port": {
				Description: "localhost:svc-e-node-Port-node-Port",
				IP:          "127.0.0.1",
				Port:        "30005",
				Expected:    "app6",
			},
		},
		"svc-a-external-ips-cluster-IP": {
			"svc-a-external-ips-svc-Port": {
				Description: "svc-a-external-ips-cluster-IP:svc-a-external-ips-svc-Port",
				IP:          "172.20.0.112",
				Port:        "82",
				Expected:    "app1",
			},
			"svc-b-external-ips-svc-Port": {
				Description: "svc-a-external-ips-cluster-IP:svc-b-external-ips-svc-Port",
				IP:          "172.20.0.112",
				Port:        "30002",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-Port-svc-Port": {
				Description: "svc-a-external-ips-cluster-IP:svc-c-node-Port-svc-Port",
				IP:          "172.20.0.112",
				Port:        "83",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-Port-svc-Port": {
				Description: "svc-a-external-ips-cluster-IP:svc-d-node-Port-svc-Port",
				IP:          "172.20.0.112",
				Port:        "84",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-Port-svc-Port": {
				Description: "svc-a-external-ips-cluster-IP:svc-e-node-Port-svc-Port",
				IP:          "172.20.0.112",
				Port:        "85",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-Port-node-Port": {
				Description: "svc-a-external-ips-cluster-IP:svc-c-node-Port-node-Port",
				IP:          "172.20.0.112",
				Port:        "30003",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-Port-node-Port": {
				Description: "svc-a-external-ips-cluster-IP:svc-d-node-Port-node-Port",
				IP:          "172.20.0.112",
				Port:        "30004",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-Port-node-Port": {
				Description: "svc-a-external-ips-cluster-IP:svc-e-node-Port-node-Port",
				IP:          "172.20.0.112",
				Port:        "30005",
				Expected:    "No route to host / connection timed out",
			},
		},
		"svc-b-external-ips-cluster-IP": {
			"svc-a-external-ips-svc-Port": {
				Description: "svc-b-external-ips-cluster-IP:svc-a-external-ips-svc-Port",
				IP:          "172.20.0.173",
				Port:        "82",
				Expected:    "No route to host / connection timed out",
			},
			"svc-b-external-ips-svc-Port": {
				Description: "svc-b-external-ips-cluster-IP:svc-b-external-ips-svc-Port",
				IP:          "172.20.0.173",
				Port:        "30002",
				Expected:    "app1",
			},
			"svc-c-node-Port-svc-Port": {
				Description: "svc-b-external-ips-cluster-IP:svc-c-node-Port-svc-Port",
				IP:          "172.20.0.173",
				Port:        "83",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-Port-svc-Port": {
				Description: "svc-b-external-ips-cluster-IP:svc-d-node-Port-svc-Port",
				IP:          "172.20.0.173",
				Port:        "84",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-Port-svc-Port": {
				Description: "svc-b-external-ips-cluster-IP:svc-e-node-Port-svc-Port",
				IP:          "172.20.0.173",
				Port:        "85",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-Port-node-Port": {
				Description: "svc-b-external-ips-cluster-IP:svc-c-node-Port-node-Port",
				IP:          "172.20.0.173",
				Port:        "30003",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-Port-node-Port": {
				Description: "svc-b-external-ips-cluster-IP:svc-d-node-Port-node-Port",
				IP:          "172.20.0.173",
				Port:        "30004",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-Port-node-Port": {
				Description: "svc-b-external-ips-cluster-IP:svc-e-node-Port-node-Port",
				IP:          "172.20.0.173",
				Port:        "30005",
				Expected:    "No route to host / connection timed out",
			},
		},
		"svc-c-node-Port-cluster-IP": {
			"svc-a-external-ips-svc-Port": {
				Description: "svc-c-node-Port-cluster-IP:svc-a-external-ips-svc-Port",
				IP:          "172.20.0.100",
				Port:        "82",
				Expected:    "No route to host / connection timed out",
			},
			"svc-b-external-ips-svc-Port": {
				Description: "svc-c-node-Port-cluster-IP:svc-b-external-ips-svc-Port",
				IP:          "172.20.0.100",
				Port:        "30002",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-Port-svc-Port": {
				Description: "svc-c-node-Port-cluster-IP:svc-c-node-Port-svc-Port",
				IP:          "172.20.0.100",
				Port:        "83",
				Expected:    "app2",
			},
			"svc-d-node-Port-svc-Port": {
				Description: "svc-c-node-Port-cluster-IP:svc-d-node-Port-svc-Port",
				IP:          "172.20.0.100",
				Port:        "84",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-Port-svc-Port": {
				Description: "svc-c-node-Port-cluster-IP:svc-e-node-Port-svc-Port",
				IP:          "172.20.0.100",
				Port:        "85",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-Port-node-Port": {
				Description: "svc-c-node-Port-cluster-IP:svc-c-node-Port-node-Port",
				IP:          "172.20.0.100",
				Port:        "30003",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-Port-node-Port": {
				Description: "svc-c-node-Port-cluster-IP:svc-d-node-Port-node-Port",
				IP:          "172.20.0.100",
				Port:        "30004",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-Port-node-Port": {
				Description: "svc-c-node-Port-cluster-IP:svc-e-node-Port-node-Port",
				IP:          "172.20.0.100",
				Port:        "30005",
				Expected:    "No route to host / connection timed out",
			},
		},
		"svc-d-node-Port-cluster-IP": {
			"svc-a-external-ips-svc-Port": {
				Description: "svc-d-node-Port-cluster-IP:svc-a-external-ips-svc-Port",
				IP:          "172.20.0.74",
				Port:        "82",
				Expected:    "No route to host / connection timed out",
			},
			"svc-b-external-ips-svc-Port": {
				Description: "svc-d-node-Port-cluster-IP:svc-b-external-ips-svc-Port",
				IP:          "172.20.0.74",
				Port:        "30002",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-Port-svc-Port": {
				Description: "svc-d-node-Port-cluster-IP:svc-c-node-Port-svc-Port",
				IP:          "172.20.0.74",
				Port:        "83",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-Port-svc-Port": {
				Description: "svc-d-node-Port-cluster-IP:svc-d-node-Port-svc-Port",
				IP:          "172.20.0.74",
				Port:        "84",
				Expected:    "app4",
			},
			"svc-e-node-Port-svc-Port": {
				Description: "svc-d-node-Port-cluster-IP:svc-e-node-Port-svc-Port",
				IP:          "172.20.0.74",
				Port:        "85",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-Port-node-Port": {
				Description: "svc-d-node-Port-cluster-IP:svc-c-node-Port-node-Port",
				IP:          "172.20.0.74",
				Port:        "30003",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-Port-node-Port": {
				Description: "svc-d-node-Port-cluster-IP:svc-d-node-Port-node-Port",
				IP:          "172.20.0.74",
				Port:        "30004",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-Port-node-Port": {
				Description: "svc-d-node-Port-cluster-IP:svc-e-node-Port-node-Port",
				IP:          "172.20.0.74",
				Port:        "30005",
				Expected:    "No route to host / connection timed out",
			},
		},
		"svc-e-node-Port-cluster-IP": {
			"svc-a-external-ips-svc-Port": {
				Description: "svc-e-node-Port-cluster-IP:svc-a-external-ips-svc-Port",
				IP:          "172.20.0.213",
				Port:        "82",
				Expected:    "No route to host / connection timed out",
			},
			"svc-b-external-ips-svc-Port": {
				Description: "svc-e-node-Port-cluster-IP:svc-b-external-ips-svc-Port",
				IP:          "172.20.0.213",
				Port:        "30002",
				Expected:    "No route to host / connection timed out",
			},
			"svc-c-node-Port-svc-Port": {
				Description: "svc-e-node-Port-cluster-IP:svc-c-node-Port-svc-Port",
				IP:          "172.20.0.213",
				Port:        "83",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-Port-svc-Port": {
				Description: "svc-e-node-Port-cluster-IP:svc-d-node-Port-svc-Port",
				IP:          "172.20.0.213",
				Port:        "84",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-Port-svc-Port": {
				Description: "svc-e-node-Port-cluster-IP:svc-e-node-Port-svc-Port",
				IP:          "172.20.0.213",
				Port:        "85",
				Expected:    "app6",
			},
			"svc-c-node-Port-node-Port": {
				Description: "svc-e-node-Port-cluster-IP:svc-c-node-Port-node-Port",
				IP:          "172.20.0.213",
				Port:        "30003",
				Expected:    "No route to host / connection timed out",
			},
			"svc-d-node-Port-node-Port": {
				Description: "svc-e-node-Port-cluster-IP:svc-d-node-Port-node-Port",
				IP:          "172.20.0.213",
				Port:        "30004",
				Expected:    "No route to host / connection timed out",
			},
			"svc-e-node-Port-node-Port": {
				Description: "svc-e-node-Port-cluster-IP:svc-e-node-Port-node-Port",
				IP:          "172.20.0.213",
				Port:        "30005",
				Expected:    "No route to host / connection timed out",
			},
		},
	}
)
