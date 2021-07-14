// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package k8sTest

import (
	"github.com/cilium/cilium/test/helpers"
)

var (
	deploymentManager = helpers.NewDeploymentManager()

	DemoDaemonSet = helpers.Manifest{
		Filename:        "demo_ds.yaml",
		Alternate:       "demo_ds_local.yaml",
		DaemonSetNames:  []string{"testds", "testclient"},
		DeploymentNames: []string{"test-k8s2"},
		NumPods:         1,
		Singleton:       true,
	}

	NetperfPods = helpers.Manifest{
		Filename:      "netperf-deployment.yaml",
		NumPods:       2,
		LabelSelector: "zgroup=testapp",
	}

	HttpServer = helpers.Manifest{
		Filename:      "http-deployment.yaml",
		NumPods:       2,
		LabelSelector: "zgroup=http-server",
	}

	HttpClients = helpers.Manifest{
		Filename:      "http-clients.yaml",
		NumPods:       2,
		LabelSelector: "zgroup=http-clients",
	}

	DemoHostFirewall = helpers.Manifest{
		Filename:       "demo_hostfw.yaml",
		DaemonSetNames: []string{"testserver", "testclient", "testserver-host", "testclient-host"},
		LabelSelector:  "zgroup=DS",
	}

	IPSecSecret = helpers.Manifest{
		Filename: "ipsec_secret.yaml",
	}

	StatelessEtcd = helpers.Manifest{
		Filename:      "etcd-deployment.yaml",
		NumPods:       1,
		LabelSelector: "name=stateless-etcd",
	}

	ConnectivityCheck = helpers.Manifest{
		Filename:      "policy-stress-test.yaml",
		NumPods:       14,
		LabelSelector: "manifest=policy-stress-test",
		Singleton:     true,
	}
)
