// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	gojson "encoding/json"
	"os"
	"strconv"

	"github.com/cilium/cilium-cli/connectivity/check"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NoInterruptedConnections checks whether there are no interruptions in
// long-lived E/W LB connections. The test case is used to validate Cilium
// upgrades.
//
// The test case consists of three steps:
//
// 1. Deploying pods and a service which establish the long-lived connections
// (done by "--conn-disrupt-test-setup"). The client pods ("test-conn-disrupt-client")
// establish connections via ClusterIP ("test-conn-disrupt") to server pods
// ("test-conn-disrupt-server"). As there former pods come first before the latter,
// the former pods can crash which increases the pod restart counter. The step
// is responsible for storing the restart counter too.
// 2. Do Cilium upgrade.
// 3. Run the test ("--include-conn-disrupt-test"). The test checks the restart
// counters, and compares them against the previously stored ones. A mismatch
// indicates that a connection was interrupted.
func NoInterruptedConnections() check.Scenario {
	return &noInterruptedConnections{}
}

type noInterruptedConnections struct{}

func (n *noInterruptedConnections) Name() string {
	return "no-interrupted-connections"
}

func (n *noInterruptedConnections) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	client := ct.K8sClient()
	pods, err := client.ListPods(ctx, ct.Params().TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + check.KindTestConnDisrupt})
	if err != nil {
		t.Fatalf("Unable to list test-conn-disrupt pods: %s", err)
	}
	if len(pods.Items) == 0 {
		t.Fatal("No test-conn-disrupt-{client,server} pods found")
	}

	restartCount := make(map[string]string)
	for _, pod := range pods.Items {
		restartCount[pod.GetObjectMeta().GetName()] = strconv.Itoa(int(pod.Status.ContainerStatuses[0].RestartCount))
	}

	// Only store restart counters which will be used later when running the same
	// test case, but w/o --conn-disrupt-test-setup.
	if ct.Params().ConnDisruptTestSetup {
		file, err := os.Create(ct.Params().ConnDisruptTestRestartsPath)
		if err != nil {
			t.Fatalf("Failed to create %q file for writing conn disrupt test temp results: %s",
				ct.Params().ConnDisruptTestRestartsPath, err)
		}
		defer file.Close()

		counts := make(map[string]string)
		for pod, count := range restartCount {
			counts[pod] = count
		}
		j, err := gojson.Marshal(counts)
		if err != nil {
			t.Fatalf("Failed to marshal JSON: %s", err)
		}

		if _, err := file.Write(j); err != nil {
			t.Fatalf("Failed to write conn disrupt test temp result into file: %s", err)
		}

		return
	}

	b, err := os.ReadFile(ct.Params().ConnDisruptTestRestartsPath)
	if err != nil {
		t.Fatalf("Failed to read conn disrupt test result files: %s", err)
	}
	prevRestartCount := make(map[string]string)
	if err := gojson.Unmarshal(b, &prevRestartCount); err != nil {
		t.Fatalf("Failed to unmarshal JSON test result file: %s", err)
	}

	for pod, count := range restartCount {
		if prevCount, found := prevRestartCount[pod]; !found {
			t.Fatalf("Could not found Pod %s restart count", pod)
		} else if prevCount != count {
			t.Fatalf("Pod %s flow was interrupted (restart count does not match %s != %s)",
				pod, prevCount, count)
		}
	}
}
