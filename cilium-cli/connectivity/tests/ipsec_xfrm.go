// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	gojson "encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/defaults"
)

type ciliumMetricsXfrmError struct {
	Labels struct {
		Error string `json:"error"`
		Type  string `json:"type"`
	} `json:"labels"`
	Name  string `json:"name"`
	Value uint64 `json:"value"`
}

func NoIPsecXfrmErrors() check.Scenario {
	return &noIPsecXfrmErrors{}
}

type noIPsecXfrmErrors struct{}

func (n *noIPsecXfrmErrors) Name() string {
	return "no-ipsec-xfrm-error"
}

func (n *noIPsecXfrmErrors) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()
	crtXfrmErrors := n.collectXfrmErrors(ctx, t)

	if ct.Params().ConnDisruptTestSetup {
		n.storeIPsecXfrmErrors(t, crtXfrmErrors)
		return
	}

	prevXfrmErrors := n.loadIPsecXfrmErrors(t)
	for node, crtErr := range crtXfrmErrors {
		if preErr, found := prevXfrmErrors[node]; !found {
			t.Fatalf("Could not found Node %s xfrm errors", node)
		} else if preErr != crtErr {
			t.Fatalf("Node %s xfrm errors were changed (previous errors: %s, current errors: %s)",
				node, preErr, crtErr)
		}
	}
}

func (n *noIPsecXfrmErrors) collectXfrmErrors(ctx context.Context, t *check.Test) map[string]string {

	xfrmErrors := map[string]string{}

	client := t.Context().K8sClient()
	nodes, err := client.ListNodes(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Unable to list nodes: %s", err)
	}
	if len(nodes.Items) == 0 {
		t.Fatal("No nodes found")
	}

	for _, node := range nodes.Items {
		ciliumPods, err := client.ListPods(ctx, "kube-system",
			metav1.ListOptions{LabelSelector: defaults.AgentPodSelector, FieldSelector: "spec.nodeName=" + node.GetName()})
		if err != nil {
			t.Fatalf("Unable to list cilium pods: %s", err)
		}
		if len(ciliumPods.Items) == 0 {
			t.Fatalf("No cilium pods found")
		}

		encryptStatus, err := client.ExecInPod(ctx, "kube-system", ciliumPods.Items[0].GetName(), "",
			[]string{"cilium", "metrics", "list", "-ojson", "-pcilium_ipsec_xfrm_error"})
		if err != nil {
			t.Fatalf("Unable to get cilium ipsec xfrm error metrics: %s", err)
		}

		xErrors := []string{}
		xfrmMetrics := []ciliumMetricsXfrmError{}
		if err := json.Unmarshal(encryptStatus.Bytes(), &xfrmMetrics); err != nil {
			t.Fatalf("Unable to unmarshal cilium ipsec xfrm error metrics: %s", err)
		}
		for _, xfrmMetric := range xfrmMetrics {
			if xfrmMetric.Value > 0 {
				xErrors = append(xErrors,
					fmt.Sprintf("%s_%s:%d",
						xfrmMetric.Labels.Type, xfrmMetric.Labels.Error, xfrmMetric.Value))
			}
			sort.Strings(xErrors)
			xfrmErrors[node.GetName()] = strings.Join(xErrors, ",")
		}
	}
	return xfrmErrors
}

func (n *noIPsecXfrmErrors) storeIPsecXfrmErrors(t *check.Test, xfrmErrors map[string]string) {
	ct := t.Context()
	file, err := os.Create(ct.Params().ConnDisruptTestXfrmErrorsPath)
	if err != nil {
		t.Fatalf("Failed to create %q file for writing disrupt test temp results: %s",
			ct.Params().ConnDisruptTestXfrmErrorsPath, err)
	}
	defer file.Close()

	j, err := gojson.Marshal(xfrmErrors)
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %s", err)
	}

	if _, err := file.Write(j); err != nil {
		t.Fatalf("Failed to write conn disrupt test temp result into file: %s", err)
	}
}

func (n *noIPsecXfrmErrors) loadIPsecXfrmErrors(t *check.Test) map[string]string {
	b, err := os.ReadFile(t.Context().Params().ConnDisruptTestXfrmErrorsPath)
	if err != nil {
		t.Fatalf("Failed to read conn disrupt test result files: %s", err)
	}
	xfrmErrors := map[string]string{}
	if err := gojson.Unmarshal(b, &xfrmErrors); err != nil {
		t.Fatalf("Failed to unmarshal JSON test result file: %s", err)
	}
	return xfrmErrors
}
