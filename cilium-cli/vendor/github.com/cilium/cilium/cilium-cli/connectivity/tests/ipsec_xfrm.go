// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/utils/features"
)

const (
	maxExpectedErrors = 10
)

type ciliumMetricsXfrmError struct {
	Labels struct {
		Error string `json:"error"`
		Type  string `json:"type"`
	} `json:"labels"`
	Name  string `json:"name"`
	Value uint64 `json:"value"`
}

func NoIPsecXfrmErrors(expectedErrors []string) check2.Scenario {
	return &noIPsecXfrmErrors{
		features.ComputeFailureExceptions(defaults.ExpectedXFRMErrors, expectedErrors),
	}
}

type noIPsecXfrmErrors struct {
	expectedErrors []string
}

func (n *noIPsecXfrmErrors) Name() string {
	return "no-ipsec-xfrm-error"
}

func (n *noIPsecXfrmErrors) Run(ctx context.Context, t *check2.Test) {
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

func (n *noIPsecXfrmErrors) collectXfrmErrors(ctx context.Context, t *check2.Test) map[string]string {
	ct := t.Context()
	xfrmErrors := map[string]string{}
	cmd := []string{"cilium", "metrics", "list", "-ojson", "-pcilium_ipsec_xfrm_error"}

	for _, pod := range ct.CiliumPods() {
		pod := pod
		encryptStatus, err := pod.K8sClient.ExecInPod(ctx, pod.Pod.Namespace, pod.Pod.Name, defaults.AgentContainerName, cmd)
		if err != nil {
			t.Fatalf("Unable to get cilium ipsec xfrm error metrics: %s", err)
		}

		xErrors := []string{}
		xfrmMetrics := []ciliumMetricsXfrmError{}
		if err := json.Unmarshal(encryptStatus.Bytes(), &xfrmMetrics); err != nil {
			t.Fatalf("Unable to unmarshal cilium ipsec xfrm error metrics: %s", err)
		}
		for _, xfrmMetric := range xfrmMetrics {
			name := fmt.Sprintf("%s_%s", xfrmMetric.Labels.Type, xfrmMetric.Labels.Error)
			if slices.Contains(n.expectedErrors, name) && xfrmMetric.Value < maxExpectedErrors {
				continue
			}
			if xfrmMetric.Value > 0 {
				xErrors = append(xErrors, fmt.Sprintf("%s:%d", name, xfrmMetric.Value))
			}
			sort.Strings(xErrors)
			xfrmErrors[pod.Pod.Status.HostIP] = strings.Join(xErrors, ",")
		}

	}

	return xfrmErrors
}

func (n *noIPsecXfrmErrors) storeIPsecXfrmErrors(t *check2.Test, xfrmErrors map[string]string) {
	ct := t.Context()
	file, err := os.Create(ct.Params().ConnDisruptTestXfrmErrorsPath)
	if err != nil {
		t.Fatalf("Failed to create %q file for writing disrupt test temp results: %s",
			ct.Params().ConnDisruptTestXfrmErrorsPath, err)
	}
	defer file.Close()

	j, err := json.Marshal(xfrmErrors)
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %s", err)
	}

	if _, err := file.Write(j); err != nil {
		t.Fatalf("Failed to write conn disrupt test temp result into file: %s", err)
	}
}

func (n *noIPsecXfrmErrors) loadIPsecXfrmErrors(t *check2.Test) map[string]string {
	b, err := os.ReadFile(t.Context().Params().ConnDisruptTestXfrmErrorsPath)
	if err != nil {
		t.Fatalf("Failed to read conn disrupt test result files: %s", err)
	}
	xfrmErrors := map[string]string{}
	if err := json.Unmarshal(b, &xfrmErrors); err != nil {
		t.Fatalf("Failed to unmarshal JSON test result file: %s", err)
	}
	return xfrmErrors
}
