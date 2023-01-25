// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of Cilium

package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"k8s.io/client-go/util/jsonpath"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/defaults"
)

func CiliumHealth() check.Scenario {
	return &ciliumHealth{}
}

type ciliumHealth struct{}

func (s *ciliumHealth) Name() string {
	return "cilium-health"
}

func (s *ciliumHealth) Run(ctx context.Context, t *check.Test) {
	for name, pod := range t.Context().CiliumPods() {
		pod := pod
		t.NewAction(s, name, &pod, nil).Run(func(a *check.Action) {
			runHealthProbe(ctx, t.Context(), &pod)
		})
	}
}

func runHealthProbe(ctx context.Context, t *check.ConnectivityTest, pod *check.Pod) {
	cmd := []string{"cilium-health", "status", "--probe", "-o=json"}
	done := ctx.Done()

	// Probe health status until it passes checks or timeout is reached.
	for {
		retryTimer := time.After(time.Second)

		stdout, err := pod.K8sClient.ExecInPod(ctx, pod.Pod.Namespace, pod.Pod.Name, defaults.AgentContainerName, cmd)
		if err != nil {
			t.Warnf("cilium-health probe failed: %q, stdout: %q, retrying...", err, stdout)
			continue
		}

		err = validateHealthStatus(t, pod, stdout)
		if err == nil {
			return
		}
		t.Warnf("cilium-health validation failed: %q, retrying...", err)

		// Wait until it's time to retry or context is cancelled.
		select {
		case <-done:
			t.Fatalf("cilium-health probe on '%s' failed: %s", pod.Name(), err)
			return
		case <-retryTimer:
		}
	}
}

func validateHealthStatus(t *check.ConnectivityTest, pod *check.Pod, out bytes.Buffer) error {
	var (
		nodesFilter = `{.nodes[*].name}`
		statusPaths = []string{
			".host.primary-address.icmp.status",
			".host.primary-address.http.status",
			".host.secondary-addresses[*].icmp.status",
			".host.secondary-addresses[*].http.status",
			".endpoint.primary-address.icmp.status",
			".endpoint.primary-address.http.status",
			".endpoint.secondary-addresses[*].icmp.status",
			".endpoint.secondary-addresses[*].http.status",
			".health-endpoint.primary-address.icmp.status",
			".health-endpoint.primary-address.http.status",
			".health-endpoint.secondary-addresses[*].icmp.status",
			".health-endpoint.secondary-addresses[*].http.status",
		}
	)

	var data interface{}
	err := json.Unmarshal(out.Bytes(), &data)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal cilium-health output: %s", err)
	}

	// Check that status of all nodes is reported
	nodes, err := filterJSON(data, nodesFilter)
	if err != nil {
		return fmt.Errorf("Failed to filter nodes: %s", err)
	}
	nodeCount := strings.Split(nodes, " ")
	if len(nodeCount) < len(t.CiliumPods()) {
		return fmt.Errorf(
			"cilium-agent '%s': only %d/%d nodes appeared in cilium-health status. nodes = '%+v'",
			pod.Name(), len(nodeCount), len(t.CiliumPods()), nodeCount)
	}

	// Check that all status checks are OK.
	for _, statusPath := range statusPaths {
		kvExpr := fmt.Sprintf(`{range .nodes[*]}{.name}{"%s="}{%s}{"\n"}{end}`, statusPath, statusPath)
		healthStatus, err := filterJSON(data, kvExpr)
		if err != nil {
			return fmt.Errorf("cilium-agent '%s': failed to filter node health status: %s", pod.Name(), err)
		}

		for path, status := range parseKVPairs(healthStatus) {
			if status != "" {
				return fmt.Errorf("cilium-agent '%s': connectivity to path '%s' is unhealthy: '%s'",
					pod.Name(), path, status)
			}
		}
	}
	return nil
}

func filterJSON(data any, filter string) (string, error) {
	parser := jsonpath.New("").AllowMissingKeys(true)
	parser.Parse(filter)
	result := new(bytes.Buffer)
	err := parser.Execute(result, data)
	return result.String(), err
}

func parseKVPairs(s string) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for _, line := range lines {
		vals := strings.Split(line, "=")
		if len(vals) == 2 {
			result[vals[0]] = vals[1]
		}
	}
	return result
}
