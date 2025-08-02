// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/types"
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

func NoIPsecXfrmErrors(expectedErrors []string) check.Scenario {
	return &noIPsecXfrmErrors{
		expectedErrors: features.ComputeFailureExceptions(defaults.ExpectedXFRMErrors, expectedErrors),
		ScenarioBase:   check.NewScenarioBase(),
	}
}

type noIPsecXfrmErrors struct {
	check.ScenarioBase

	expectedErrors []string
}

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
	ct := t.Context()
	xfrmErrors := map[string]string{}
	cmd := []string{"cilium", "metrics", "list", "-ojson", "-pcilium_ipsec_xfrm_error"}

	for _, pod := range ct.CiliumPods() {
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
			slices.Sort(xErrors)
			xfrmErrors[pod.Pod.Status.HostIP] = strings.Join(xErrors, ",")
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

	j, err := json.Marshal(xfrmErrors)
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
	if err := json.Unmarshal(b, &xfrmErrors); err != nil {
		t.Fatalf("Failed to unmarshal JSON test result file: %s", err)
	}
	return xfrmErrors
}

// validateKeysWith validates that two XFRM states have matching keys
// representing the same tunnel. Returns an error if keys don't match.
func validateKeysWith(state1, state2 types.XfrmStateInfo) error {
	if state1.AuthKey != "" && state2.AuthKey != "" && state1.AuthKey != state2.AuthKey {
		return fmt.Errorf("authentication keys mismatch: %s vs %s", state1.AuthKey, state2.AuthKey)
	}
	if state1.CryptKey != "" && state2.CryptKey != "" && state1.CryptKey != state2.CryptKey {
		return fmt.Errorf("encryption keys mismatch: %s vs %s", state1.CryptKey, state2.CryptKey)
	}
	if state1.AeadKey != "" && state2.AeadKey != "" && state1.AeadKey != state2.AeadKey {
		return fmt.Errorf("AEAD keys mismatch: %s vs %s", state1.AeadKey, state2.AeadKey)
	}
	return nil
}

// IPsecKeyDerivationValidation creates a test scenario that validates
// IPsec key derivation by ensuring derived keys are the same on two nodes
// for a given tunnel
func IPsecKeyDerivationValidation() check.Scenario {
	return &ipsecKeyDerivationTest{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type ipsecKeyDerivationTest struct {
	check.ScenarioBase
}

func (t *ipsecKeyDerivationTest) Name() string {
	return "ipsec-key-derivation-validation"
}

func (t *ipsecKeyDerivationTest) Run(ctx context.Context, testContext *check.Test) {
	ct := testContext.Context()

	ciliumPods := ct.CiliumPods()
	if len(ciliumPods) < 2 {
		testContext.Fatalf("Not enough cilium pods for multi-node key derivation test (have %d, need 2)", len(ciliumPods))
		return
	}

	testContext.Log("Starting IPsec key derivation validation test")

	// Get XFRM states from all nodes
	nodeStates := make(map[string][]types.XfrmStateInfo)
	for _, pod := range ciliumPods {
		hostIP := pod.Pod.Status.HostIP
		states, err := t.getXfrmStates(ctx, testContext, pod)
		if err != nil {
			testContext.Fatalf("Failed to get XFRM states from node %s: %v", hostIP, err)
		}
		nodeStates[hostIP] = states
		testContext.Debugf("Found %d XFRM states on node %s", len(states), hostIP)
	}

	// Validate key derivation across nodes
	t.validateKeyDerivation(testContext, nodeStates)
}

// getXfrmStates extracts XFRM state information from a cilium pod using netlink
func (t *ipsecKeyDerivationTest) getXfrmStates(ctx context.Context, testContext *check.Test, pod check.Pod) ([]types.XfrmStateInfo, error) {
	cmd := []string{"cilium-dbg", "encrypt", "dump-xfrm", "--output", "json"}

	result, err := pod.K8sClient.ExecInPod(ctx, pod.Pod.Namespace, pod.Pod.Name, defaults.AgentContainerName, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to execute cilium-dbg encrypt dump-xfrm: %w", err)
	}

	var states []types.XfrmStateInfo
	if err := json.Unmarshal(result.Bytes(), &states); err != nil {
		return nil, fmt.Errorf("failed to unmarshal XFRM states JSON: %w", err)
	}

	return states, nil
}

// validateKeyDerivation validates that keys are correctly derived and consistent across nodes
func (t *ipsecKeyDerivationTest) validateKeyDerivation(testContext *check.Test, nodeStates map[string][]types.XfrmStateInfo) {
	nodeIPs := make([]string, 0, len(nodeStates))
	for nodeIP := range nodeStates {
		nodeIPs = append(nodeIPs, nodeIP)
	}

	validationCount := 0

	// Compare states between every pair of nodes
	for i := 0; i < len(nodeIPs); i++ {
		for j := i + 1; j < len(nodeIPs); j++ {
			node1IP := nodeIPs[i]
			node2IP := nodeIPs[j]

			node1States := nodeStates[node1IP]
			node2States := nodeStates[node2IP]

			testContext.Debugf("Validating key derivation between nodes %s and %s", node1IP, node2IP)

			// Index node2 states by src->dst:spi for efficient lookup
			node2Index := make(map[string]types.XfrmStateInfo)
			for _, state := range node2States {
				key := state.Src + "->" + state.Dst + ":" + strconv.FormatUint(uint64(state.SPI), 10)
				node2Index[key] = state
			}

			// Find and validate matching tunnel states
			matchingPairs := false
			for _, state1 := range node1States {
				key := state1.Src + "->" + state1.Dst + ":" + strconv.FormatUint(uint64(state1.SPI), 10)
				if state2, exists := node2Index[key]; exists {
					t.validateTunnelKeyPair(testContext, state1, state2, node1IP, node2IP)
					matchingPairs = true
					validationCount++
				}
			}

			if !matchingPairs {
				testContext.Fatalf("No matching tunnels found between nodes %s and %s", node1IP, node2IP)
			}
		}
	}

	if validationCount == 0 {
		testContext.Fatalf("No tunnel key pairs found for validation")
	}

	testContext.Logf("Successfully validated %d tunnel key pairs", validationCount)
}

// validateTunnelKeyPair validates that two XFRM states have matching keys
func (t *ipsecKeyDerivationTest) validateTunnelKeyPair(testContext *check.Test, state1, state2 types.XfrmStateInfo, node1IP, node2IP string) {
	if err := validateKeysWith(state1, state2); err != nil {
		testContext.Fatalf("Key validation failed for tunnel %s->%s between nodes %s and %s: %v",
			state1.Src, state1.Dst, node1IP, node2IP, err)
	}
}
