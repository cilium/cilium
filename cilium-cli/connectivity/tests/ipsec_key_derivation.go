// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/pkg/types"
)

// IPsecKeyDerivationValidation validates that IPsec key derivation produces
// consistent keys across nodes for the same tunnels
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

func (t *ipsecKeyDerivationTest) Run(ctx context.Context, test *check.Test) {
	// Get all Cilium agent pods
	ciliumPods := test.Context().CiliumPods()

	if len(ciliumPods) < 2 {
		test.Logf("Need at least 2 Cilium agents for key derivation validation, found %d", len(ciliumPods))
		return
	}

	// Collect XFRM states from all nodes
	nodeStates := make(map[string][]types.XfrmStateInfo)
	for nodeName, pod := range ciliumPods {
		test.Debugf("Collecting XFRM states from node %s", nodeName)

		// Execute cilium encrypt dump-xfrm command
		cmd := []string{"cilium", "encrypt", "dump-xfrm"}
		stdout, err := pod.K8sClient.ExecInPod(ctx, pod.Pod.Namespace, pod.Pod.Name, defaults.AgentContainerName, cmd)
		if err != nil {
			test.Fatalf("Failed to dump XFRM states from %s: %s", nodeName, err)
			return
		}

		// Debug: log the raw output to help diagnose parsing issues
		rawOutput := stdout.String()
		test.Debugf("Raw XFRM output from %s: %s", nodeName, rawOutput)

		// Parse the JSON output
		var states []types.XfrmStateInfo
		if err := json.Unmarshal(stdout.Bytes(), &states); err != nil {
			test.Fatalf("Failed to parse XFRM states from %s (output: %q): %s", nodeName, rawOutput, err)
			return
		}

		if len(states) == 0 {
			test.Fatalf("No XFRM states found on node %s", nodeName)
			return
		}

		nodeStates[nodeName] = states
		test.Debugf("Found %d XFRM states on node %s", len(states), nodeName)
	}

	// Validate key consistency across nodes
	t.validateKeys(test, nodeStates)

	// Validate bidirectional tunnels
	t.validateBidirectionalTunnels(test, nodeStates)

	test.Logf("IPsec key derivation validation completed successfully")
}

// validateKeys checks that keys are consistent across nodes for matching tunnels
func (t *ipsecKeyDerivationTest) validateKeys(test *check.Test, nodeStates map[string][]types.XfrmStateInfo) {
	// Create an index of states by tunnel identifier (src->dst:spi)
	nodeIndices := make(map[string]map[string]types.XfrmStateInfo)

	for nodeName, states := range nodeStates {
		nodeIndices[nodeName] = make(map[string]types.XfrmStateInfo)
		for _, state := range states {
			key := fmt.Sprintf("%s->%s:%s", state.Src, state.Dst, strconv.FormatUint(uint64(state.SPI), 16))
			nodeIndices[nodeName][key] = state
		}
	}

	// Compare states between nodes
	matchingPairs := false
	for node1, states1 := range nodeIndices {
		for node2, states2 := range nodeIndices {
			if node1 >= node2 { // Avoid duplicate comparisons
				continue
			}

			for tunnelKey, state1 := range states1 {
				if state2, exists := states2[tunnelKey]; exists {
					t.validateKeysWith(test, state1, state2, node1, node2, tunnelKey)
					matchingPairs = true
				}
			}
		}
	}

	if !matchingPairs {
		test.Fatalf("No matching tunnel pairs found between nodes for key validation")
	}
}

// validateKeysWith compares keys between two XFRM states
func (t *ipsecKeyDerivationTest) validateKeysWith(test *check.Test, state1, state2 types.XfrmStateInfo, node1, node2, tunnelKey string) {
	test.Debugf("Validating keys for tunnel %s between nodes %s and %s", tunnelKey, node1, node2)

	// Compare authentication keys
	if state1.AuthKey != state2.AuthKey {
		test.Fatalf("Authentication key mismatch for tunnel %s: %s has %s, %s has %s",
			tunnelKey, node1, state1.AuthKey, node2, state2.AuthKey)
	}

	// Compare encryption keys
	if state1.CryptKey != state2.CryptKey {
		test.Fatalf("Encryption key mismatch for tunnel %s: %s has %s, %s has %s",
			tunnelKey, node1, state1.CryptKey, node2, state2.CryptKey)
	}

	// Compare AEAD keys
	if state1.AeadKey != state2.AeadKey {
		test.Fatalf("AEAD key mismatch for tunnel %s: %s has %s, %s has %s",
			tunnelKey, node1, state1.AeadKey, node2, state2.AeadKey)
	}

	test.Debugf("Keys validated successfully for tunnel %s", tunnelKey)
}

// validateBidirectionalTunnels ensures that for every tunnel direction, the reverse also exists
func (t *ipsecKeyDerivationTest) validateBidirectionalTunnels(test *check.Test, nodeStates map[string][]types.XfrmStateInfo) {
	test.Debugf("Validating bidirectional tunnel establishment")

	for nodeName, states := range nodeStates {
		t.validateNodeBidirectionalTunnels(test, nodeName, states)
	}
}

// validateNodeBidirectionalTunnels validates bidirectional tunnels for a specific node
func (t *ipsecKeyDerivationTest) validateNodeBidirectionalTunnels(test *check.Test, nodeName string, states []types.XfrmStateInfo) {
	// Create a set of tunnels by direction
	tunnels := make(map[string]bool)
	for _, state := range states {
		direction := fmt.Sprintf("%s->%s", state.Src, state.Dst)
		tunnels[direction] = true
	}

	// Check that each tunnel has its reverse
	for _, state := range states {
		// Each Encrypt state has two Decrypt states (to support both
		// CiliumInternalIP and NodeInternalIP at the same time). Thus, we
		// should check that each Encrypt state has a reverse state, as the
		// other way around isn't true.
		if !state.Encrypt {
			continue
		}

		forward := fmt.Sprintf("%s->%s", state.Src, state.Dst)
		reverse := fmt.Sprintf("%s->%s", state.Dst, state.Src)

		if !tunnels[reverse] {
			test.Fatalf("Bidirectional tunnel validation failed on node %s: found %s but missing %s",
				nodeName, forward, reverse)
		}
	}

	test.Debugf("Bidirectional tunnel validation passed for node %s (%d tunnel pairs)",
		nodeName, len(states)/2)
}
