// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumnode

import (
	"errors"
	"fmt"
	"os"
	"path"
	"reflect"
	"testing"

	v1 "k8s.io/api/core/v1" // nolint: golint
	"k8s.io/apimachinery/pkg/runtime/schema"

	operatorOption "github.com/cilium/cilium/operator/option"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2" // nolint: golint
	agentOption "github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/test/controlplane"
	"github.com/cilium/cilium/test/controlplane/suite"
)

type step struct {
	filename       string
	expectedLabels map[string]string
}

var steps = []step{
	{
		"state1.yaml",
		map[string]string{
			"cilium.io/ci-node":      "k8s1",
			"kubernetes.io/arch":     "amd64",
			"kubernetes.io/hostname": "cilium-nodes-worker",
			"kubernetes.io/os":       "linux",
			"test-label":             "test-value",
		},
	},

	{
		"state2.yaml",
		map[string]string{
			"cilium.io/ci-node":      "k8s1",
			"kubernetes.io/arch":     "amd64",
			"kubernetes.io/hostname": "cilium-nodes-worker",
			"kubernetes.io/os":       "linux",
		},
	},

	{
		"state3.yaml",
		map[string]string{
			"cilium.io/ci-node":      "k8s1",
			"kubernetes.io/arch":     "amd64",
			"kubernetes.io/hostname": "cilium-nodes-worker",
			"kubernetes.io/os":       "linux",
			"another-test-label":     "another-test-value",
		},
	},

	{
		"state4.yaml",
		map[string]string{
			"cilium.io/ci-node":      "k8s1",
			"kubernetes.io/arch":     "amd64",
			"kubernetes.io/hostname": "cilium-nodes-worker",
			"kubernetes.io/os":       "linux",
			"another-test-label":     "changed-test-value",
		},
	},
}

func init() {
	suite.AddTestCase("CiliumNodes", func(t *testing.T) {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}

		modConfig := func(daemonCfg *agentOption.DaemonConfig, _ *operatorOption.OperatorConfig) {
			daemonCfg.EnableNodePort = true
		}
		for _, version := range controlplane.K8sVersions() {
			abs := func(f string) string { return path.Join(cwd, "node", "ciliumnodes", "v"+version, f) }

			t.Run("v"+version, func(t *testing.T) {
				test := suite.NewControlPlaneTest(t, "cilium-nodes-worker", version)

				// Feed in initial state and start the agent.
				test.
					UpdateObjectsFromFile(abs("init.yaml")).
					SetupEnvironment(modConfig).
					StartAgent()

				// Run through the test steps
				for _, step := range steps {
					test.UpdateObjectsFromFile(abs(step.filename))
					test.Eventually(func() error { return validateLabels(test, step.expectedLabels) })
				}

				test.StopAgent()
			})
		}
	})
}

func validateLabels(test *suite.ControlPlaneTest, expectedLabels map[string]string) error {
	nodeLabels, err := getTestNodeLabels(test, "cilium-nodes-worker")
	if err != nil {
		return fmt.Errorf("failed to get Node labels: %w", err)
	}
	if !reflect.DeepEqual(expectedLabels, nodeLabels) {
		return fmt.Errorf("Node labels mismatch, expected: %v, found: %v",
			nodeLabels, expectedLabels)
	}
	ciliumNodeLabels, err := getTestCiliumNodeLabels(test, "cilium-nodes-worker")
	if err != nil {
		return fmt.Errorf("failed to get CiliumNode labels: %w", err)
	}
	if !reflect.DeepEqual(expectedLabels, ciliumNodeLabels) {
		return fmt.Errorf("CiliumNode labels mismatch, expected: %v, found: %v",
			ciliumNodeLabels, expectedLabels)
	}
	return nil
}

func getTestNodeLabels(test *suite.ControlPlaneTest, name string) (map[string]string, error) {
	nodeObj, err := test.Get(
		schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"},
		"",
		name,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to get %q Node: %w", name, err)
	}
	node, ok := nodeObj.(*v1.Node)
	if !ok {
		return nil, errors.New("type assertion failed for Node obj")
	}

	return node.GetLabels(), nil
}

func getTestCiliumNodeLabels(test *suite.ControlPlaneTest, name string) (map[string]string, error) {
	ciliumNodeObj, err := test.Get(
		schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnodes"},
		"",
		name,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to get %q CiliumNode: %w", name, err)
	}
	ciliumNode, ok := ciliumNodeObj.(*v2.CiliumNode)
	if !ok {
		return nil, errors.New("type assertion failed for CiliumNode obj")
	}

	return ciliumNode.GetLabels(), nil
}
