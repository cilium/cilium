// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"errors"
	"fmt"
	"path"
	"reflect"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cilium/cilium/pkg/datapath/fake"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	controlplane "github.com/cilium/cilium/test/control-plane"
)

type goldenCiliumNodesValidator struct {
	step           int
	expectedLabels map[string]string
}

func NewGoldenCiliumNodesValidator(stateFile string, update bool) controlplane.Validator {
	var step int
	fmt.Sscanf(path.Base(stateFile), "state%d.yaml", &step)

	switch step {
	case 1:
		// step 1: added label "test-label" -> "test-value"
		return &goldenCiliumNodesValidator{
			step: step,
			expectedLabels: map[string]string{
				"beta.kubernetes.io/arch": "amd64",
				"beta.kubernetes.io/os":   "linux",
				"cilium.io/ci-node":       "k8s1",
				"kubernetes.io/arch":      "amd64",
				"kubernetes.io/hostname":  "cilium-nodes-worker",
				"kubernetes.io/os":        "linux",

				"test-label": "test-value",
			},
		}
	case 2:
		// step 2: removed label "test-label"
		return &goldenCiliumNodesValidator{
			step: step,
			expectedLabels: map[string]string{
				"beta.kubernetes.io/arch": "amd64",
				"beta.kubernetes.io/os":   "linux",
				"cilium.io/ci-node":       "k8s1",
				"kubernetes.io/arch":      "amd64",
				"kubernetes.io/hostname":  "cilium-nodes-worker",
				"kubernetes.io/os":        "linux",
			},
		}
	}

	return nil
}

func getTestNodeLabels(proxy *controlplane.K8sObjsProxy, name string) (map[string]string, error) {
	nodeObj, err := proxy.Get(
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

func getTestCiliumNodeLabels(proxy *controlplane.K8sObjsProxy, name string) (map[string]string, error) {
	ciliumNodeObj, err := proxy.Get(
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

func (v *goldenCiliumNodesValidator) Validate(datapath *fake.FakeDatapath, proxy *controlplane.K8sObjsProxy) error {
	nodeLabels, err := getTestNodeLabels(proxy, "cilium-nodes-worker")
	if err != nil {
		return fmt.Errorf("validation failed in step %d: %w", v.step, err)
	}
	if !reflect.DeepEqual(v.expectedLabels, nodeLabels) {
		return fmt.Errorf("nodes labels validation failed in step %d, expected: %v, found: %v",
			v.step, nodeLabels, v.expectedLabels)
	}

	ciliumNodeLabels, err := getTestCiliumNodeLabels(proxy, "cilium-nodes-worker")
	if err != nil {
		return fmt.Errorf("validation failed in step %d: %w", v.step, err)
	}
	if !reflect.DeepEqual(v.expectedLabels, ciliumNodeLabels) {
		return fmt.Errorf("cilium nodes labels validation failed in step %d, expected: %v, found: %v",
			v.step, ciliumNodeLabels, v.expectedLabels)
	}

	return nil
}
