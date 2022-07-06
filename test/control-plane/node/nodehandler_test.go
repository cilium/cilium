// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"

	"github.com/cilium/cilium/pkg/cidr"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/option"
	controlplane "github.com/cilium/cilium/test/control-plane"
)

var (
	podCIDR = cidr.MustParseCIDR("10.0.1.0/24")

	minimalNode = &corev1.Node{
		TypeMeta:   metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "minimal"},
		Spec: corev1.NodeSpec{
			PodCIDR:  podCIDR.String(),
			PodCIDRs: []string{podCIDR.String()},
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{},
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
				{Type: corev1.NodeHostName, Address: "minimal"},
			},
		},
	}

	initialObjects = []k8sRuntime.Object{
		minimalNode,
	}

	steps = []*controlplane.ControlPlaneTestStep{
		controlplane.
			NewStep("validate node").
			AddValidationFunc(validateNodes),
	}

	testCase = controlplane.ControlPlaneTestCase{
		NodeName:          "minimal",
		InitialObjects:    initialObjects,
		Steps:             steps,
		ValidationTimeout: time.Second,
	}
)

func validateNodes(dp *fakeDatapath.FakeDatapath) error {
	nodes := dp.FakeNode().Nodes

	if len(nodes) != 1 {
		return fmt.Errorf("expected 1 node, found %d (%v)", len(nodes), nodes)
	}

	minimal, ok := nodes["minimal"]
	if !ok {
		return fmt.Errorf("'minimal' node not found from nodes (%v)", nodes)
	}

	if minimal.Name != "minimal" {
		return fmt.Errorf("name mismatch: %q vs %q", "minimal", minimal.Name)
	}

	if !podCIDR.Equal(minimal.IPv4AllocCIDR) {
		return fmt.Errorf("cidr mismatch: %q vs %q", podCIDR, minimal)
	}

	return nil
}

func TestNodeHander(t *testing.T) {
	testCase.Run(t, "1.21", func(*option.DaemonConfig) {})
}
