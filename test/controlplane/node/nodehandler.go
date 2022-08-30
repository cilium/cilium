// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/cidr"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	agentOption "github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/test/controlplane"
	"github.com/cilium/cilium/test/controlplane/suite"
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

func init() {
	suite.AddTestCase("NodeHandler", func(t *testing.T) {
		k8sVersions := controlplane.K8sVersions()
		// We only need to test the last k8s version
		test := suite.NewControlPlaneTest(t, "minimal", k8sVersions[len(k8sVersions)-1])

		test.
			UpdateObjects(minimalNode).
			SetupEnvironment(func(*agentOption.DaemonConfig, *operatorOption.OperatorConfig) {}).
			StartAgent().
			Eventually(func() error { return validateNodes(test.Datapath) }).
			StopAgent()
	})
}
