// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"context"
	"errors"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/test/controlplane"
	"github.com/cilium/cilium/test/controlplane/suite"
)

var (
	localNodeObject = &corev1.Node{
		TypeMeta: metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "minimal",
			Labels: map[string]string{
				"foo": "bar",
			},
			Annotations: map[string]string{
				"cilium.io/baz": "quux",
			},
		},
		Spec: corev1.NodeSpec{
			PodCIDR:  podCIDR.String(),
			PodCIDRs: []string{podCIDR.String()},
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{},
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
				{Type: corev1.NodeExternalIP, Address: "20.0.0.2"},
				{Type: corev1.NodeHostName, Address: "minimal"},
			},
		},
	}
)

// errorer implements the interface required by 'assert' to gather
// the assertion errors.
type errorer struct {
	err error
}

func (e *errorer) Errorf(format string, args ...interface{}) {
	e.err = errors.Join(e.err, fmt.Errorf(format, args...))
}

func validateLocalNodeInit(lns *node.LocalNodeStore) error {
	// Validate that after LocalNodeStore has started it has been partially populated.
	// This is called before Daemon is started.

	errs := &errorer{}
	node, err := lns.Get(context.TODO())
	if err != nil {
		return err
	}

	// These things we expect to be populated right after
	// LocalNodeStore has started:
	assert.Equal(errs, localNodeObject.Name, node.Name)
	assert.Equal(errs, "10.0.0.1", node.GetNodeIP(false).String())
	assert.Equal(errs, "20.0.0.2", node.GetExternalIP(false).String())
	assert.Contains(errs, node.Labels, "foo")
	assert.Contains(errs, node.Annotations, "cilium.io/baz")

	if errs.err != nil {
		return fmt.Errorf("validateLocalNodeInit: %w", errs.err)
	}
	return nil
}

func validateLocalNodeAgent(cs client.Clientset, lns *node.LocalNodeStore) error {
	// Validate that the local node information is fully populated after the Daemon
	// has fully started.

	// The initial assertions should still hold.
	if err := validateLocalNodeInit(lns); err != nil {
		return fmt.Errorf("validateLocalNode: %w", err)
	}

	errs := &errorer{}
	node, err := lns.Get(context.TODO())
	if err != nil {
		return err
	}

	// PodCIDR has been populated from the node object.
	assert.Equal(errs, podCIDR.String(), node.IPv4AllocCIDR.String())

	// HealthIP has been allocated.
	assert.NotEmpty(errs, node.IPv4HealthIP)
	// CiliumNode object has been created and populated correctly
	// and reflects the state of the local node.
	ciliumNodes, err := cs.CiliumV2().CiliumNodes().List(context.TODO(), metav1.ListOptions{})
	assert.NoError(errs, err)
	assert.Len(errs, ciliumNodes.Items, 1)

	ciliumNode := ciliumNodes.Items[0]

	if assert.NotEmpty(errs, ciliumNode.OwnerReferences) {
		// CiliumNode should have owner reference to Node
		assert.Equal(errs, localNodeObject.UID, ciliumNode.OwnerReferences[0].UID)
	}

	parsedCiliumNode := nodeTypes.ParseCiliumNode(&ciliumNode)
	assert.Equal(errs, node.IPv4HealthIP, parsedCiliumNode.IPv4HealthIP, "CiliumNode HealthIP")
	assert.Equal(errs, node.IPAddresses, parsedCiliumNode.IPAddresses, "CiliumNode IPAddresses")
	assert.Equal(errs, node.Labels, parsedCiliumNode.Labels, "CiliumNode Labels")
	if errs.err != nil {
		return fmt.Errorf("validateLocalNode: %w", errs.err)
	}
	return nil
}

func init() {
	// LocalNodeStore test validates that the local node store is populated correctly
	// at early stages of the agent initialization. This makes sure that components
	// lifted into modules from Daemon can access initialized state before
	// Daemon is started.
	suite.AddTestCase("LocalNodeStore", func(t *testing.T) {
		k8sVersions := controlplane.K8sVersions()
		// We only need to test the last k8s version
		test := suite.NewControlPlaneTest(t, "minimal", k8sVersions[len(k8sVersions)-1])

		var (
			lns         *node.LocalNodeStore
			cs          client.Clientset
			grabLNSCell = cell.Invoke(
				func(lns_ *node.LocalNodeStore, cs_ client.Clientset) {
					lns = lns_
					cs = cs_
				})

			validateLNSInit = cell.Invoke(
				func(lc hive.Lifecycle, lns *node.LocalNodeStore) {
					lc.Append(hive.Hook{
						OnStart: func(hive.HookContext) error {
							return validateLocalNodeInit(lns)
						},
					})
				})
		)

		test.
			UpdateObjects(localNodeObject).
			SetupEnvironment().
			StartAgent(func(*option.DaemonConfig) {}, grabLNSCell, validateLNSInit).
			Eventually(func() error { return validateLocalNodeAgent(cs, lns) }).
			StopAgent().
			ClearEnvironment()
	})
}
