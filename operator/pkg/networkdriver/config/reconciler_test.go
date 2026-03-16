// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sfake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestIsOperatorManaged(t *testing.T) {
	tests := []struct {
		name     string
		config   *v2alpha1.CiliumNetworkDriverNodeConfig
		expected bool
	}{
		{
			name: "operator managed",
			config: &v2alpha1.CiliumNetworkDriverNodeConfig{
				Status: v2alpha1.CiliumNetworkDriverNodeConfigStatus{
					ManagedBy: ManagedByOperator,
				},
			},
			expected: true,
		},
		{
			name: "user managed",
			config: &v2alpha1.CiliumNetworkDriverNodeConfig{
				Status: v2alpha1.CiliumNetworkDriverNodeConfigStatus{
					ManagedBy: "user",
				},
			},
			expected: false,
		},
		{
			name: "empty managed by",
			config: &v2alpha1.CiliumNetworkDriverNodeConfig{
				Status: v2alpha1.CiliumNetworkDriverNodeConfigStatus{
					ManagedBy: "",
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isOperatorManaged(tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRegisterConfigReconciler_DisabledClientset(t *testing.T) {
	// Test that registration with disabled clientset doesn't panic
	params := ConfigReconcilerParams{}
	registerConfigReconciler(params)
}

func TestConflictError_Error(t *testing.T) {
	err := &ConflictError{
		NodeName:     "node1",
		OldConfig:    "config1",
		NewConfig:    "config2",
		ConflictType: "selector-based-assignment",
	}

	expected := "conflict for node node1: already assigned by config1 (attempting: config2, type: selector-based-assignment)"
	assert.Equal(t, expected, err.Error())
}

// TestCleanupOrphanedNodeConfigs_DeletedNode tests that NodeConfigs are cleaned up
// when their corresponding CiliumNode is deleted
func TestCleanupOrphanedNodeConfigs_DeletedNode(t *testing.T) {
	ctx := context.Background()

	// Create fake clientset
	fakeClient := k8sfake.NewSimpleClientset()

	// Create test data
	clusterConfig := &v2alpha1.CiliumNetworkDriverClusterConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "config1",
		},
		Spec: v2alpha1.CiliumNetworkDriverClusterConfigSpec{
			NodeSelector: &slim_meta_v1.LabelSelector{
				MatchLabels: map[string]string{
					"role": "worker",
				},
			},
			Spec: v2alpha1.CiliumNetworkDriverNodeConfigSpec{
				DriverName: "test-driver",
			},
		},
	}

	nodeConfig := &v2alpha1.CiliumNetworkDriverNodeConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "node1",
		},
		Spec: v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			DriverName: "test-driver",
		},
		Status: v2alpha1.CiliumNetworkDriverNodeConfigStatus{
			ManagedBy: ManagedByOperator,
		},
	}

	// Create reconciler
	r := &ConfigReconciler{
		logger:           slog.Default(),
		nodeConfigClient: fakeClient.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs(),
		clusterConfigs: map[resource.Key]*v2alpha1.CiliumNetworkDriverClusterConfig{
			{Name: "config1"}: clusterConfig,
		},
		nodeConfigs: map[resource.Key]*v2alpha1.CiliumNetworkDriverNodeConfig{
			{Name: "node1"}: nodeConfig,
		},
		ciliumNodes: map[resource.Key]*v2.CiliumNode{
			// node1 is NOT in the map (deleted)
		},
	}

	// Create the NodeConfig in the fake client
	_, err := fakeClient.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs().Create(
		ctx, nodeConfig, meta_v1.CreateOptions{})
	require.NoError(t, err)

	// Run cleanup
	err = r.cleanupOrphanedNodeConfigs(ctx)
	require.NoError(t, err)

	// Verify NodeConfig was deleted
	_, err = fakeClient.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs().Get(
		ctx, "node1", meta_v1.GetOptions{})
	assert.Error(t, err)
	assert.True(t, k8serrors.IsNotFound(err))
}

// TestCleanupOrphanedNodeConfigs_NoMatchingClusterConfig tests that NodeConfigs
// are cleaned up when no ClusterConfig selects the node anymore
func TestCleanupOrphanedNodeConfigs_NoMatchingClusterConfig(t *testing.T) {
	ctx := context.Background()

	// Create fake clientset
	fakeClient := k8sfake.NewSimpleClientset()

	// Create test data
	node1 := &v2.CiliumNode{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "node1",
			Labels: map[string]string{
				"role": "worker",
			},
		},
	}

	clusterConfig := &v2alpha1.CiliumNetworkDriverClusterConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "config1",
		},
		Spec: v2alpha1.CiliumNetworkDriverClusterConfigSpec{
			NodeSelector: &slim_meta_v1.LabelSelector{
				MatchLabels: map[string]string{
					"role": "control-plane", // Doesn't match node1
				},
			},
			Spec: v2alpha1.CiliumNetworkDriverNodeConfigSpec{
				DriverName: "test-driver",
			},
		},
	}

	nodeConfig := &v2alpha1.CiliumNetworkDriverNodeConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "node1",
		},
		Spec: v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			DriverName: "test-driver",
		},
		Status: v2alpha1.CiliumNetworkDriverNodeConfigStatus{
			ManagedBy: ManagedByOperator,
		},
	}

	// Create reconciler
	r := &ConfigReconciler{
		logger:           slog.Default(),
		nodeConfigClient: fakeClient.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs(),
		clusterConfigs: map[resource.Key]*v2alpha1.CiliumNetworkDriverClusterConfig{
			{Name: "config1"}: clusterConfig,
		},
		nodeConfigs: map[resource.Key]*v2alpha1.CiliumNetworkDriverNodeConfig{
			{Name: "node1"}: nodeConfig,
		},
		ciliumNodes: map[resource.Key]*v2.CiliumNode{
			{Name: "node1"}: node1,
		},
	}

	// Create the NodeConfig in the fake client
	_, err := fakeClient.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs().Create(
		ctx, nodeConfig, meta_v1.CreateOptions{})
	require.NoError(t, err)

	// Run cleanup
	err = r.cleanupOrphanedNodeConfigs(ctx)
	require.NoError(t, err)

	// Verify NodeConfig was deleted
	_, err = fakeClient.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs().Get(
		ctx, "node1", meta_v1.GetOptions{})
	assert.Error(t, err)
	assert.True(t, k8serrors.IsNotFound(err))
}

// TestCleanupOrphanedNodeConfigs_UserManaged tests that user-managed NodeConfigs
// are NOT deleted even if the node is deleted
func TestCleanupOrphanedNodeConfigs_UserManaged(t *testing.T) {
	ctx := context.Background()

	// Create fake clientset
	fakeClient := k8sfake.NewSimpleClientset()

	nodeConfig := &v2alpha1.CiliumNetworkDriverNodeConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "node1",
		},
		Spec: v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			DriverName: "test-driver",
		},
		Status: v2alpha1.CiliumNetworkDriverNodeConfigStatus{
			ManagedBy: "user", // User-managed
		},
	}

	// Create reconciler
	r := &ConfigReconciler{
		logger:           slog.Default(),
		nodeConfigClient: fakeClient.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs(),
		clusterConfigs:   map[resource.Key]*v2alpha1.CiliumNetworkDriverClusterConfig{},
		nodeConfigs: map[resource.Key]*v2alpha1.CiliumNetworkDriverNodeConfig{
			{Name: "node1"}: nodeConfig,
		},
		ciliumNodes: map[resource.Key]*v2.CiliumNode{
			// node1 is NOT in the map (deleted)
		},
	}

	// Create the NodeConfig in the fake client
	_, err := fakeClient.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs().Create(
		ctx, nodeConfig, meta_v1.CreateOptions{})
	require.NoError(t, err)

	// Run cleanup
	err = r.cleanupOrphanedNodeConfigs(ctx)
	require.NoError(t, err)

	// Verify NodeConfig was NOT deleted (user-managed)
	nc, err := fakeClient.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs().Get(
		ctx, "node1", meta_v1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, "node1", nc.Name)
}

// TestDeleteOrphanedNodeConfigsForClusterConfig tests that NodeConfigs are deleted
// when they no longer match a ClusterConfig's selector
func TestDeleteOrphanedNodeConfigsForClusterConfig(t *testing.T) {
	ctx := context.Background()

	// Create fake clientset
	fakeClient := k8sfake.NewSimpleClientset()

	// Create test data
	node1 := &v2.CiliumNode{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "node1",
			Labels: map[string]string{
				"role": "worker",
			},
		},
	}

	node2 := &v2.CiliumNode{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "node2",
			Labels: map[string]string{
				"role": "control-plane",
			},
		},
	}

	clusterConfig := &v2alpha1.CiliumNetworkDriverClusterConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "config1",
		},
		Spec: v2alpha1.CiliumNetworkDriverClusterConfigSpec{
			NodeSelector: &slim_meta_v1.LabelSelector{
				MatchLabels: map[string]string{
					"role": "worker", // Only matches node1
				},
			},
			Spec: v2alpha1.CiliumNetworkDriverNodeConfigSpec{
				DriverName: "test-driver",
			},
		},
	}

	nodeConfig1 := &v2alpha1.CiliumNetworkDriverNodeConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "node1",
		},
		Spec: v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			DriverName: "test-driver",
		},
		Status: v2alpha1.CiliumNetworkDriverNodeConfigStatus{
			ManagedBy: ManagedByOperator,
		},
	}

	nodeConfig2 := &v2alpha1.CiliumNetworkDriverNodeConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "node2",
		},
		Spec: v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			DriverName: "test-driver",
		},
		Status: v2alpha1.CiliumNetworkDriverNodeConfigStatus{
			ManagedBy: ManagedByOperator,
		},
	}

	// Create reconciler
	r := &ConfigReconciler{
		logger:           slog.Default(),
		nodeConfigClient: fakeClient.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs(),
		clusterConfigs: map[resource.Key]*v2alpha1.CiliumNetworkDriverClusterConfig{
			{Name: "config1"}: clusterConfig,
		},
		nodeConfigs: map[resource.Key]*v2alpha1.CiliumNetworkDriverNodeConfig{
			{Name: "node1"}: nodeConfig1,
			{Name: "node2"}: nodeConfig2,
		},
		ciliumNodes: map[resource.Key]*v2.CiliumNode{
			{Name: "node1"}: node1,
			{Name: "node2"}: node2,
		},
	}

	// Create the NodeConfigs in the fake client
	_, err := fakeClient.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs().Create(
		ctx, nodeConfig1, meta_v1.CreateOptions{})
	require.NoError(t, err)
	_, err = fakeClient.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs().Create(
		ctx, nodeConfig2, meta_v1.CreateOptions{})
	require.NoError(t, err)

	// matchingNodes only includes node1
	matchingNodes := sets.New[string]("node1")

	// Run delete orphaned for this config
	err = r.deleteOrphanedNodeConfigsForClusterConfig(ctx, matchingNodes, clusterConfig)
	require.NoError(t, err)

	// Verify node1's NodeConfig still exists
	nc1, err := fakeClient.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs().Get(
		ctx, "node1", meta_v1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, "node1", nc1.Name)

	// Verify node2's NodeConfig was deleted
	_, err = fakeClient.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs().Get(
		ctx, "node2", meta_v1.GetOptions{})
	assert.Error(t, err)
	assert.True(t, k8serrors.IsNotFound(err))
}

// TestDeleteOrphanedNodeConfigsForClusterConfig_StillSelectedByOther tests that
// NodeConfigs are NOT deleted if another ClusterConfig still selects them
func TestDeleteOrphanedNodeConfigsForClusterConfig_StillSelectedByOther(t *testing.T) {
	ctx := context.Background()

	// Create fake clientset
	fakeClient := k8sfake.NewSimpleClientset()

	// Create test data
	node1 := &v2.CiliumNode{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "node1",
			Labels: map[string]string{
				"role": "worker",
			},
		},
	}

	clusterConfig1 := &v2alpha1.CiliumNetworkDriverClusterConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "config1",
		},
		Spec: v2alpha1.CiliumNetworkDriverClusterConfigSpec{
			NodeSelector: &slim_meta_v1.LabelSelector{
				MatchLabels: map[string]string{
					"role": "control-plane", // Doesn't match node1
				},
			},
			Spec: v2alpha1.CiliumNetworkDriverNodeConfigSpec{
				DriverName: "driver1",
			},
		},
	}

	clusterConfig2 := &v2alpha1.CiliumNetworkDriverClusterConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "config2",
		},
		Spec: v2alpha1.CiliumNetworkDriverClusterConfigSpec{
			NodeSelector: &slim_meta_v1.LabelSelector{
				MatchLabels: map[string]string{
					"role": "worker", // Matches node1
				},
			},
			Spec: v2alpha1.CiliumNetworkDriverNodeConfigSpec{
				DriverName: "driver2",
			},
		},
	}

	nodeConfig1 := &v2alpha1.CiliumNetworkDriverNodeConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "node1",
		},
		Spec: v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			DriverName: "driver1",
		},
		Status: v2alpha1.CiliumNetworkDriverNodeConfigStatus{
			ManagedBy: ManagedByOperator,
		},
	}

	// Create reconciler
	r := &ConfigReconciler{
		logger:           slog.Default(),
		nodeConfigClient: fakeClient.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs(),
		clusterConfigs: map[resource.Key]*v2alpha1.CiliumNetworkDriverClusterConfig{
			{Name: "config1"}: clusterConfig1,
			{Name: "config2"}: clusterConfig2,
		},
		nodeConfigs: map[resource.Key]*v2alpha1.CiliumNetworkDriverNodeConfig{
			{Name: "node1"}: nodeConfig1,
		},
		ciliumNodes: map[resource.Key]*v2.CiliumNode{
			{Name: "node1"}: node1,
		},
	}

	// Create the NodeConfig in the fake client
	_, err := fakeClient.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs().Create(
		ctx, nodeConfig1, meta_v1.CreateOptions{})
	require.NoError(t, err)

	// config1 doesn't match node1
	matchingNodes := sets.New[string]()

	// Run delete orphaned for config1
	err = r.deleteOrphanedNodeConfigsForClusterConfig(ctx, matchingNodes, clusterConfig1)
	require.NoError(t, err)

	// Verify node1's NodeConfig still exists (because config2 still selects it)
	nc1, err := fakeClient.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs().Get(
		ctx, "node1", meta_v1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, "node1", nc1.Name)
}
