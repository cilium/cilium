// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodediscovery

import (
	"context"
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	apimodels "github.com/cilium/cilium/api/v1/models"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clienttestutils "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	cnitypes "github.com/cilium/cilium/plugins/cilium-cni/types"
)

// mockK8sGetters implements k8sGetters returning a pre-existing CiliumNode,
// so updateCiliumNodeResource takes the Update path (not Create).
type mockK8sGetters struct {
	ciliumNode *ciliumv2.CiliumNode
}

func (m *mockK8sGetters) GetCiliumNode(_ context.Context, _ string) (*ciliumv2.CiliumNode, error) {
	return m.ciliumNode, nil
}

// mockCNIConfigManager implements cni.CNIConfigManager with no-op methods.
type mockCNIConfigManager struct{}

func (m *mockCNIConfigManager) GetMTU() int                         { return 0 }
func (m *mockCNIConfigManager) GetChainingMode() string             { return "" }
func (m *mockCNIConfigManager) Status() *apimodels.Status           { return nil }
func (m *mockCNIConfigManager) GetCustomNetConf() *cnitypes.NetConf { return nil }
func (m *mockCNIConfigManager) ExternalRoutingEnabled() bool        { return false }

// TestUpdateCiliumNodeResourceTransientErrorCausesFatal reproduces
// https://github.com/cilium/cilium/issues/44388: a transient error from the
// API server during a CiliumNode Update caused logging.Fatal instead of being
// retried.
func TestUpdateCiliumNodeResourceTransientErrorCausesFatal(t *testing.T) {
	logging.RegisterExitHandler(func() { panic("fatal called") })
	t.Cleanup(func() { logging.RegisterExitHandler(func() {}) })

	option.Config.AutoCreateCiliumNodeResource = true
	option.Config.IPAM = ""
	t.Cleanup(func() {
		option.Config.AutoCreateCiliumNodeResource = false
	})

	const nodeName = "test-node"
	nodeTypes.SetName(nodeName)

	fakeClient, _ := clienttestutils.NewFakeClientset(hivetest.Logger(t))

	existingNode := &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName},
	}
	require.NoError(t, fakeClient.CiliumFakeClientset.Tracker().Add(existingNode))

	updateCalls := 0
	// PrependReactor is required: the tracker's ObjectReaction (added at
	// clientset creation via AddReactor) would otherwise intercept Update
	// first and return a Conflict error due to the missing resource version.
	fakeClient.CiliumFakeClientset.PrependReactor("update", "ciliumnodes",
		func(_ k8stesting.Action) (bool, runtime.Object, error) {
			updateCalls++
			return true, nil, fmt.Errorf("connection reset by peer")
		},
	)

	nd := &NodeDiscovery{
		logger:           hivetest.Logger(t),
		clientset:        fakeClient,
		k8sGetters:       &mockK8sGetters{ciliumNode: existingNode},
		cniConfigManager: &mockCNIConfigManager{},
	}

	ln := &node.LocalNode{
		Node:  nodeTypes.Node{Name: nodeName},
		Local: &node.LocalNodeInfo{},
	}

	require.Panics(t, func() {
		nd.updateCiliumNodeResource(context.Background(), ln)
	})

	require.Equal(t, maxRetryCount, updateCalls,
		"transient errors should be retried %d times, not fataled immediately", maxRetryCount)
}
