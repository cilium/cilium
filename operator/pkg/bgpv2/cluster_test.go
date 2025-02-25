// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"context"
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/utils/ptr"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/time"
)

var (
	cluster1 = v2.CiliumBGPInstance{
		Name:      "cluster-1-instance-65001",
		LocalASN:  ptr.To[int64](65001),
		LocalPort: ptr.To[int32](1179),
		Peers: []v2.CiliumBGPPeer{
			{
				Name:        "cluster-1-instance-65002-peer-10.0.0.2",
				PeerAddress: ptr.To[string]("10.0.0.2"),
				PeerASN:     ptr.To[int64](65002),
				PeerConfigRef: &v2.PeerConfigReference{
					Name: "peer-1",
				},
			},
		},
	}

	expectedNode1 = v2.CiliumBGPNodeInstance{
		Name:      "cluster-1-instance-65001",
		LocalASN:  ptr.To[int64](65001),
		LocalPort: ptr.To[int32](1179),
		Peers: []v2.CiliumBGPNodePeer{
			{
				Name:        "cluster-1-instance-65002-peer-10.0.0.2",
				PeerAddress: ptr.To[string]("10.0.0.2"),
				PeerASN:     ptr.To[int64](65002),
				PeerConfigRef: &v2.PeerConfigReference{
					Name: "peer-1",
				},
			},
		},
	}

	nodeOverride1 = v2.CiliumBGPNodeConfigOverrideSpec{
		BGPInstances: []v2.CiliumBGPNodeConfigInstanceOverride{
			{
				Name:      "cluster-1-instance-65001",
				RouterID:  ptr.To[string]("10.10.10.10"),
				LocalPort: ptr.To[int32](5400),
				LocalASN:  ptr.To[int64](65010),
				Peers: []v2.CiliumBGPNodeConfigPeerOverride{
					{
						Name:         "cluster-1-instance-65002-peer-10.0.0.2",
						LocalAddress: ptr.To[string]("10.10.10.1"),
					},
				},
			},
		},
	}

	expectedNodeWithOverride1 = v2.CiliumBGPNodeInstance{
		Name:      "cluster-1-instance-65001",
		LocalASN:  ptr.To[int64](65010),
		RouterID:  ptr.To[string]("10.10.10.10"),
		LocalPort: ptr.To[int32](5400),
		Peers: []v2.CiliumBGPNodePeer{
			{
				Name:         "cluster-1-instance-65002-peer-10.0.0.2",
				PeerAddress:  ptr.To[string]("10.0.0.2"),
				PeerASN:      ptr.To[int64](65002),
				LocalAddress: ptr.To[string]("10.10.10.1"),
				PeerConfigRef: &v2.PeerConfigReference{
					Name: "peer-1",
				},
			},
		},
	}

	nodeOverride2 = v2.CiliumBGPNodeConfigOverrideSpec{
		BGPInstances: []v2.CiliumBGPNodeConfigInstanceOverride{
			{
				Name:      "cluster-1-instance-65001",
				RouterID:  ptr.To[string]("10.10.10.10"),
				LocalPort: nil,
				LocalASN:  ptr.To[int64](65010),
				Peers: []v2.CiliumBGPNodeConfigPeerOverride{
					{
						Name:         "cluster-1-instance-65002-peer-10.0.0.2",
						LocalAddress: ptr.To[string]("10.10.10.1"),
					},
				},
			},
		},
	}

	expectedNodeWithOverride2 = v2.CiliumBGPNodeInstance{
		Name:      "cluster-1-instance-65001",
		LocalASN:  ptr.To[int64](65010),
		RouterID:  ptr.To[string]("10.10.10.10"),
		LocalPort: ptr.To[int32](1179),
		Peers: []v2.CiliumBGPNodePeer{
			{
				Name:         "cluster-1-instance-65002-peer-10.0.0.2",
				PeerAddress:  ptr.To[string]("10.0.0.2"),
				PeerASN:      ptr.To[int64](65002),
				LocalAddress: ptr.To[string]("10.10.10.1"),
				PeerConfigRef: &v2.PeerConfigReference{
					Name: "peer-1",
				},
			},
		},
	}
)

func Test_NodeLabels(t *testing.T) {
	tests := []struct {
		description        string
		node               *v2.CiliumNode
		clusterConfig      *v2.CiliumBGPClusterConfig
		expectedNodeConfig *v2.CiliumBGPNodeConfig
	}{
		{
			description: "node without any labels",
			node: &v2.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "node-1",
				},
			},
			clusterConfig: &v2.CiliumBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "bgp-cluster-config",
				},
				Spec: v2.CiliumBGPClusterConfigSpec{
					NodeSelector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp": "rack1",
						},
					},
					BGPInstances: []v2.CiliumBGPInstance{
						cluster1,
					},
				},
			},
			expectedNodeConfig: nil,
		},
		{
			description: "node with label and cluster config with MatchLabels",
			node: &v2.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "node-1",
					Labels: map[string]string{
						"bgp": "rack1",
					},
				},
			},
			clusterConfig: &v2.CiliumBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "bgp-cluster-config",
				},
				Spec: v2.CiliumBGPClusterConfigSpec{
					NodeSelector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp": "rack1",
						},
					},
					BGPInstances: []v2.CiliumBGPInstance{
						cluster1,
					},
				},
			},
			expectedNodeConfig: &v2.CiliumBGPNodeConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "node-1",
					OwnerReferences: []meta_v1.OwnerReference{
						{
							Kind: v2.BGPCCKindDefinition,
							Name: "bgp-cluster-config",
						},
					},
				},
				Spec: v2.CiliumBGPNodeSpec{
					BGPInstances: []v2.CiliumBGPNodeInstance{
						expectedNode1,
					},
				},
			},
		},
		{
			description: "node with label and cluster config with MatchExpression",
			node: &v2.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "node-1",
					Labels: map[string]string{
						"bgp": "rack1",
					},
				},
			},
			clusterConfig: &v2.CiliumBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "bgp-cluster-config",
				},
				Spec: v2.CiliumBGPClusterConfigSpec{
					NodeSelector: &slim_meta_v1.LabelSelector{
						MatchExpressions: []slim_meta_v1.LabelSelectorRequirement{
							{
								Key:      "bgp",
								Operator: slim_meta_v1.LabelSelectorOpIn,
								Values:   []string{"rack1"},
							},
						},
					},
					BGPInstances: []v2.CiliumBGPInstance{
						cluster1,
					},
				},
			},
			expectedNodeConfig: &v2.CiliumBGPNodeConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "node-1",
					OwnerReferences: []meta_v1.OwnerReference{
						{
							Kind: v2.BGPCCKindDefinition,
							Name: "bgp-cluster-config",
						},
					},
				},
				Spec: v2.CiliumBGPNodeSpec{
					BGPInstances: []v2.CiliumBGPNodeInstance{
						expectedNode1,
					},
				},
			},
		},
		{
			description: "node with label and cluster config with nil node selector",
			node: &v2.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "node-1",
					Labels: map[string]string{
						"bgp": "rack1",
					},
				},
			},
			clusterConfig: &v2.CiliumBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "bgp-cluster-config",
				},
				Spec: v2.CiliumBGPClusterConfigSpec{
					NodeSelector: nil,
					BGPInstances: []v2.CiliumBGPInstance{
						cluster1,
					},
				},
			},
			expectedNodeConfig: &v2.CiliumBGPNodeConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "node-1",
					OwnerReferences: []meta_v1.OwnerReference{
						{
							Kind: v2.BGPCCKindDefinition,
							Name: "bgp-cluster-config",
						},
					},
				},
				Spec: v2.CiliumBGPNodeSpec{
					BGPInstances: []v2.CiliumBGPNodeInstance{
						expectedNode1,
					},
				},
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := require.New(t)

			f, watcherReady := newFixture(t, ctx, req, true)

			tlog := hivetest.Logger(t)
			f.hive.Start(tlog, ctx)
			defer f.hive.Stop(tlog, ctx)

			// blocking till all watchers are ready
			watcherReady()

			// setup node
			upsertNode(req, ctx, f, tt.node)

			// upsert BGP cluster config
			upsertBGPCC(req, ctx, f, tt.clusterConfig)

			// validate node configs
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				nodeConfigs, err := f.bgpnClient.List(ctx, meta_v1.ListOptions{})
				if err != nil {
					assert.NoError(c, err)
					return
				}

				if tt.expectedNodeConfig == nil {
					assert.Empty(c, nodeConfigs.Items)
					return
				}

				nodeConfig, err := f.bgpnClient.Get(ctx, tt.expectedNodeConfig.Name, meta_v1.GetOptions{})
				if err != nil {
					assert.NoError(c, err)
					return
				}

				assert.True(c, isSameOwner(tt.expectedNodeConfig.GetOwnerReferences(), nodeConfig.GetOwnerReferences()))
				assert.Equal(c, tt.expectedNodeConfig.Spec, nodeConfig.Spec)

			}, TestTimeout, 50*time.Millisecond)
		})
	}
}

// Test_ClusterConfigSteps is step based test to validate the BGP node config controller
func Test_ClusterConfigSteps(t *testing.T) {
	clusterConfigName := "bgp-cluster-config"

	steps := []struct {
		description            string
		clusterConfig          *v2.CiliumBGPClusterConfig
		nodes                  []*v2.CiliumNode
		nodeOverrides          []*v2.CiliumBGPNodeConfigOverride
		expectedNodeConfigs    []*v2.CiliumBGPNodeConfig
		expectedTrueConditions []string
	}{
		{
			description:   "initial node setup",
			clusterConfig: nil,
			nodes: []*v2.CiliumNode{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
						Labels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
						Labels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
			},
			nodeOverrides:       nil,
			expectedNodeConfigs: nil,
		},
		{
			description: "initial bgp cluster config",
			clusterConfig: &v2.CiliumBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v2.CiliumBGPClusterConfigSpec{
					NodeSelector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp": "rack1",
						},
					},
					BGPInstances: []v2.CiliumBGPInstance{
						cluster1,
					},
				},
			},
			nodes:         nil,
			nodeOverrides: nil,
			expectedNodeConfigs: []*v2.CiliumBGPNodeConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Name: "bgp-cluster-config",
							},
						},
					},
					Spec: v2.CiliumBGPNodeSpec{
						BGPInstances: []v2.CiliumBGPNodeInstance{
							expectedNode1,
						},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Name: "bgp-cluster-config",
							},
						},
					},
					Spec: v2.CiliumBGPNodeSpec{
						BGPInstances: []v2.CiliumBGPNodeInstance{
							expectedNode1,
						},
					},
				},
			},
		},
		{
			description:   "add node override1",
			clusterConfig: nil,
			nodes:         nil,
			nodeOverrides: []*v2.CiliumBGPNodeConfigOverride{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
					},

					Spec: nodeOverride1,
				},
			},
			expectedNodeConfigs: []*v2.CiliumBGPNodeConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Name: "bgp-cluster-config",
							},
						},
					},
					Spec: v2.CiliumBGPNodeSpec{
						BGPInstances: []v2.CiliumBGPNodeInstance{
							expectedNodeWithOverride1,
						},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Name: "bgp-cluster-config",
							},
						},
					},
					Spec: v2.CiliumBGPNodeSpec{
						BGPInstances: []v2.CiliumBGPNodeInstance{
							expectedNode1,
						},
					},
				},
			},
		},
		{
			description:   "add node override2",
			clusterConfig: nil,
			nodes:         nil,
			nodeOverrides: []*v2.CiliumBGPNodeConfigOverride{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
					},

					Spec: nodeOverride2,
				},
			},
			expectedNodeConfigs: []*v2.CiliumBGPNodeConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Name: "bgp-cluster-config",
							},
						},
					},
					Spec: v2.CiliumBGPNodeSpec{
						BGPInstances: []v2.CiliumBGPNodeInstance{
							expectedNodeWithOverride2,
						},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Name: "bgp-cluster-config",
							},
						},
					},
					Spec: v2.CiliumBGPNodeSpec{
						BGPInstances: []v2.CiliumBGPNodeInstance{
							expectedNode1,
						},
					},
				},
			},
		},
		{
			description:   "add new node",
			clusterConfig: nil,
			nodes: []*v2.CiliumNode{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-3",
						Labels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
			},
			nodeOverrides: nil,
			expectedNodeConfigs: []*v2.CiliumBGPNodeConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Name: "bgp-cluster-config",
							},
						},
					},
					Spec: v2.CiliumBGPNodeSpec{
						BGPInstances: []v2.CiliumBGPNodeInstance{
							expectedNodeWithOverride2,
						},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Name: "bgp-cluster-config",
							},
						},
					},
					Spec: v2.CiliumBGPNodeSpec{
						BGPInstances: []v2.CiliumBGPNodeInstance{
							expectedNode1,
						},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-3",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Name: "bgp-cluster-config",
							},
						},
					},
					Spec: v2.CiliumBGPNodeSpec{
						BGPInstances: []v2.CiliumBGPNodeInstance{
							expectedNode1,
						},
					},
				},
			},
		},
		{
			description:   "remove node labels",
			clusterConfig: nil,
			nodes: []*v2.CiliumNode{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-3",
					},
				},
			},
			nodeOverrides:       nil,
			expectedNodeConfigs: nil,
			expectedTrueConditions: []string{
				v2.BGPClusterConfigConditionNoMatchingNode,
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	f, watchersReady := newFixture(t, ctx, require.New(t), true)

	tlog := hivetest.Logger(t)
	f.hive.Start(tlog, ctx)
	defer f.hive.Stop(tlog, ctx)

	watchersReady()

	for _, step := range steps {
		t.Run(step.description, func(t *testing.T) {
			req := require.New(t)

			// setup nodes
			for _, node := range step.nodes {
				upsertNode(req, ctx, f, node)
			}

			// upsert BGP cluster config
			upsertBGPCC(req, ctx, f, step.clusterConfig)

			// upsert node overrides
			for _, nodeOverride := range step.nodeOverrides {
				upsertNodeOverrides(req, ctx, f, nodeOverride)
			}

			// validate node configs
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				nodes, err := f.bgpnClient.List(ctx, meta_v1.ListOptions{})
				if err != nil {
					assert.NoError(c, err)
					return
				}

				assert.Equal(c, len(step.expectedNodeConfigs), len(nodes.Items))

				for _, expectedNodeConfig := range step.expectedNodeConfigs {
					nodeConfig, err := f.bgpnClient.Get(ctx, expectedNodeConfig.Name, meta_v1.GetOptions{})
					if err != nil {
						assert.NoError(c, err)
						return
					}

					assert.Equal(c, expectedNodeConfig.Name, nodeConfig.Name)
					assert.Equal(c, expectedNodeConfig.Spec, nodeConfig.Spec)
				}
			}, TestTimeout, 50*time.Millisecond)

			// Condition checks. Assuming the cluster config already exists on the API server.
			if len(step.expectedTrueConditions) > 0 {
				bgpcc, err := f.bgpcClient.Get(ctx, clusterConfigName, meta_v1.GetOptions{})
				req.NoError(err)

				trueConditions := sets.New[string]()
				for _, cond := range bgpcc.Status.Conditions {
					trueConditions.Insert(cond.Type)
				}

				for _, cond := range step.expectedTrueConditions {
					req.True(trueConditions.Has(cond), "Condition missing or not true: %s", cond)
				}
			}
		})
	}
}

func TestClusterConfigConditions(t *testing.T) {
	clusterConfigName := "cluster-config0"
	peerConfigName := "peer-config0"

	node := v2.CiliumNode{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "node-1",
			Labels: map[string]string{
				"bgp": "rack1",
			},
		},
	}

	peerConfig := v2.CiliumBGPPeerConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: peerConfigName,
		},
	}

	tests := []struct {
		name                    string
		clusterConfig           *v2.CiliumBGPClusterConfig
		expectedConditionStatus map[string]meta_v1.ConditionStatus
	}{
		{
			name: "NoMatchingNode False",
			clusterConfig: &v2.CiliumBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v2.CiliumBGPClusterConfigSpec{
					NodeSelector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v2.BGPClusterConfigConditionNoMatchingNode: meta_v1.ConditionFalse,
			},
		},
		{
			name: "NoMatchingNode False Nil Selector",
			clusterConfig: &v2.CiliumBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v2.CiliumBGPClusterConfigSpec{
					NodeSelector: nil,
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v2.BGPClusterConfigConditionNoMatchingNode: meta_v1.ConditionFalse,
			},
		},
		{
			name: "NoMatchingNode True",
			clusterConfig: &v2.CiliumBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v2.CiliumBGPClusterConfigSpec{
					NodeSelector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp": "rack2",
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v2.BGPClusterConfigConditionNoMatchingNode: meta_v1.ConditionTrue,
			},
		},
		{
			name: "MissingPeerConfig False",
			clusterConfig: &v2.CiliumBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v2.CiliumBGPClusterConfigSpec{
					NodeSelector: nil,
					BGPInstances: []v2.CiliumBGPInstance{
						{
							Peers: []v2.CiliumBGPPeer{
								{
									Name: "peer0",
									PeerConfigRef: &v2.PeerConfigReference{
										Name: peerConfigName,
									},
								},
							},
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v2.BGPClusterConfigConditionMissingPeerConfigs: meta_v1.ConditionFalse,
			},
		},
		{
			name: "MissingPeerConfig False nil PeerConfigRef",
			clusterConfig: &v2.CiliumBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v2.CiliumBGPClusterConfigSpec{
					NodeSelector: nil,
					BGPInstances: []v2.CiliumBGPInstance{
						{
							Peers: []v2.CiliumBGPPeer{
								{
									Name: "peer0",
								},
							},
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v2.BGPClusterConfigConditionMissingPeerConfigs: meta_v1.ConditionFalse,
			},
		},
		{
			name: "MissingPeerConfig True",
			clusterConfig: &v2.CiliumBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v2.CiliumBGPClusterConfigSpec{
					NodeSelector: nil,
					BGPInstances: []v2.CiliumBGPInstance{
						{
							Peers: []v2.CiliumBGPPeer{
								{
									Name: "peer0",
									PeerConfigRef: &v2.PeerConfigReference{
										Name: peerConfigName + "-foo",
									},
								},
							},
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v2.BGPClusterConfigConditionMissingPeerConfigs: meta_v1.ConditionTrue,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
			defer cancel()

			f, watchersReady := newFixture(t, ctx, require.New(t), true)

			tlog := hivetest.Logger(t)
			f.hive.Start(tlog, ctx)
			defer f.hive.Stop(tlog, ctx)

			watchersReady()

			// Setup resources
			upsertNode(req, ctx, f, &node)
			upsertBGPCC(req, ctx, f, tt.clusterConfig)
			upsertBGPPC(req, ctx, f, &peerConfig)

			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				// Check conditions
				cc, err := f.bgpcClient.Get(ctx, clusterConfigName, meta_v1.GetOptions{})
				if !assert.NoError(ct, err, "Cannot get cluster config") {
					return
				}

				// Check if the expected condition exists and has an intended values
				missing := maps.Clone(tt.expectedConditionStatus)
				for condType, status := range tt.expectedConditionStatus {
					for _, cond := range cc.Status.Conditions {
						if cond.Type == condType {
							if !assert.Equal(ct, status, cond.Status) {
								return
							}
							delete(missing, cond.Type)
						}
					}
				}

				assert.Empty(ct, missing, "Missing conditions: %v", missing)
			}, time.Second*3, time.Millisecond*100)
		})
	}
}

func TestConflictingClusterConfigCondition(t *testing.T) {
	nodes := []*v2.CiliumNode{
		{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: "node-0",
				Labels: map[string]string{
					"rack":             "rack0",
					"complete-overlap": "true",
					"partial-overlap0": "true",
				},
			},
		},
		{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: "node-1",
				Labels: map[string]string{
					"rack":             "rack1",
					"complete-overlap": "true",
					"partial-overlap0": "true",
					"partial-overlap1": "true",
				},
			},
		},
		{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: "node-2",
				Labels: map[string]string{
					"rack":             "rack2",
					"complete-overlap": "true",
					"partial-overlap1": "true",
				},
			},
		},
	}

	type clusterConfig struct {
		name     string
		selector *slim_meta_v1.LabelSelector
	}

	// sortRelation sorts the relation in a deterministic way.
	sortRelation := func(a, b [2]string) int {
		slices.Sort(a[:])
		slices.Sort(b[:])
		return strings.Compare(a[0]+a[1], b[0]+b[1])
	}

	tests := []struct {
		name           string
		clusterConfigs []clusterConfig

		// conflictingRelations is a list of pairs of cluster config
		// names that are expected to have a conflict.
		conflictingRelations [][2]string
	}{
		{
			name: "ConflictingClusterConfig False",
			clusterConfigs: []clusterConfig{
				{
					name: "cluster-config-0",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"rack": "rack0",
						},
					},
				},
				{
					name: "cluster-config-1",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"rack": "rack1",
						},
					},
				},
				{
					name: "cluster-config-2",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"rack": "rack2",
						},
					},
				},
			},
			conflictingRelations: [][2]string{},
		},
		{
			name: "ConflictingClusterConfig True complete overlap",
			clusterConfigs: []clusterConfig{
				{
					name: "cluster-config-0",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"complete-overlap": "true",
						},
					},
				},
				{
					name: "cluster-config-1",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"complete-overlap": "true",
						},
					},
				},
			},
			conflictingRelations: [][2]string{
				{"cluster-config-0", "cluster-config-1"},
			},
		},
		{
			name: "ConflictingClusterConfig True complete overlap with nil",
			clusterConfigs: []clusterConfig{
				{
					name:     "cluster-config-0",
					selector: nil,
				},
				{
					name:     "cluster-config-1",
					selector: nil,
				},
			},
			conflictingRelations: [][2]string{
				{"cluster-config-0", "cluster-config-1"},
			},
		},
		{
			name: "ConflictingClusterConfig True partial overlap",
			clusterConfigs: []clusterConfig{
				{
					name: "cluster-config-0",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"partial-overlap0": "true",
						},
					},
				},
				{
					name: "cluster-config-1",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"partial-overlap1": "true",
						},
					},
				},
			},
			conflictingRelations: [][2]string{
				{"cluster-config-0", "cluster-config-1"},
			},
		},
		{
			name: "ConflictingClusterConfig True partial overlap of four configs",
			clusterConfigs: []clusterConfig{
				{
					name: "cluster-config-0",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"partial-overlap0": "true",
						},
					},
				},
				{
					name: "cluster-config-1",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"rack": "rack0",
						},
					},
				},
				{
					name: "cluster-config-2",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"rack": "rack1",
						},
					},
				},
				{
					name: "cluster-config-3",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"rack": "rack2",
						},
					},
				},
			},
			conflictingRelations: [][2]string{
				{"cluster-config-0", "cluster-config-1"},
				{"cluster-config-0", "cluster-config-2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
			defer cancel()

			f, watchersReady := newFixture(t, ctx, require.New(t), true)

			tlog := hivetest.Logger(t)
			f.hive.Start(tlog, ctx)
			defer f.hive.Stop(tlog, ctx)

			watchersReady()

			// Setup resources
			for _, node := range nodes {
				upsertNode(req, ctx, f, node)
			}

			for _, config := range tt.clusterConfigs {
				clusterConfig := &v2.CiliumBGPClusterConfig{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: config.name,
						// Fake client doesn't set UID. Assign it manually.
						UID: uuid.NewUUID(),
					},
					Spec: v2.CiliumBGPClusterConfigSpec{
						NodeSelector: config.selector,
						BGPInstances: []v2.CiliumBGPInstance{
							{
								Peers: []v2.CiliumBGPPeer{},
							},
						},
					},
				}
				upsertBGPCC(req, ctx, f, clusterConfig)
			}

			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				configs, err := f.bgpcClient.List(ctx, meta_v1.ListOptions{})
				if !assert.NoError(ct, err, "Cannot list cluster configs") {
					return
				}

				// Here we collect all conflicting configs from all cluster configs.
				// Since we detect the conflict by checking the owner reference of
				// the node config, the cluster config observes the conflict depends
				// on the node config creation order. So we need to check all cluster
				// configs to get the entire view of the conflicts.
				conflictingRelations := [][2]string{}
				for _, config := range configs.Items {
					cond := meta.FindStatusCondition(
						config.Status.Conditions,
						v2.BGPClusterConfigConditionConflictingClusterConfigs,
					)
					if !assert.NotNil(ct, cond, "Condition not found") {
						return
					}

					if len(tt.conflictingRelations) == 0 {
						if !assert.Equal(ct, meta_v1.ConditionFalse, cond.Status, "Expected condition to be false") {
							return
						}
						return
					}

					if cond.Status == meta_v1.ConditionFalse {
						continue
					}

					expr, err := regexp.Compile(
						`Selecting the same node\(s\) with ClusterConfig\(s\): \[(.*)\]`,
					)
					if !assert.NoError(ct, err, "Error during regexp match") {
						return
					}

					match := expr.FindSubmatch([]byte(cond.Message))
					if !assert.Len(ct, match, 2, "Invalid number of match") {
						return
					}

					for _, conflictingConfig := range strings.Split(string(match[1]), " ") {
						relation := [2]string{config.Name, conflictingConfig}
						conflictingRelations = append(conflictingRelations, relation)
					}
				}

				// Short circuit if the number of conflict relations is not the same.
				if !assert.Len(ct, conflictingRelations, len(tt.conflictingRelations), "Exexpected number of conflicts") {
					return
				}

				// Sort the conflicting relations to make the comparison deterministic.
				slices.SortFunc(conflictingRelations, sortRelation)
				slices.SortFunc(tt.conflictingRelations, sortRelation)

				// Compare the conflicting relations.
				for i := 0; i < len(tt.conflictingRelations); i++ {
					if !assert.ElementsMatch(ct, tt.conflictingRelations[i], conflictingRelations[i]) {
						return
					}
				}
			}, time.Second*3, time.Millisecond*100)
		})
	}
}

func TestDisableClusterConfigStatusReport(t *testing.T) {
	req := require.New(t)

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	f, watchersReady := newFixture(t, ctx, require.New(t), false)

	tlog := hivetest.Logger(t)
	f.hive.Start(tlog, ctx)
	defer f.hive.Stop(tlog, ctx)

	watchersReady()

	clusterConfig := &v2.CiliumBGPClusterConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "config0",
		},
		Spec: v2.CiliumBGPClusterConfigSpec{},
		Status: v2.CiliumBGPClusterConfigStatus{
			Conditions: []meta_v1.Condition{},
		},
	}

	// Fill with all known conditions
	for _, cond := range v2.AllBGPClusterConfigConditions {
		clusterConfig.Status.Conditions = append(clusterConfig.Status.Conditions, meta_v1.Condition{
			Type: cond,
		})
	}

	// Setup resourses with status
	upsertBGPCC(req, ctx, f, clusterConfig)

	// Wait for status to be cleared
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Check conditions
		cc, err := f.bgpcClient.Get(ctx, clusterConfig.Name, meta_v1.GetOptions{})
		if !assert.NoError(ct, err, "Cannot get cluster config") {
			return
		}

		assert.Empty(ct, cc.Status.Conditions, "Conditions are not cleared")
	}, time.Second*3, time.Millisecond*100)
}

func upsertNode(req *require.Assertions, ctx context.Context, f *fixture, node *v2.CiliumNode) {
	_, err := f.nodeClient.Get(ctx, node.Name, meta_v1.GetOptions{})
	if err != nil && k8sErrors.IsNotFound(err) {
		_, err = f.nodeClient.Create(ctx, node, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		_, err = f.nodeClient.Update(ctx, node, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

func upsertBGPCC(req *require.Assertions, ctx context.Context, f *fixture, bgpcc *v2.CiliumBGPClusterConfig) {
	if bgpcc == nil {
		return
	}

	_, err := f.bgpcClient.Get(ctx, bgpcc.Name, meta_v1.GetOptions{})
	if err != nil && k8sErrors.IsNotFound(err) {
		_, err = f.bgpcClient.Create(ctx, bgpcc, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		_, err = f.bgpcClient.Update(ctx, bgpcc, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

func upsertBGPPC(req *require.Assertions, ctx context.Context, f *fixture, bgppc *v2.CiliumBGPPeerConfig) {
	if bgppc == nil {
		return
	}

	_, err := f.bgpcClient.Get(ctx, bgppc.Name, meta_v1.GetOptions{})
	if err != nil && k8sErrors.IsNotFound(err) {
		_, err = f.bgppcClient.Create(ctx, bgppc, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		_, err = f.bgppcClient.Update(ctx, bgppc, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

func upsertNodeOverrides(req *require.Assertions, ctx context.Context, f *fixture, nodeOverride *v2.CiliumBGPNodeConfigOverride) {
	_, err := f.bgpncoClient.Get(ctx, nodeOverride.Name, meta_v1.GetOptions{})
	if err != nil && k8sErrors.IsNotFound(err) {
		_, err = f.bgpncoClient.Create(ctx, nodeOverride, meta_v1.CreateOptions{})
	} else {
		_, err = f.bgpncoClient.Update(ctx, nodeOverride, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

func isSameOwner(expectedOwners, runningOwners []meta_v1.OwnerReference) bool {
	if len(expectedOwners) != len(runningOwners) {
		return false
	}

	for i, owner := range expectedOwners {
		if runningOwners[i].Kind != owner.Kind || runningOwners[i].Name != owner.Name {
			return false
		}
	}
	return true
}
