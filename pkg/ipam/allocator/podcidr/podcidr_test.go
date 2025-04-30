// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package podcidr

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/ipam/allocator/clusterpool/cidralloc"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/trigger"
)

func mustNewCIDRs(cidrs ...string) []*net.IPNet {
	ipnets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		ipnets = append(ipnets, ipNet)
	}
	return ipnets
}

func mustNewTrigger(f func(), minInterval time.Duration) *trigger.Trigger {
	t, err := trigger.NewTrigger(trigger.Parameters{
		MinInterval: minInterval,
		TriggerFunc: func(reasons []string) {
			f()
		},
		Name: "",
	})
	if err != nil {
		panic(err)
	}
	return t
}

type mockCIDRAllocator struct {
	OnOccupy       func(cidr *net.IPNet) error
	OnAllocateNext func() (*net.IPNet, error)
	OnRelease      func(cidr *net.IPNet) error
	OnIsAllocated  func(cidr *net.IPNet) (bool, error)
	OnIsFull       func() bool
	OnInRange      func(cidr *net.IPNet) bool
}

func (d *mockCIDRAllocator) String() string {
	return "clusterCIDR: 10.0.0.0/24, nodeMask: 24"
}

func (d *mockCIDRAllocator) Occupy(cidr *net.IPNet) error {
	if d.OnOccupy != nil {
		return d.OnOccupy(cidr)
	}
	panic("d.Occupy should not have been called!")
}

func (d *mockCIDRAllocator) AllocateNext() (*net.IPNet, error) {
	if d.OnAllocateNext != nil {
		return d.OnAllocateNext()
	}
	panic("d.AllocateNext should not have been called!")
}

func (d *mockCIDRAllocator) Release(cidr *net.IPNet) error {
	if d.OnRelease != nil {
		return d.OnRelease(cidr)
	}
	panic("d.Release should not have been called!")
}

func (d *mockCIDRAllocator) IsAllocated(cidr *net.IPNet) (bool, error) {
	if d.OnIsAllocated != nil {
		return d.OnIsAllocated(cidr)
	}
	panic("d.IsAllocated should not have been called!")
}

func (d *mockCIDRAllocator) IsFull() bool {
	if d.OnIsFull != nil {
		return d.OnIsFull()
	}
	panic("d.IsFull should not have been called!")
}

func (d *mockCIDRAllocator) InRange(cidr *net.IPNet) bool {
	if d.OnInRange != nil {
		return d.OnInRange(cidr)
	}
	panic("d.InRange should not have been called!")
}

func (d *mockCIDRAllocator) IsClusterCIDR(cidr netip.Prefix) bool {
	return false
}

func (d *mockCIDRAllocator) Prefix() netip.Prefix {
	return netip.MustParsePrefix("10.0.0.0/24")
}

type k8sNodeMock struct {
	OnUpdate       func(oldNode, newNode *v2.CiliumNode) (*v2.CiliumNode, error)
	OnUpdateStatus func(oldNode, newNode *v2.CiliumNode) (*v2.CiliumNode, error)
	OnGet          func(node string) (*v2.CiliumNode, error)
	OnCreate       func(n *v2.CiliumNode) (*v2.CiliumNode, error)
	OnDelete       func(nodeName string) error
}

func (k *k8sNodeMock) Update(origNode, node *v2.CiliumNode) (*v2.CiliumNode, error) {
	if k.OnUpdate != nil {
		return k.OnUpdate(origNode, node)
	}
	panic("d.Update should not be called!")
}

func (k *k8sNodeMock) UpdateStatus(origNode, node *v2.CiliumNode) (*v2.CiliumNode, error) {
	if k.OnUpdateStatus != nil {
		return k.OnUpdateStatus(origNode, node)
	}
	panic("d.UpdateStatus should not be called!")
}

func (k *k8sNodeMock) Get(node string) (*v2.CiliumNode, error) {
	if k.OnGet != nil {
		return k.OnGet(node)
	}
	panic("d.Get should not be called!")
}

func (k *k8sNodeMock) Create(n *v2.CiliumNode) (*v2.CiliumNode, error) {
	if k.OnCreate != nil {
		return k.OnCreate(n)
	}
	panic("d.Create should not be called!")
}

func TestNodesPodCIDRManager_Delete(t *testing.T) {
	var reSyncCalls atomic.Int32
	type fields struct {
		k8sReSyncController *controller.Manager
		k8sReSync           *trigger.Trigger
		canAllocateNodes    bool
		v4ClusterCIDRs      []cidralloc.CIDRAllocator
		v6ClusterCIDRs      []cidralloc.CIDRAllocator
		nodes               map[string]*nodeCIDRs
		ciliumNodesToK8s    map[string]*ciliumNodeK8sOp
	}
	type args struct {
		node *v2.CiliumNode
	}
	tests := []struct {
		testSetup   func() *fields
		testPostRun func(fields *fields)
		name        string
		fields      *fields
		args        args
	}{
		{
			name: "test-1 - should release the v4 CIDR",
			testSetup: func() *fields {
				reSyncCalls.Store(0)
				return &fields{
					canAllocateNodes: true,
					v4ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{
							OnRelease: func(cidr *net.IPNet) error {
								require.Equal(t, mustNewCIDRs("10.10.0.0/24")[0], cidr)
								return nil
							},
							OnInRange: func(cidr *net.IPNet) bool {
								require.Equal(t, mustNewCIDRs("10.10.0.0/24")[0], cidr)
								return true
							},
						},
					},
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDRs: mustNewCIDRs("10.10.0.0/24"),
						},
					},
					ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{},
					k8sReSync: mustNewTrigger(func() {
						reSyncCalls.Add(1)
					}, time.Millisecond),
				}
			},
			testPostRun: func(fields *fields) {
				time.Sleep(2 * time.Millisecond)
				require.Equal(t, map[string]*nodeCIDRs{}, fields.nodes)
				require.Equal(t, map[string]*ciliumNodeK8sOp{
					"node-1": {
						op: k8sOpDelete,
					},
				}, fields.ciliumNodesToK8s)
				require.Equal(t, int32(1), reSyncCalls.Load())
			},
			args: args{
				node: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
					},
				},
			},
		},
		{
			name: "test-2 - should be a no op since the node is not allocated",
			testSetup: func() *fields {
				reSyncCalls.Store(0)
				return &fields{
					canAllocateNodes: true,
					ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{},
				}
			},
			testPostRun: func(fields *fields) {
				require.Equal(t, map[string]*ciliumNodeK8sOp{}, fields.ciliumNodesToK8s)
				require.Equal(t, int32(0), reSyncCalls.Load())
			},
			args: args{
				node: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt.fields = tt.testSetup()
		n := &NodesPodCIDRManager{
			logger:              hivetest.Logger(t),
			k8sReSyncController: tt.fields.k8sReSyncController,
			k8sReSync:           tt.fields.k8sReSync,
			canAllocatePodCIDRs: tt.fields.canAllocateNodes,
			v4CIDRAllocators:    tt.fields.v4ClusterCIDRs,
			v6CIDRAllocators:    tt.fields.v6ClusterCIDRs,
			nodes:               tt.fields.nodes,
			ciliumNodesToK8s:    tt.fields.ciliumNodesToK8s,
		}
		n.Delete(tt.args.node)

		if tt.testPostRun != nil {
			tt.testPostRun(tt.fields)
		}
	}
}

func TestNodesPodCIDRManager_Resync(t *testing.T) {
	var reSyncCalls atomic.Int32
	type fields struct {
		k8sReSync *trigger.Trigger
	}
	tests := []struct {
		testSetup   func() *fields
		testPostRun func(fields *fields)
		name        string
		fields      *fields
	}{
		{
			name: "test-1",
			testSetup: func() *fields {
				return &fields{
					k8sReSync: mustNewTrigger(func() {
						reSyncCalls.Add(1)
					}, time.Millisecond),
				}
			},
			testPostRun: func(fields *fields) {
				// Trigger is async, so until we have synctest testing we have
				// to resort to Eventually.
				require.Eventually(t, func() bool { return reSyncCalls.Load() >= 1 },
					time.Second*2, time.Millisecond)
				require.Equal(t, int32(1), reSyncCalls.Load())
			},
		},
	}

	for _, tt := range tests {
		tt.fields = tt.testSetup()
		n := &NodesPodCIDRManager{
			logger:    hivetest.Logger(t),
			k8sReSync: tt.fields.k8sReSync,
		}
		n.Resync(t.Context(), time.Time{})

		if tt.testPostRun != nil {
			tt.testPostRun(tt.fields)
		}
	}
}

func TestNodesPodCIDRManager_Upsert(t *testing.T) {
	type fields struct {
		k8sReSyncController *controller.Manager
		k8sReSync           *trigger.Trigger
		canAllocateNodes    bool
		v4ClusterCIDRs      []cidralloc.CIDRAllocator
		v6ClusterCIDRs      []cidralloc.CIDRAllocator
		nodes               map[string]*nodeCIDRs
		ciliumNodesToK8s    map[string]*ciliumNodeK8sOp
	}
	type args struct {
		node *v2.CiliumNode
	}
	tests := []struct {
		testSetup   func() *fields
		testPostRun func(fields *fields)
		name        string
		fields      *fields
		args        args
	}{
		{
			name: "test-1 - should allocate a v4 addr",
			testSetup: func() *fields {
				return &fields{
					canAllocateNodes: true,
					v4ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{
							OnAllocateNext: func() (ipNet *net.IPNet, err error) {
								return mustNewCIDRs("10.10.0.0/24")[0], nil
							},
							OnIsFull: func() bool {
								return false
							},
						},
					},
					nodes:            map[string]*nodeCIDRs{},
					ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{},
					k8sReSync: mustNewTrigger(func() {
					}, time.Second),
				}
			},
			testPostRun: func(fields *fields) {
				require.Equal(t, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDRs: mustNewCIDRs("10.10.0.0/24"),
					},
				}, fields.nodes)
				require.Equal(t, map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: metav1.ObjectMeta{
								Name:            "node-1",
								ResourceVersion: "1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						},
						op: k8sOpUpdate,
					},
				}, fields.ciliumNodesToK8s)
			},
			args: args{
				node: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "node-1",
						ResourceVersion: "1",
					},
				},
			},
		},
		{
			name: "test-2 - failed to allocate a v4 addr",
			testSetup: func() *fields {
				return &fields{
					canAllocateNodes: true,
					v4ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{
							OnAllocateNext: func() (ipNet *net.IPNet, err error) {
								return nil, fmt.Errorf("Allocator full!")
							},
							OnIsFull: func() bool {
								return false
							},
						},
					},
					nodes:            map[string]*nodeCIDRs{},
					ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{},
					k8sReSync: mustNewTrigger(func() {
					}, time.Second),
				}
			},
			testPostRun: func(fields *fields) {
				require.Equal(t, map[string]*nodeCIDRs{}, fields.nodes)
				require.Equal(t, map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: metav1.ObjectMeta{
								Name:            "node-1",
								ResourceVersion: "1",
							},
							Status: v2.NodeStatus{
								IPAM: ipamTypes.IPAMStatus{
									OperatorStatus: ipamTypes.OperatorStatus{
										Error: "Allocator full!",
									},
								},
							},
						},
						op: k8sOpUpdateStatus,
					},
				}, fields.ciliumNodesToK8s)
			},
			args: args{
				node: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "node-1",
						ResourceVersion: "1",
					},
				},
			},
		},
		{
			name: "test-3 - node is already allocated with the requested pod CIDRs",
			testSetup: func() *fields {
				return &fields{
					canAllocateNodes: true,
					v4ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{
							OnAllocateNext: func() (ipNet *net.IPNet, err error) {
								return nil, fmt.Errorf("Allocator full!")
							},
							OnIsFull: func() bool {
								return false
							},
						},
					},
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDRs: mustNewCIDRs("10.10.0.0/24"),
						},
					},
				}
			},
			testPostRun: func(fields *fields) {
				require.Equal(t, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDRs: mustNewCIDRs("10.10.0.0/24"),
					},
				}, fields.nodes)
			},
			args: args{
				node: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "node-1",
						ResourceVersion: "1",
					},
					Spec: v2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							PodCIDRs: []string{
								"10.10.0.0/24",
							},
						},
					},
				},
			},
		},
		{
			name: "test-4 - node is requesting pod CIDRs, it's already allocated locally but the spec is not updated",
			testSetup: func() *fields {
				return &fields{
					canAllocateNodes: true,
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDRs: mustNewCIDRs("10.10.0.0/24"),
						},
					},
					ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{},
					k8sReSync: mustNewTrigger(func() {
					}, time.Second),
				}
			},
			testPostRun: func(fields *fields) {
				require.Equal(t, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDRs: mustNewCIDRs("10.10.0.0/24"),
					},
				}, fields.nodes)
				require.Equal(t, map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: metav1.ObjectMeta{
								Name:            "node-1",
								ResourceVersion: "1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						},
						op: k8sOpUpdate,
					},
				}, fields.ciliumNodesToK8s)
			},
			args: args{
				node: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "node-1",
						ResourceVersion: "1",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt.fields = tt.testSetup()
		n := &NodesPodCIDRManager{
			logger:              hivetest.Logger(t),
			k8sReSyncController: tt.fields.k8sReSyncController,
			k8sReSync:           tt.fields.k8sReSync,
			canAllocatePodCIDRs: tt.fields.canAllocateNodes,
			v4CIDRAllocators:    tt.fields.v4ClusterCIDRs,
			v6CIDRAllocators:    tt.fields.v6ClusterCIDRs,
			nodes:               tt.fields.nodes,
			ciliumNodesToK8s:    tt.fields.ciliumNodesToK8s,
		}
		n.Upsert(tt.args.node)

		if tt.testPostRun != nil {
			tt.testPostRun(tt.fields)
		}
	}
}

func TestNodesPodCIDRManager_allocateIPNets(t *testing.T) {
	var (
		onOccupyCallsv4, releaseCallsv4, onIsAllocatedCallsv4 int
		onOccupyCallsv6, releaseCallsv6, onIsAllocatedCallsv6 int
		onAllocateNextv6                                      int
	)

	type fields struct {
		canAllocatePodCIDRs bool
		v4ClusterCIDRs      []cidralloc.CIDRAllocator
		v6ClusterCIDRs      []cidralloc.CIDRAllocator
		newNodeCIDRs        *nodeCIDRs
		nodes               map[string]*nodeCIDRs
	}
	type args struct {
		nodeName string
		v4CIDR   []*net.IPNet
		v6CIDR   []*net.IPNet
	}
	tests := []struct {
		name          string
		testSetup     func() *fields
		testPostRun   func(fields *fields)
		fields        *fields
		args          args
		wantAllocated bool
		wantErr       bool
	}{
		{
			name: "test-1 - should not allocate anything because the node had previously allocated CIDRs",
			testSetup: func() *fields {
				return &fields{
					canAllocatePodCIDRs: true,
					v4ClusterCIDRs:      []cidralloc.CIDRAllocator{&mockCIDRAllocator{}},
					v6ClusterCIDRs:      []cidralloc.CIDRAllocator{&mockCIDRAllocator{}},
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDRs: mustNewCIDRs("10.10.0.0/24"),
							v6PodCIDRs: mustNewCIDRs("fd00::/80"),
						},
					},
					newNodeCIDRs: &nodeCIDRs{
						v4PodCIDRs: mustNewCIDRs("10.10.0.0/24"),
						v6PodCIDRs: mustNewCIDRs("fd00::/80"),
					},
				}
			},
			testPostRun: func(fields *fields) {
				require.Equal(t, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDRs: mustNewCIDRs("10.10.0.0/24"),
						v6PodCIDRs: mustNewCIDRs("fd00::/80"),
					},
				}, fields.nodes)
			},
			args: args{
				nodeName: "node-1",
				v4CIDR:   mustNewCIDRs("10.10.0.0/24"),
				v6CIDR:   mustNewCIDRs("fd00::/80"),
			},
			wantAllocated: false,
			wantErr:       false,
		},
		{
			name: "test-2 - should allocate both CIDRs",
			testSetup: func() *fields {
				releaseCallsv4, releaseCallsv6 = 0, 0
				onOccupyCallsv4, onOccupyCallsv6 = 0, 0
				onIsAllocatedCallsv4, onIsAllocatedCallsv6 = 0, 0
				return &fields{
					canAllocatePodCIDRs: true,
					v4ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{
							OnOccupy: func(cidr *net.IPNet) error {
								onOccupyCallsv4++
								require.Equal(t, mustNewCIDRs("10.10.0.0/24")[0], cidr)
								return nil
							},
							OnIsAllocated: func(cidr *net.IPNet) (bool, error) {
								onIsAllocatedCallsv4++
								require.Equal(t, mustNewCIDRs("10.10.0.0/24")[0], cidr)
								return false, nil
							},
							OnInRange: func(cidr *net.IPNet) bool {
								require.Equal(t, mustNewCIDRs("10.10.0.0/24")[0], cidr)
								return true
							},
							OnIsFull: func() bool {
								return false
							},
						},
					},
					v6ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{
							OnOccupy: func(cidr *net.IPNet) error {
								onOccupyCallsv6++
								require.Equal(t, mustNewCIDRs("fd00::/80")[0], cidr)
								return nil
							},
							OnIsAllocated: func(cidr *net.IPNet) (bool, error) {
								onIsAllocatedCallsv6++
								require.Equal(t, mustNewCIDRs("fd00::/80")[0], cidr)
								return false, nil
							},
							OnInRange: func(cidr *net.IPNet) bool {
								require.Equal(t, mustNewCIDRs("fd00::/80")[0], cidr)
								return true
							},
							OnIsFull: func() bool {
								return false
							},
						},
					},
					nodes: map[string]*nodeCIDRs{},
					newNodeCIDRs: &nodeCIDRs{
						v4PodCIDRs: mustNewCIDRs("10.10.0.0/24"),
						v6PodCIDRs: mustNewCIDRs("fd00::/80"),
					},
				}
			},
			testPostRun: func(fields *fields) {
				require.Equal(t, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDRs: mustNewCIDRs("10.10.0.0/24"),
						v6PodCIDRs: mustNewCIDRs("fd00::/80"),
					},
				}, fields.nodes)
				require.Equal(t, 1, onIsAllocatedCallsv4)
				require.Equal(t, 1, onOccupyCallsv4)
				require.Equal(t, 0, releaseCallsv4)

				require.Equal(t, 1, onIsAllocatedCallsv6)
				require.Equal(t, 1, onOccupyCallsv6)
				require.Equal(t, 0, releaseCallsv6)
			},
			args: args{
				nodeName: "node-1",
				v4CIDR:   mustNewCIDRs("10.10.0.0/24"),
				v6CIDR:   mustNewCIDRs("fd00::/80"),
			},
			wantAllocated: true,
			wantErr:       false,
		},
		{
			name: "test-3 - the v6 allocator is full!",
			testSetup: func() *fields {
				releaseCallsv4, releaseCallsv6 = 0, 0
				onOccupyCallsv4, onOccupyCallsv6 = 0, 0
				onIsAllocatedCallsv4, onIsAllocatedCallsv6 = 0, 0
				return &fields{
					canAllocatePodCIDRs: true,
					v4ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{
							OnIsAllocated: func(cidr *net.IPNet) (bool, error) {
								onIsAllocatedCallsv4++
								require.Equal(t, mustNewCIDRs("10.10.0.0/24")[0], cidr)
								return false, nil
							},
							OnOccupy: func(cidr *net.IPNet) error {
								onOccupyCallsv4++
								require.Equal(t, mustNewCIDRs("10.10.0.0/24")[0], cidr)
								return nil
							},
							OnRelease: func(cidr *net.IPNet) error {
								require.Equal(t, mustNewCIDRs("10.10.0.0/24")[0], cidr)
								releaseCallsv4++
								return nil
							},
							OnInRange: func(cidr *net.IPNet) bool {
								require.Equal(t, mustNewCIDRs("10.10.0.0/24")[0], cidr)
								return true
							},
							OnIsFull: func() bool {
								return false
							},
						},
					},
					v6ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{
							OnInRange: func(cidr *net.IPNet) bool {
								require.Equal(t, mustNewCIDRs("fd00::/80")[0], cidr)
								return true
							},
							OnIsFull: func() bool {
								return true
							},
						},
					},
					nodes: map[string]*nodeCIDRs{},
				}
			},
			testPostRun: func(fields *fields) {
				require.Equal(t, map[string]*nodeCIDRs{}, fields.nodes)
				require.Equal(t, 1, onIsAllocatedCallsv4)
				require.Equal(t, 1, onOccupyCallsv4)
				require.Equal(t, 1, releaseCallsv4)

				require.Equal(t, 0, onIsAllocatedCallsv6)
				require.Equal(t, 0, onOccupyCallsv6)
				require.Equal(t, 0, releaseCallsv6)
			},
			args: args{
				nodeName: "node-1",
				v4CIDR:   mustNewCIDRs("10.10.0.0/24"),
				v6CIDR:   mustNewCIDRs("fd00::/80"),
			},
			wantAllocated: false,
			wantErr:       true,
		},
		{
			name: "test-4 - changing CIDRs of a node is not valid",
			testSetup: func() *fields {
				return &fields{
					canAllocatePodCIDRs: true,
					v4ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{},
					},
					v6ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{},
					},
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDRs: mustNewCIDRs("10.10.1.0/24"),
							v6PodCIDRs: mustNewCIDRs("fd01::/80"),
						},
					},
				}
			},
			testPostRun: func(fields *fields) {
				require.Equal(t, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDRs: mustNewCIDRs("10.10.1.0/24"),
						v6PodCIDRs: mustNewCIDRs("fd01::/80"),
					},
				}, fields.nodes)
			},
			args: args{
				nodeName: "node-1",
				v4CIDR:   mustNewCIDRs("10.10.0.0/24"),
				v6CIDR:   mustNewCIDRs("fd00::/80"),
			},
			wantAllocated: false,
			wantErr:       true,
		},
		{
			name: "test-5 - should not allocate anything because there isn't" +
				" an allocator available for the CIDR family requested!",
			testSetup: func() *fields {
				return &fields{
					canAllocatePodCIDRs: true,
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDRs: mustNewCIDRs("10.10.1.0/24"),
							v6PodCIDRs: mustNewCIDRs("fd01::/80"),
						},
					},
				}
			},
			testPostRun: func(fields *fields) {
				require.Equal(t, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDRs: mustNewCIDRs("10.10.1.0/24"),
						v6PodCIDRs: mustNewCIDRs("fd01::/80"),
					},
				}, fields.nodes)
			},
			args: args{
				nodeName: "node-1",
				v4CIDR:   mustNewCIDRs("10.10.1.0/24"),
				v6CIDR:   mustNewCIDRs("fd01::/80"),
			},
			wantErr: true,
		},
		{
			name: "test-7- should allocate a v6 address if the node has a v4 " +
				"and missing a v6 address.",
			testSetup: func() *fields {
				onAllocateNextv6 = 0
				return &fields{
					canAllocatePodCIDRs: true,
					v4ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{},
					},
					v6ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{
							OnIsFull: func() bool {
								return false
							},
							OnAllocateNext: func() (*net.IPNet, error) {
								onAllocateNextv6++
								return mustNewCIDRs("fd00::/80")[0], nil
							},
						},
					},
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDRs: mustNewCIDRs("10.10.0.0/24"),
						},
					},
					newNodeCIDRs: &nodeCIDRs{
						v4PodCIDRs: mustNewCIDRs("10.10.0.0/24"),
						v6PodCIDRs: mustNewCIDRs("fd00::/80"),
					},
				}
			},
			testPostRun: func(fields *fields) {
				require.Equal(t, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDRs: mustNewCIDRs("10.10.0.0/24"),
						v6PodCIDRs: mustNewCIDRs("fd00::/80"),
					},
				}, fields.nodes)
				require.Equal(t, 1, onAllocateNextv6)
			},
			args: args{
				nodeName: "node-1",
				v4CIDR:   mustNewCIDRs("10.10.0.0/24"),
			},
			wantAllocated: true,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		tt.fields = tt.testSetup()
		n := &NodesPodCIDRManager{
			logger:              hivetest.Logger(t),
			canAllocatePodCIDRs: tt.fields.canAllocatePodCIDRs,
			v4CIDRAllocators:    tt.fields.v4ClusterCIDRs,
			v6CIDRAllocators:    tt.fields.v6ClusterCIDRs,
			nodes:               tt.fields.nodes,
		}
		newNodeCIDRs, gotAllocated, err := n.reuseIPNets(tt.args.nodeName, tt.args.v4CIDR, tt.args.v6CIDR)
		gotErr := err != nil
		require.Equal(t, tt.wantErr, gotErr, "Test Name: %s", tt.name)
		require.Equal(t, tt.wantAllocated, gotAllocated, "Test Name: %s", tt.name)
		require.Equal(t, tt.fields.newNodeCIDRs, newNodeCIDRs, "Test Name: %s", tt.name)

		if tt.testPostRun != nil {
			tt.testPostRun(tt.fields)
		}
	}
}

func TestNodesPodCIDRManager_allocateNext(t *testing.T) {
	var (
		allocateNextCallsv4, releaseCallsv4 int
		allocateNextCallsv6                 int
	)

	type fields struct {
		v4ClusterCIDRs []cidralloc.CIDRAllocator
		v6ClusterCIDRs []cidralloc.CIDRAllocator
		nodes          map[string]*nodeCIDRs
	}
	type args struct {
		nodeName string
	}
	tests := []struct {
		testSetup     func() *fields
		testPostRun   func(fields *fields)
		name          string
		fields        *fields
		args          args
		nodeCIDRs     *nodeCIDRs
		wantAllocated bool
		wantErr       error
	}{
		{
			name: "test-1 - should not allocate anything because the node had previously allocated CIDRs",
			testSetup: func() *fields {
				return &fields{
					v4ClusterCIDRs: []cidralloc.CIDRAllocator{},
					v6ClusterCIDRs: []cidralloc.CIDRAllocator{},
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDRs: mustNewCIDRs("10.10.0.0/24"),
							v6PodCIDRs: mustNewCIDRs("fd00::/80"),
						},
					},
				}
			},
			testPostRun: func(fields *fields) {
				require.Equal(t, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDRs: mustNewCIDRs("10.10.0.0/24"),
						v6PodCIDRs: mustNewCIDRs("fd00::/80"),
					},
				}, fields.nodes)
			},
			args: args{
				nodeName: "node-1",
			},
			nodeCIDRs: &nodeCIDRs{
				v4PodCIDRs: mustNewCIDRs("10.10.0.0/24"),
				v6PodCIDRs: mustNewCIDRs("fd00::/80"),
			},
			wantAllocated: false,
			wantErr:       nil,
		},
		{
			name: "test-2 - should allocate both CIDRs",
			testSetup: func() *fields {
				allocateNextCallsv4, allocateNextCallsv6 = 0, 0
				return &fields{
					v4ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{
							OnAllocateNext: func() (ipNet *net.IPNet, err error) {
								allocateNextCallsv4++
								return mustNewCIDRs("10.10.0.0/24")[0], nil
							},
							OnIsFull: func() bool {
								return false
							},
							OnInRange: func(cidr *net.IPNet) bool {
								require.Equal(t, mustNewCIDRs("10.10.0.0/24")[0], cidr)
								return true
							},
						},
					},
					v6ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{
							OnAllocateNext: func() (ipNet *net.IPNet, err error) {
								allocateNextCallsv6++
								return mustNewCIDRs("fd00::/80")[0], nil
							},
							OnIsFull: func() bool {
								return false
							},
							OnInRange: func(cidr *net.IPNet) bool {
								require.Equal(t, mustNewCIDRs("10.10.0.0/24")[0], cidr)
								return true
							},
						},
					},
					nodes: map[string]*nodeCIDRs{},
				}
			},
			testPostRun: func(fields *fields) {
				require.Equal(t, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDRs: mustNewCIDRs("10.10.0.0/24"),
						v6PodCIDRs: mustNewCIDRs("fd00::/80"),
					},
				}, fields.nodes)
				require.Equal(t, 1, allocateNextCallsv4)
				require.Equal(t, 1, allocateNextCallsv6)
			},
			args: args{
				nodeName: "node-1",
			},
			nodeCIDRs: &nodeCIDRs{
				v4PodCIDRs: mustNewCIDRs("10.10.0.0/24"),
				v6PodCIDRs: mustNewCIDRs("fd00::/80"),
			},
			wantAllocated: true,
			wantErr:       nil,
		},
		{
			name: "test-3 - the v6 allocator is full!",
			testSetup: func() *fields {
				allocateNextCallsv4 = 0
				releaseCallsv4 = 0
				return &fields{
					v4ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{
							OnAllocateNext: func() (ipNet *net.IPNet, err error) {
								allocateNextCallsv4++
								return mustNewCIDRs("10.10.0.0/24")[0], nil
							},
							OnRelease: func(cidr *net.IPNet) error {
								require.Equal(t, mustNewCIDRs("10.10.0.0/24")[0], cidr)
								releaseCallsv4++
								return nil
							},
							OnIsFull: func() bool {
								return false
							},
							OnInRange: func(cidr *net.IPNet) bool {
								require.Equal(t, mustNewCIDRs("10.10.0.0/24")[0], cidr)
								return true
							},
						},
					},
					v6ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{
							OnIsFull: func() bool {
								return true
							},
							OnInRange: func(cidr *net.IPNet) bool {
								require.Equal(t, mustNewCIDRs("10.10.0.0/24")[0], cidr)
								return true
							},
						},
					},
					nodes: map[string]*nodeCIDRs{},
				}
			},
			testPostRun: func(fields *fields) {
				require.Equal(t, map[string]*nodeCIDRs{}, fields.nodes)
				require.Equal(t, 1, allocateNextCallsv4)
				require.Equal(t, 1, releaseCallsv4)
			},
			args: args{
				nodeName: "node-1",
			},
			wantAllocated: false,
			wantErr:       &ErrAllocatorFull{},
		},
		{
			name: "test-4 - no allocators!",
			testSetup: func() *fields {
				return &fields{
					v4ClusterCIDRs: []cidralloc.CIDRAllocator{},
					nodes:          map[string]*nodeCIDRs{},
				}
			},
			args: args{
				nodeName: "node-1",
			},
			wantAllocated: false,
			wantErr: ErrNoAllocators{
				name: "node-1",
				v4:   "[]",
				v6:   "[]",
			},
		},
	}

	for _, tt := range tests {
		tt.fields = tt.testSetup()
		n := &NodesPodCIDRManager{
			logger:           hivetest.Logger(t),
			v4CIDRAllocators: tt.fields.v4ClusterCIDRs,
			v6CIDRAllocators: tt.fields.v6ClusterCIDRs,
			nodes:            tt.fields.nodes,
		}
		nodeCIDRs, gotAllocated, err := n.allocateNext(tt.args.nodeName)
		require.Equal(t, tt.wantErr, err, "Test Name: %s", tt.name)
		require.Equal(t, tt.nodeCIDRs, nodeCIDRs, "Test Name: %s", tt.name)
		require.Equal(t, tt.wantAllocated, gotAllocated, "Test Name: %s", tt.name)

		if tt.testPostRun != nil {
			tt.testPostRun(tt.fields)
		}
	}
}

func TestNodesPodCIDRManager_releaseIPNets(t *testing.T) {
	var onReleaseCalls int

	type fields struct {
		v4ClusterCIDRs []cidralloc.CIDRAllocator
		v6ClusterCIDRs []cidralloc.CIDRAllocator
		nodes          map[string]*nodeCIDRs
	}
	type args struct {
		nodeName string
	}
	tests := []struct {
		testSetup   func() *fields
		testPostRun func(fields *fields)
		name        string
		fields      *fields
		args        args
		want        bool
	}{
		{
			name: "test-1",
			testSetup: func() *fields {
				return &fields{
					nodes: map[string]*nodeCIDRs{},
				}
			},
			args: args{
				nodeName: "node-1",
			},
			want: false,
		},
		{
			name: "test-2",
			testSetup: func() *fields {
				onReleaseCalls = 0
				cidrSet := []cidralloc.CIDRAllocator{
					&mockCIDRAllocator{
						OnRelease: func(cidr *net.IPNet) error {
							onReleaseCalls++
							require.Equal(t, mustNewCIDRs("10.0.0.0/16")[0], cidr)
							return nil
						},
						OnInRange: func(cidr *net.IPNet) bool {
							require.Equal(t, mustNewCIDRs("10.0.0.0/16")[0], cidr)
							return true
						},
					},
				}
				return &fields{
					v4ClusterCIDRs: cidrSet,
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDRs: mustNewCIDRs("10.0.0.0/16"),
						},
					},
				}
			},
			testPostRun: func(fields *fields) {
				require.Empty(t, fields.nodes)
				require.Equal(t, 1, onReleaseCalls)
			},
			args: args{
				nodeName: "node-1",
			},
			want: true,
		},
		{
			name: "test-3",
			testSetup: func() *fields {
				onReleaseCalls = 0
				cidrSet := []cidralloc.CIDRAllocator{
					&mockCIDRAllocator{
						OnRelease: func(cidr *net.IPNet) error {
							onReleaseCalls++
							require.Equal(t, mustNewCIDRs("fd00::/80")[0], cidr)
							return nil
						},
						OnInRange: func(cidr *net.IPNet) bool {
							require.Equal(t, mustNewCIDRs("fd00::/80")[0], cidr)
							return true
						},
					},
				}
				return &fields{
					v6ClusterCIDRs: cidrSet,
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v6PodCIDRs: mustNewCIDRs("fd00::/80"),
						},
					},
				}
			},
			testPostRun: func(fields *fields) {
				require.Empty(t, fields.nodes)
				require.Equal(t, 1, onReleaseCalls)
			},
			args: args{
				nodeName: "node-1",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		tt.fields = tt.testSetup()
		n := &NodesPodCIDRManager{
			logger:           hivetest.Logger(t),
			v4CIDRAllocators: tt.fields.v4ClusterCIDRs,
			v6CIDRAllocators: tt.fields.v6ClusterCIDRs,
			nodes:            tt.fields.nodes,
		}
		got := n.releaseIPNets(tt.args.nodeName)
		require.Equal(t, tt.want, got, "Test Name: %s", tt.name)

		if tt.testPostRun != nil {
			tt.testPostRun(tt.fields)
		}
	}
}

func Test_parsePodCIDRs(t *testing.T) {
	type args struct {
		podCIDRs []string
	}
	tests := []struct {
		name    string
		args    args
		want    *nodeCIDRs
		wantErr bool
	}{
		{
			name: "test-1",
			args: args{
				podCIDRs: []string{
					"1.1.1.1/20",
					"1.1.1.1/28",
				},
			},
			want: &nodeCIDRs{
				v4PodCIDRs: mustNewCIDRs("1.1.1.1/20", "1.1.1.1/28"),
			},
			wantErr: false,
		},
		{
			name: "test-2",
			args: args{
				podCIDRs: []string{
					"fd00::1/64",
					"fd01::/64",
				},
			},
			want: &nodeCIDRs{
				v6PodCIDRs: mustNewCIDRs("fd00::1/64", "fd01::/64"),
			},
			wantErr: false,
		},
		{
			name: "test-3",
			args: args{
				podCIDRs: []string{
					"fd00::1/64",
					"1.1.1.1/28",
				},
			},
			want: &nodeCIDRs{
				v4PodCIDRs: mustNewCIDRs("1.1.1.0/28"),
				v6PodCIDRs: mustNewCIDRs("fd00::/64"),
			},
			wantErr: false,
		},
		{
			name: "test-4",
			args: args{
				podCIDRs: []string{
					"fd00::1/64",
				},
			},
			want: &nodeCIDRs{
				v6PodCIDRs: mustNewCIDRs("fd00::/64"),
			},
			wantErr: false,
		},
		{
			name: "test-5",
			args: args{
				podCIDRs: []string{
					"1.1.1.1/28",
				},
			},
			want: &nodeCIDRs{
				v4PodCIDRs: mustNewCIDRs("1.1.1.0/28"),
			},
			wantErr: false,
		},
		{
			name: "test-6",
			args: args{
				podCIDRs: []string{
					"1.1.1.1/280",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		nodeCIDRs, err := parsePodCIDRs(tt.args.podCIDRs)
		gotErr := err != nil
		require.Equal(t, tt.wantErr, gotErr, fmt.Sprintf("Test Name: %s", tt.name), gotErr)
		require.Equal(t, tt.want, nodeCIDRs, "Test Name: %s", tt.name)
	}
}

func Test_syncToK8s(t *testing.T) {
	const k8sOpGet = k8sOp(99)

	calls := map[k8sOp]int{}
	type args struct {
		nodeGetter       *k8sNodeMock
		ciliumNodesToK8s map[string]*ciliumNodeK8sOp
	}
	tests := []struct {
		testSetup   func()
		testPostRun func(args *args)
		name        string
		args        *args
		wantErr     bool
	}{
		{
			name: "test-1 - create a Cilium Node",
			testSetup: func() {
				calls = map[k8sOp]int{}
			},
			args: &args{
				nodeGetter: &k8sNodeMock{
					OnCreate: func(n *v2.CiliumNode) (node *v2.CiliumNode, err error) {
						calls[k8sOpCreate]++
						require.Equal(t, &v2.CiliumNode{
							ObjectMeta: metav1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						}, n)
						return nil, nil
					},
				},
				ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: metav1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						},
						op: k8sOpCreate,
					},
				},
			},
			testPostRun: func(args *args) {
				require.Equal(t, map[k8sOp]int{
					k8sOpCreate: 1,
				}, calls)
				require.Equal(t, map[string]*ciliumNodeK8sOp{}, args.ciliumNodesToK8s)
			},
			wantErr: false,
		},
		{
			name: "test-2 - create a Cilium Node but it already exists so the next operation should be an update",
			testSetup: func() {
				calls = map[k8sOp]int{}
			},
			args: &args{
				nodeGetter: &k8sNodeMock{
					OnCreate: func(n *v2.CiliumNode) (node *v2.CiliumNode, err error) {
						calls[k8sOpCreate]++
						require.Equal(t, &v2.CiliumNode{
							ObjectMeta: metav1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						}, n)
						return nil, &k8sErrors.StatusError{
							ErrStatus: metav1.Status{
								Reason: metav1.StatusReasonAlreadyExists,
							}}
					},
					OnGet: func(nodeName string) (node *v2.CiliumNode, err error) {
						calls[k8sOpGet]++
						require.Equal(t, "node-1", nodeName)
						return &v2.CiliumNode{
							ObjectMeta: metav1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						}, nil
					},
				},
				ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: metav1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						},
						op: k8sOpCreate,
					},
				},
			},
			testPostRun: func(args *args) {
				require.Equal(t, map[k8sOp]int{
					k8sOpCreate: 1,
					k8sOpGet:    1,
				}, calls)
				require.Equal(t, map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: metav1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						},
						op: k8sOpUpdate,
					}}, args.ciliumNodesToK8s)
			},
			wantErr: true,
		},
		{
			name: "test-3 - create a Cilium Node but it already exists. When performing a get" +
				" the node was removed upstream." +
				" The operator is listening for node events, if the node is removed," +
				" a delete event will eventually remove the node from the list of nodes that" +
				" need to be synchronized with k8s",
			testSetup: func() {
				calls = map[k8sOp]int{}
			},
			args: &args{
				nodeGetter: &k8sNodeMock{
					OnCreate: func(n *v2.CiliumNode) (node *v2.CiliumNode, err error) {
						calls[k8sOpCreate]++
						require.Equal(t, &v2.CiliumNode{
							ObjectMeta: metav1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						}, n)
						return nil, &k8sErrors.StatusError{
							ErrStatus: metav1.Status{
								Reason: metav1.StatusReasonAlreadyExists,
							}}
					},
					OnGet: func(nodeName string) (node *v2.CiliumNode, err error) {
						calls[k8sOpGet]++
						require.Equal(t, "node-1", nodeName)
						return nil, &k8sErrors.StatusError{
							ErrStatus: metav1.Status{
								Reason: metav1.StatusReasonNotFound,
							}}
					},
				},
				ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: metav1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						},
						op: k8sOpCreate,
					},
				},
			},
			testPostRun: func(args *args) {
				require.Equal(t, map[k8sOp]int{
					k8sOpCreate: 1,
					k8sOpGet:    1,
				}, calls)
				require.Equal(t, map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: metav1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						},
						op: k8sOpCreate,
					},
				}, args.ciliumNodesToK8s)
			},
			wantErr: true,
		},
		{
			name: "test-4 - try to update a node that no longer exists. We should stop" +
				" trying to update it again.",
			testSetup: func() {
				calls = map[k8sOp]int{}
			},
			args: &args{
				nodeGetter: &k8sNodeMock{
					OnUpdate: func(_, n *v2.CiliumNode) (node *v2.CiliumNode, err error) {
						calls[k8sOpUpdate]++
						require.Equal(t, &v2.CiliumNode{
							ObjectMeta: metav1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						}, n)
						return nil, &k8sErrors.StatusError{
							ErrStatus: metav1.Status{
								Reason: metav1.StatusReasonNotFound,
							}}
					},
				},
				ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: metav1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						},
						op: k8sOpUpdate,
					},
				},
			},
			testPostRun: func(args *args) {
				require.Equal(t, map[k8sOp]int{
					k8sOpUpdate: 1,
				}, calls)
				require.Equal(t, map[string]*ciliumNodeK8sOp{}, args.ciliumNodesToK8s)
			},
			wantErr: false,
		},
		{
			name: "test-5 - try update the status only",
			testSetup: func() {
				calls = map[k8sOp]int{}
			},
			args: &args{
				nodeGetter: &k8sNodeMock{
					OnUpdateStatus: func(_, n *v2.CiliumNode) (node *v2.CiliumNode, err error) {
						calls[k8sOpUpdateStatus]++
						require.Equal(t, &v2.CiliumNode{
							ObjectMeta: metav1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						}, n)
						return nil, nil
					},
				},
				ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: metav1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						},
						op: k8sOpUpdateStatus,
					},
				},
			},
			testPostRun: func(args *args) {
				require.Equal(t, map[k8sOp]int{
					k8sOpUpdateStatus: 1,
				}, calls)
				require.Equal(t, map[string]*ciliumNodeK8sOp{}, args.ciliumNodesToK8s)
			},
			wantErr: false,
		},
		{
			name: "test-6 - delete node and ignore error if node was not found",
			testSetup: func() {
				calls = map[k8sOp]int{}
			},
			args: &args{
				nodeGetter: &k8sNodeMock{
					// k8sOpDelete calls Get(), instead of Delete()
					OnGet: func(nodeName string) (*v2.CiliumNode, error) {
						calls[k8sOpDelete]++
						require.Equal(t, "node-1", nodeName)
						return nil, k8sErrors.NewNotFound(schema.GroupResource{}, nodeName)
					},
				},
				ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{
					"node-1": {
						op: k8sOpDelete,
					},
				},
			},
			testPostRun: func(args *args) {
				require.Equal(t, map[k8sOp]int{
					k8sOpDelete: 1,
				}, calls)
				require.Equal(t, map[string]*ciliumNodeK8sOp{}, args.ciliumNodesToK8s)
			},
			wantErr: false,
		},
		{
			name: "test-7 - delete node and do not ignore any other error besides node was not found",
			testSetup: func() {
				calls = map[k8sOp]int{}
			},
			args: &args{
				nodeGetter: &k8sNodeMock{
					// k8sOpDelete calls Get(), instead of Delete()
					OnGet: func(nodeName string) (*v2.CiliumNode, error) {
						calls[k8sOpDelete]++
						require.Equal(t, "node-1", nodeName)
						return nil, k8sErrors.NewTimeoutError("", 0)
					},
				},
				ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{
					"node-1": {
						op: k8sOpDelete,
					},
				},
			},
			testPostRun: func(args *args) {
				require.Equal(t, map[k8sOp]int{
					k8sOpDelete: 1,
				}, calls)
				require.Equal(t, map[string]*ciliumNodeK8sOp{
					"node-1": {
						op: k8sOpDelete,
					},
				}, args.ciliumNodesToK8s)
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt.testSetup()
		gotErr := syncToK8s(hivetest.Logger(t), tt.args.nodeGetter, tt.args.ciliumNodesToK8s) != nil
		require.Equal(t, tt.wantErr, gotErr, "Test Name: %s", tt.name)
		if tt.testPostRun != nil {
			tt.testPostRun(tt.args)
		}
	}
}

func TestNewNodesPodCIDRManager(t *testing.T) {
	name := "node-1"
	ciliumNode := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	// `nm` will call Get() on a delete op, because we don't actually delete.
	onGetCalls := 0
	wasDeletedOnce := make(chan struct{})
	nodeGetter := &k8sNodeMock{
		OnGet: func(nodeName string) (*v2.CiliumNode, error) {
			onGetCalls++
			if onGetCalls == 1 {
				close(wasDeletedOnce)
			} else if onGetCalls > 1 {
				return ciliumNode, nil
			}
			return nil, k8sErrors.NewNotFound(schema.GroupResource{}, nodeName)
		},
	}
	updateK8sInterval = time.Second

	nm := NewNodesPodCIDRManager(hivetest.Logger(t), nil, nil, nodeGetter, nil)
	nm.k8sReSync.Trigger()
	// Waiting 2 times the amount of time set in the trigger
	time.Sleep(2 * time.Second)
	require.Equal(t, 0, onGetCalls)

	nm.Mutex.Lock()
	nm.ciliumNodesToK8s = map[string]*ciliumNodeK8sOp{
		name: {
			op: k8sOpDelete,
		},
	}
	nm.Mutex.Unlock()
	select {
	case <-wasDeletedOnce:
	case <-time.Tick(5 * time.Second):
		t.Error("The controller should have received the delete operation by now")
	}
	nm.Mutex.Lock()
	require.Equal(t, map[string]*ciliumNodeK8sOp{}, nm.ciliumNodesToK8s)
	nm.Mutex.Unlock()
	// Wait for the controller to try more times, the number of deletedCalls
	// should not be different because we have successfully processed the
	// deletion operation of the node.
	time.Sleep(2 * time.Second)
	require.Equal(t, 1, onGetCalls)
}
