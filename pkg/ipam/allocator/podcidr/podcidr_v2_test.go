// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package podcidr

import (
	"net"

	"github.com/cilium/cilium/pkg/ipam/allocator/clusterpool/cidralloc"

	. "github.com/cilium/checkmate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/checker"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func (s *PodCIDRSuite) TestNodesPodCIDRManager_allocateNodeV2(c *C) {
	type fields struct {
		v4ClusterCIDRs      []cidralloc.CIDRAllocator
		v6ClusterCIDRs      []cidralloc.CIDRAllocator
		nodes               map[string]*nodeCIDRs
		canAllocatePodCIDRs bool
		nodesToAllocate     map[string]*v2.CiliumNode
	}
	type args struct {
		node *v2.CiliumNode
	}
	tests := []struct {
		testSetup        func() *fields
		testPostRun      func(fields *fields)
		name             string
		fields           *fields
		args             args
		wantCiliumNode   *v2.CiliumNode
		wantUpdateSpec   bool
		wantUpdateStatus bool
		wantErr          error
	}{
		{
			name: "test occupy, release, and allocate v4",
			testSetup: func() *fields {
				return &fields{
					v4ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{
							OnIsFull: func() bool {
								return false
							},
							OnAllocateNext: func() (*net.IPNet, error) {
								return mustNewCIDRs("10.10.3.0/24")[0], nil
							},
							OnOccupy: func(cidr *net.IPNet) error {
								c.Assert(cidr.String(), checker.DeepEquals, "10.10.2.0/24")
								return nil
							},
							OnIsAllocated: func(_ *net.IPNet) (bool, error) {
								return false, nil
							},
							OnInRange: func(_ *net.IPNet) bool {
								return true
							},
							OnRelease: func(cidr *net.IPNet) error {
								c.Assert(cidr.String(), checker.DeepEquals, "10.10.1.0/24")
								return nil
							},
						},
					},
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDRs: mustNewCIDRs("10.10.1.0/24"),
						},
					},
					nodesToAllocate:     map[string]*v2.CiliumNode{},
					canAllocatePodCIDRs: true,
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDRs: mustNewCIDRs("10.10.2.0/24", "10.10.3.0/24"),
					},
				})
			},
			args: args{
				node: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
					Spec: v2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							PodCIDRs: []string{
								"10.10.1.0/24",
								"10.10.2.0/24",
							},
						},
					},
					Status: v2.NodeStatus{
						IPAM: ipamTypes.IPAMStatus{
							PodCIDRs: ipamTypes.PodCIDRMap{
								"10.10.1.0/24": {Status: ipamTypes.PodCIDRStatusReleased},
								"10.10.2.0/24": {Status: ipamTypes.PodCIDRStatusDepleted},
							},
						},
					},
				},
			},
			wantCiliumNode: &v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
				Spec: v2.NodeSpec{
					IPAM: ipamTypes.IPAMSpec{
						PodCIDRs: []string{
							"10.10.2.0/24",
							"10.10.3.0/24",
						},
					},
				},
				Status: v2.NodeStatus{
					IPAM: ipamTypes.IPAMStatus{
						PodCIDRs: ipamTypes.PodCIDRMap{
							"10.10.1.0/24": {Status: ipamTypes.PodCIDRStatusReleased},
							"10.10.2.0/24": {Status: ipamTypes.PodCIDRStatusDepleted},
						},
					},
				},
			},
			wantUpdateStatus: false,
			wantUpdateSpec:   true,
			wantErr:          nil,
		},
		{
			name: "test allocate v4 and occupy v6 from status",
			testSetup: func() *fields {
				return &fields{
					v4ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{
							OnIsFull: func() bool {
								return false
							},
							OnAllocateNext: func() (*net.IPNet, error) {
								return mustNewCIDRs("10.10.1.0/24")[0], nil
							},
						},
					},
					v6ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{
							OnOccupy: func(_ *net.IPNet) error {
								return nil
							},
							OnIsAllocated: func(_ *net.IPNet) (bool, error) {
								return false, nil
							},
							OnIsFull: func() bool {
								return false
							},
							OnInRange: func(cidr *net.IPNet) bool {
								return true
							},
						},
					},
					nodes:               map[string]*nodeCIDRs{},
					nodesToAllocate:     map[string]*v2.CiliumNode{},
					canAllocatePodCIDRs: true,
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDRs: mustNewCIDRs("10.10.1.0/24"),
						v6PodCIDRs: mustNewCIDRs("fd00::/80", "fd01::/80"),
					},
				})
			},
			args: args{
				node: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
					Spec: v2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							PodCIDRs: []string{},
						},
					},
					Status: v2.NodeStatus{
						IPAM: ipamTypes.IPAMStatus{
							PodCIDRs: ipamTypes.PodCIDRMap{
								"fd00::/80": {Status: ipamTypes.PodCIDRStatusInUse},
								"fd01::/80": {Status: ipamTypes.PodCIDRStatusDepleted},
							},
						},
					},
				},
			},
			wantCiliumNode: &v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
				Spec: v2.NodeSpec{
					IPAM: ipamTypes.IPAMSpec{
						PodCIDRs: []string{
							"10.10.1.0/24",
							"fd00::/80", "fd01::/80",
						},
					},
				},
				Status: v2.NodeStatus{
					IPAM: ipamTypes.IPAMStatus{
						PodCIDRs: ipamTypes.PodCIDRMap{
							"fd00::/80": {Status: ipamTypes.PodCIDRStatusInUse},
							"fd01::/80": {Status: ipamTypes.PodCIDRStatusDepleted},
						},
					},
				},
			},
			wantUpdateStatus: false,
			wantUpdateSpec:   true,
			wantErr:          nil,
		},
		{
			name: "test occupy depleted but delay allocation v4",
			testSetup: func() *fields {
				return &fields{
					canAllocatePodCIDRs: false,
					v4ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{
							OnOccupy: func(_ *net.IPNet) error {
								return nil
							},
							OnIsAllocated: func(_ *net.IPNet) (bool, error) {
								return false, nil
							},
							OnIsFull: func() bool {
								return false
							},
							OnInRange: func(cidr *net.IPNet) bool {
								return true
							},
						},
					},
					nodes:           map[string]*nodeCIDRs{},
					nodesToAllocate: map[string]*v2.CiliumNode{},
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDRs: mustNewCIDRs("10.10.1.0/24"),
					},
				})
				c.Assert(fields.nodesToAllocate, checker.DeepEquals, map[string]*v2.CiliumNode{
					"node-1": {
						ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
						Spec: v2.NodeSpec{
							IPAM: ipamTypes.IPAMSpec{
								PodCIDRs: []string{"10.10.1.0/24"},
							},
						},
						Status: v2.NodeStatus{
							IPAM: ipamTypes.IPAMStatus{
								PodCIDRs: ipamTypes.PodCIDRMap{
									"10.10.1.0/24": {Status: ipamTypes.PodCIDRStatusDepleted},
									"10.10.2.0/24": {Status: ipamTypes.PodCIDRStatusReleased},
								},
							},
						},
					},
				})
			},
			args: args{
				node: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
					Spec: v2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							PodCIDRs: []string{"10.10.1.0/24"},
						},
					},
					Status: v2.NodeStatus{
						IPAM: ipamTypes.IPAMStatus{
							PodCIDRs: ipamTypes.PodCIDRMap{
								"10.10.1.0/24": {Status: ipamTypes.PodCIDRStatusDepleted},
								"10.10.2.0/24": {Status: ipamTypes.PodCIDRStatusReleased},
							},
						},
					},
				},
			},
			wantCiliumNode: &v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
				Spec: v2.NodeSpec{
					IPAM: ipamTypes.IPAMSpec{
						PodCIDRs: []string{"10.10.1.0/24"},
					},
				},
				Status: v2.NodeStatus{
					IPAM: ipamTypes.IPAMStatus{
						PodCIDRs: ipamTypes.PodCIDRMap{
							"10.10.1.0/24": {Status: ipamTypes.PodCIDRStatusDepleted},
							"10.10.2.0/24": {Status: ipamTypes.PodCIDRStatusReleased},
						},
					},
				},
			},
			wantUpdateStatus: false,
			wantUpdateSpec:   true,
			wantErr:          nil,
		},
		{
			name: "test allocate and occupy v4 errors, but allocate and occupy v6 succeeds",
			testSetup: func() *fields {
				return &fields{
					v4ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{
							OnIsFull: func() bool {
								return true
							},
							OnAllocateNext: func() (*net.IPNet, error) {
								return nil, &ErrAllocatorFull{}
							},
							OnInRange: func(_ *net.IPNet) bool {
								return true
							},
						},
					},
					v6ClusterCIDRs: []cidralloc.CIDRAllocator{
						&mockCIDRAllocator{
							OnIsFull: func() bool {
								return false
							},
							OnAllocateNext: func() (*net.IPNet, error) {
								return mustNewCIDRs("fd01::/80")[0], nil
							},
							OnOccupy: func(cidr *net.IPNet) error {
								c.Assert(cidr.String(), checker.DeepEquals, "fd00::/80")
								return nil
							},
							OnIsAllocated: func(_ *net.IPNet) (bool, error) {
								return false, nil
							},
							OnInRange: func(_ *net.IPNet) bool {
								return true
							},
						},
					},
					nodes:               map[string]*nodeCIDRs{},
					nodesToAllocate:     map[string]*v2.CiliumNode{},
					canAllocatePodCIDRs: true,
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{
					"node-1": {
						v6PodCIDRs: mustNewCIDRs("fd00::/80", "fd01::/80"),
					},
				})
			},
			args: args{
				node: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
					Status: v2.NodeStatus{
						IPAM: ipamTypes.IPAMStatus{
							PodCIDRs: ipamTypes.PodCIDRMap{
								"fd00::/80": ipamTypes.PodCIDRMapEntry{
									Status: ipamTypes.PodCIDRStatusDepleted,
								},
								"10.10.0.0/24": ipamTypes.PodCIDRMapEntry{
									Status: ipamTypes.PodCIDRStatusDepleted,
								},
							},
						},
					},
				},
			},
			wantCiliumNode: &v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
				Spec: v2.NodeSpec{
					IPAM: ipamTypes.IPAMSpec{
						PodCIDRs: []string{
							"fd00::/80", "fd01::/80",
						},
					},
				},
				Status: v2.NodeStatus{
					IPAM: ipamTypes.IPAMStatus{
						PodCIDRs: ipamTypes.PodCIDRMap{
							"fd00::/80": ipamTypes.PodCIDRMapEntry{
								Status: ipamTypes.PodCIDRStatusDepleted,
							},
							"10.10.0.0/24": ipamTypes.PodCIDRMapEntry{
								Status: ipamTypes.PodCIDRStatusDepleted,
							},
						},
						OperatorStatus: ipamTypes.OperatorStatus{
							Error: "allocator clusterCIDR: 10.0.0.0/24, nodeMask: 24 full; allocator full",
						},
					},
				},
			},
			wantUpdateStatus: true,
			wantUpdateSpec:   true,
			wantErr:          nil,
		},
	}

	for _, tt := range tests {
		tt.fields = tt.testSetup()
		n := &NodesPodCIDRManager{
			v4CIDRAllocators:    tt.fields.v4ClusterCIDRs,
			v6CIDRAllocators:    tt.fields.v6ClusterCIDRs,
			nodes:               tt.fields.nodes,
			nodesToAllocate:     tt.fields.nodesToAllocate,
			canAllocatePodCIDRs: tt.fields.canAllocatePodCIDRs,
		}
		cn, updateSpec, updateStatus, err := n.allocateNodeV2(tt.args.node)
		c.Assert(err, checker.DeepEquals, tt.wantErr, Commentf("Test Name: %s", tt.name))
		c.Assert(updateSpec, checker.DeepEquals, tt.wantUpdateSpec, Commentf("Test Name: %s", tt.name))
		c.Assert(updateStatus, checker.DeepEquals, tt.wantUpdateStatus, Commentf("Test Name: %s", tt.name))
		c.Assert(cn, checker.DeepEquals, tt.wantCiliumNode, Commentf("Test Name: %s", tt.name))

		if tt.testPostRun != nil {
			tt.testPostRun(tt.fields)
		}
	}
}
