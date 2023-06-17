// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/checker"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	nodeAddressing "github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

func (s *K8sSuite) TestParseNode(c *C) {
	prevAnnotateK8sNode := option.Config.AnnotateK8sNode
	option.Config.AnnotateK8sNode = true
	defer func() {
		option.Config.AnnotateK8sNode = prevAnnotateK8sNode
	}()

	// PodCIDR takes precedence over annotations
	k8sNode := &slim_corev1.Node{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: "node1",
			Annotations: map[string]string{
				annotation.V4CIDRName: "10.254.0.0/16",
				annotation.V6CIDRName: "f00d:aaaa:bbbb:cccc:dddd:eeee::/112",
			},
			Labels: map[string]string{
				"type": "m5.xlarge",
			},
		},
		Spec: slim_corev1.NodeSpec{
			PodCIDR: "10.1.0.0/16",
		},
	}

	n := ParseNode(k8sNode, source.Local)
	c.Assert(n.Name, Equals, "node1")
	c.Assert(n.IPv4AllocCIDR, NotNil)
	c.Assert(n.IPv4AllocCIDR.String(), Equals, "10.1.0.0/16")
	c.Assert(n.IPv6AllocCIDR, NotNil)
	c.Assert(n.IPv6AllocCIDR.String(), Equals, "f00d:aaaa:bbbb:cccc:dddd:eeee::/112")
	c.Assert(n.Labels["type"], Equals, "m5.xlarge")

	// No IPv6 annotation
	k8sNode = &slim_corev1.Node{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: "node2",
			Annotations: map[string]string{
				annotation.V4CIDRName: "10.254.0.0/16",
			},
		},
		Spec: slim_corev1.NodeSpec{
			PodCIDR: "10.1.0.0/16",
		},
	}

	n = ParseNode(k8sNode, source.Local)
	c.Assert(n.Name, Equals, "node2")
	c.Assert(n.IPv4AllocCIDR, NotNil)
	c.Assert(n.IPv4AllocCIDR.String(), Equals, "10.1.0.0/16")
	c.Assert(n.IPv6AllocCIDR, IsNil)

	// No IPv6 annotation but PodCIDR with v6
	k8sNode = &slim_corev1.Node{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: "node2",
			Annotations: map[string]string{
				annotation.V4CIDRName: "10.254.0.0/16",
			},
		},
		Spec: slim_corev1.NodeSpec{
			PodCIDR: "f00d:aaaa:bbbb:cccc:dddd:eeee::/112",
		},
	}

	n = ParseNode(k8sNode, source.Local)
	c.Assert(n.Name, Equals, "node2")
	c.Assert(n.IPv4AllocCIDR, NotNil)
	c.Assert(n.IPv4AllocCIDR.String(), Equals, "10.254.0.0/16")
	c.Assert(n.IPv6AllocCIDR, NotNil)
	c.Assert(n.IPv6AllocCIDR.String(), Equals, "f00d:aaaa:bbbb:cccc:dddd:eeee::/112")

	// No IPv4/IPv6 annotations but PodCIDRs with IPv4/IPv6
	k8sNode = &slim_corev1.Node{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: "node2",
			Annotations: map[string]string{
				annotation.V4CIDRName: "10.254.0.0/16",
			},
		},
		Spec: slim_corev1.NodeSpec{
			PodCIDR:  "10.1.0.0/16",
			PodCIDRs: []string{"10.1.0.0/16", "f00d:aaaa:bbbb:cccc:dddd:eeee::/112"},
		},
	}

	n = ParseNode(k8sNode, source.Local)
	c.Assert(n.Name, Equals, "node2")
	c.Assert(n.IPv4AllocCIDR, NotNil)
	c.Assert(n.IPv4AllocCIDR.String(), Equals, "10.1.0.0/16")
	c.Assert(n.IPv6AllocCIDR, NotNil)
	c.Assert(n.IPv6AllocCIDR.String(), Equals, "f00d:aaaa:bbbb:cccc:dddd:eeee::/112")

	// Node with multiple status addresses of the same type and family
	expected := []string{"1.2.3.4", "f00d:aaaa:bbbb:cccc:dddd:eeee:0:1", "4.3.2.1", "f00d:aaaa:bbbb:cccc:dddd:eeef:0:1"}
	notExpected := []string{"5.6.7.8", "f00d:aaaa:bbbb:cccc:dddd:aaaa::1", "8.7.6.5", "f00d:aaaa:bbbb:cccc:dddd:aaab::1"}
	k8sNode = &slim_corev1.Node{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:        "node2",
			Annotations: map[string]string{},
		},
		Spec: slim_corev1.NodeSpec{
			PodCIDR: "10.1.0.0/16",
		},
		Status: slim_corev1.NodeStatus{
			Addresses: []slim_corev1.NodeAddress{
				{
					Type:    slim_corev1.NodeInternalIP,
					Address: expected[0],
				},
				{
					Type:    slim_corev1.NodeInternalIP,
					Address: notExpected[0],
				},
				{
					Type:    slim_corev1.NodeInternalIP,
					Address: expected[1],
				},
				{
					Type:    slim_corev1.NodeInternalIP,
					Address: notExpected[1],
				},
				{
					Type:    slim_corev1.NodeExternalIP,
					Address: expected[2],
				},
				{
					Type:    slim_corev1.NodeExternalIP,
					Address: notExpected[2],
				},
				{
					Type:    slim_corev1.NodeExternalIP,
					Address: expected[3],
				},
				{
					Type:    slim_corev1.NodeExternalIP,
					Address: notExpected[3],
				},
			},
		},
	}

	n = ParseNode(k8sNode, source.Local)
	c.Assert(n.Name, Equals, "node2")
	c.Assert(n.IPv4AllocCIDR, NotNil)
	c.Assert(n.IPv4AllocCIDR.String(), Equals, "10.1.0.0/16")
	c.Assert(len(n.IPAddresses), Equals, len(expected))
	addrsFound := 0
	for _, addr := range n.IPAddresses {
		for _, expect := range expected {
			if addr.IP.String() == expect {
				addrsFound++
			}
		}
	}
	c.Assert(addrsFound, Equals, len(expected))
}

func (s *K8sSuite) TestParseNodeWithoutAnnotations(c *C) {
	prevAnnotateK8sNode := option.Config.AnnotateK8sNode
	option.Config.AnnotateK8sNode = false
	defer func() {
		option.Config.AnnotateK8sNode = prevAnnotateK8sNode
	}()

	// PodCIDR takes precedence over annotations
	k8sNode := &slim_corev1.Node{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: "node1",
			Annotations: map[string]string{
				annotation.V4CIDRName: "10.254.0.0/16",
				annotation.V6CIDRName: "f00d:aaaa:bbbb:cccc:dddd:eeee::/112",
			},
			Labels: map[string]string{
				"type": "m5.xlarge",
			},
		},
		Spec: slim_corev1.NodeSpec{
			PodCIDR: "10.1.0.0/16",
		},
	}

	n := ParseNode(k8sNode, source.Local)
	c.Assert(n.Name, Equals, "node1")
	c.Assert(n.IPv4AllocCIDR, NotNil)
	c.Assert(n.IPv4AllocCIDR.String(), Equals, "10.1.0.0/16")
	c.Assert(n.IPv6AllocCIDR, IsNil)
	c.Assert(n.Labels["type"], Equals, "m5.xlarge")

	// No IPv6 annotation but PodCIDR with v6
	k8sNode = &slim_corev1.Node{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: "node2",
			Annotations: map[string]string{
				annotation.V4CIDRName: "10.254.0.0/16",
			},
		},
		Spec: slim_corev1.NodeSpec{
			PodCIDR: "f00d:aaaa:bbbb:cccc:dddd:eeee::/112",
		},
	}

	n = ParseNode(k8sNode, source.Local)
	c.Assert(n.Name, Equals, "node2")
	c.Assert(n.IPv4AllocCIDR, IsNil)
	c.Assert(n.IPv6AllocCIDR, NotNil)
	c.Assert(n.IPv6AllocCIDR.String(), Equals, "f00d:aaaa:bbbb:cccc:dddd:eeee::/112")
}

func Test_ParseNodeAddressType(t *testing.T) {
	type args struct {
		k8sNodeType slim_corev1.NodeAddressType
	}

	type result struct {
		ciliumNodeType nodeAddressing.AddressType
		errExists      bool
	}

	tests := []struct {
		name string
		args args
		want result
	}{
		{
			name: "NodeExternalDNS",
			args: args{
				k8sNodeType: slim_corev1.NodeExternalDNS,
			},
			want: result{
				ciliumNodeType: nodeAddressing.NodeExternalDNS,
				errExists:      false,
			},
		},
		{
			name: "NodeExternalIP",
			args: args{
				k8sNodeType: slim_corev1.NodeExternalIP,
			},
			want: result{
				ciliumNodeType: nodeAddressing.NodeExternalIP,
				errExists:      false,
			},
		},
		{
			name: "NodeHostName",
			args: args{
				k8sNodeType: slim_corev1.NodeHostName,
			},
			want: result{
				ciliumNodeType: nodeAddressing.NodeHostName,
				errExists:      false,
			},
		},
		{
			name: "NodeInternalIP",
			args: args{
				k8sNodeType: slim_corev1.NodeInternalIP,
			},
			want: result{
				ciliumNodeType: nodeAddressing.NodeInternalIP,
				errExists:      false,
			},
		},
		{
			name: "NodeInternalDNS",
			args: args{
				k8sNodeType: slim_corev1.NodeInternalDNS,
			},
			want: result{
				ciliumNodeType: nodeAddressing.NodeInternalDNS,
				errExists:      false,
			},
		},
		{
			name: "invalid",
			args: args{
				k8sNodeType: slim_corev1.NodeAddressType("lololol"),
			},
			want: result{
				ciliumNodeType: nodeAddressing.AddressType("lololol"),
				errExists:      true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotNodeAddress, gotErr := ParseNodeAddressType(tt.args.k8sNodeType)
			res := result{
				ciliumNodeType: gotNodeAddress,
				errExists:      gotErr != nil,
			}
			args := []interface{}{res, tt.want}
			names := []string{"obtained", "expected"}
			if equal, err := checker.DeepEquals.Check(args, names); !equal {
				t.Errorf("Failed to ParseNodeAddressType():\n%s", err)
			}
		})
	}
}
