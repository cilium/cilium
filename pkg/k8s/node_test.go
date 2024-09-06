// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/cidr"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	nodeAddressing "github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

func TestParseNode(t *testing.T) {
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
				annotation.V4CIDRName:     "10.254.0.0/16",
				annotation.V6CIDRName:     "f00d:aaaa:bbbb:cccc:dddd:eeee::/112",
				annotation.CiliumHostIP:   "10.254.9.9",
				annotation.CiliumHostIPv6: "fd00:10:244:1::8ace",
				"cilium.io/foo":           "value",
				"qux.cilium.io/foo":       "value",
				"fr3d.qux.cilium.io/foo":  "value",
				"other.whatever.io/foo":   "value",
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
	require.Equal(t, "node1", n.Name)
	require.NotNil(t, n.IPv4AllocCIDR)
	require.Equal(t, "10.1.0.0/16", n.IPv4AllocCIDR.String())
	require.NotNil(t, n.IPv6AllocCIDR)
	require.Equal(t, "f00d:aaaa:bbbb:cccc:dddd:eeee::/112", n.IPv6AllocCIDR.String())
	require.Equal(t, "m5.xlarge", n.Labels["type"])
	require.Equal(t, 2, len(n.IPAddresses))
	require.Equal(t, "10.254.9.9", n.IPAddresses[0].IP.String())
	require.Equal(t, nodeAddressing.NodeCiliumInternalIP, n.IPAddresses[0].Type)
	require.Equal(t, "fd00:10:244:1::8ace", n.IPAddresses[1].IP.String())
	require.Equal(t, nodeAddressing.NodeCiliumInternalIP, n.IPAddresses[1].Type)

	for _, key := range []string{"cilium.io/foo", "qux.cilium.io/foo", "fr3d.qux.cilium.io/foo"} {
		require.Equal(t, "value", n.Annotations[key])
	}
	require.NotContains(t, n.Annotations, "other.whatever.io/foo")

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
	require.Equal(t, "node2", n.Name)
	require.NotNil(t, n.IPv4AllocCIDR)
	require.Equal(t, "10.1.0.0/16", n.IPv4AllocCIDR.String())
	require.Nil(t, n.IPv6AllocCIDR)

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
	require.Equal(t, "node2", n.Name)
	require.NotNil(t, n.IPv4AllocCIDR)
	require.Equal(t, "10.254.0.0/16", n.IPv4AllocCIDR.String())
	require.NotNil(t, n.IPv6AllocCIDR)
	require.Equal(t, "f00d:aaaa:bbbb:cccc:dddd:eeee::/112", n.IPv6AllocCIDR.String())

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
	require.Equal(t, "node2", n.Name)
	require.NotNil(t, n.IPv4AllocCIDR)
	require.Equal(t, "10.1.0.0/16", n.IPv4AllocCIDR.String())
	require.NotNil(t, n.IPv6AllocCIDR)
	require.Equal(t, "f00d:aaaa:bbbb:cccc:dddd:eeee::/112", n.IPv6AllocCIDR.String())

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
	require.Equal(t, "node2", n.Name)
	require.NotNil(t, n.IPv4AllocCIDR)
	require.Equal(t, "10.1.0.0/16", n.IPv4AllocCIDR.String())
	require.Equal(t, len(expected), len(n.IPAddresses))
	addrsFound := 0
	for _, addr := range n.IPAddresses {
		for _, expect := range expected {
			if addr.IP.String() == expect {
				addrsFound++
			}
		}
	}
	require.Equal(t, len(expected), addrsFound)
}

func TestParseNodeWithoutAnnotations(t *testing.T) {
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
				annotation.V4CIDRName:    "10.254.0.0/16",
				annotation.V6CIDRName:    "f00d:aaaa:bbbb:cccc:dddd:eeee::/112",
				"cilium.io/foo":          "value",
				"qux.cilium.io/foo":      "value",
				"fr3d.qux.cilium.io/foo": "value",
				"other.whatever.io/foo":  "value",
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
	require.Equal(t, "node1", n.Name)
	require.NotNil(t, n.IPv4AllocCIDR)
	require.Equal(t, "10.1.0.0/16", n.IPv4AllocCIDR.String())
	require.Nil(t, n.IPv6AllocCIDR)
	require.Equal(t, "m5.xlarge", n.Labels["type"])

	for _, key := range []string{"cilium.io/foo", "qux.cilium.io/foo", "fr3d.qux.cilium.io/foo"} {
		require.Equal(t, "value", n.Annotations[key])
	}
	require.NotContains(t, n.Annotations, "other.whatever.io/foo")

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
	require.Equal(t, "node2", n.Name)
	require.Nil(t, n.IPv4AllocCIDR)
	require.NotNil(t, n.IPv6AllocCIDR)
	require.Equal(t, "f00d:aaaa:bbbb:cccc:dddd:eeee::/112", n.IPv6AllocCIDR.String())
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
			require.EqualValues(t, tt.want, res)
		})
	}
}

func TestParseNodeWithService(t *testing.T) {
	prevAnnotateK8sNode := option.Config.AnnotateK8sNode
	option.Config.AnnotateK8sNode = false
	defer func() {
		option.Config.AnnotateK8sNode = prevAnnotateK8sNode
	}()

	k8sNode := &slim_corev1.Node{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: "node1",
			Labels: map[string]string{
				annotation.ServiceNodeExposure: "beefy",
			},
		},
		Spec: slim_corev1.NodeSpec{
			PodCIDR: "10.1.0.0/16",
		},
	}

	n1 := ParseNode(k8sNode, source.Local)
	require.Equal(t, "node1", n1.Name)
	require.NotNil(t, n1.IPv4AllocCIDR)
	require.Equal(t, "10.1.0.0/16", n1.IPv4AllocCIDR.String())
	require.Equal(t, "beefy", n1.Labels[annotation.ServiceNodeExposure])

	k8sNode = &slim_corev1.Node{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: "node2",
		},
		Spec: slim_corev1.NodeSpec{
			PodCIDR: "10.2.0.0/16",
		},
	}

	n2 := ParseNode(k8sNode, source.Local)
	require.Equal(t, "node2", n2.Name)
	require.NotNil(t, n2.IPv4AllocCIDR)
	require.Equal(t, "10.2.0.0/16", n2.IPv4AllocCIDR.String())
	require.Equal(t, "", n2.Labels[annotation.ServiceNodeExposure])

	objMeta := slim_metav1.ObjectMeta{
		Name:      "foo",
		Namespace: "bar",
		Annotations: map[string]string{
			annotation.ServiceNodeExposure: "beefy",
		},
	}
	k8sSvc := &slim_corev1.Service{
		ObjectMeta: objMeta,
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Selector: map[string]string{
				"foo": "bar",
			},
			Type: slim_corev1.ServiceTypeClusterIP,
		},
	}

	id, svc := ParseService(k8sSvc, nil)
	require.EqualValues(t, ServiceID{Namespace: "bar", Name: "foo"}, id)
	require.EqualValues(t, &Service{
		ExtTrafficPolicy:         loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy:         loadbalancer.SVCTrafficPolicyCluster,
		FrontendIPs:              []net.IP{net.ParseIP("127.0.0.1")},
		Selector:                 map[string]string{"foo": "bar"},
		Annotations:              map[string]string{annotation.ServiceNodeExposure: "beefy"},
		Ports:                    map[loadbalancer.FEPortName]*loadbalancer.L4Addr{},
		NodePorts:                map[loadbalancer.FEPortName]NodePortToFrontend{},
		LoadBalancerSourceRanges: map[string]*cidr.CIDR{},
		Type:                     loadbalancer.SVCTypeClusterIP,
	}, svc)
}
