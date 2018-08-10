// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package node

import (
	"net"
	"testing"

	. "gopkg.in/check.v1"
	"k8s.io/api/core/v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type NodeSuite struct{}

var _ = Suite(&NodeSuite{})

func (s *NodeSuite) TestGetNodeIP(c *C) {
	n := Node{
		Name: "node-1",
		IPAddresses: []Address{
			{IP: net.ParseIP("192.0.2.3"), AddressType: v1.NodeExternalIP},
		},
	}
	ip := n.GetNodeIP(false)
	// Return the only IP present
	c.Assert(ip.Equal(net.ParseIP("192.0.2.3")), Equals, true)

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("192.0.2.3"), AddressType: v1.NodeExternalIP})
	ip = n.GetNodeIP(false)
	// The next priority should be NodeExternalIP
	c.Assert(ip.Equal(net.ParseIP("192.0.2.3")), Equals, true)

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("198.51.100.2"), AddressType: v1.NodeInternalIP})
	ip = n.GetNodeIP(false)
	// The next priority should be NodeInternalIP
	c.Assert(ip.Equal(net.ParseIP("198.51.100.2")), Equals, true)

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("2001:DB8::1"), AddressType: v1.NodeExternalIP})
	ip = n.GetNodeIP(true)
	// The next priority should be NodeExternalIP and IPv6
	c.Assert(ip.Equal(net.ParseIP("2001:DB8::1")), Equals, true)

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("2001:DB8::2"), AddressType: v1.NodeInternalIP})
	ip = n.GetNodeIP(true)
	// The next priority should be NodeInternalIP and IPv6
	c.Assert(ip.Equal(net.ParseIP("2001:DB8::2")), Equals, true)

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("198.51.100.2"), AddressType: v1.NodeInternalIP})
	ip = n.GetNodeIP(false)
	// Should still return NodeInternalIP and IPv4
	c.Assert(ip.Equal(net.ParseIP("198.51.100.2")), Equals, true)

}

func (s *NodeSuite) TestPublicAttrEquals(c *C) {
	type fields struct {
		Name          string
		Cluster       string
		IPAddresses   []Address
		IPv4AllocCIDR *net.IPNet
		IPv6AllocCIDR *net.IPNet
		dev           string
		IPv4HealthIP  net.IP
		IPv6HealthIP  net.IP
		ClusterID     int
		cluster       *clusterConfiguation
		Source        Source
	}
	type args struct {
		o *Node
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name:   "test nil equalness",
			fields: fields{},
			args:   args{o: nil},
			want:   false,
		},
		{
			name: "test equalness",
			fields: fields{
				Name:          "foo",
				Cluster:       "cluster-1",
				IPv4HealthIP:  net.ParseIP("1.1.1.1"),
				IPv6HealthIP:  net.ParseIP("fd00::1"),
				ClusterID:     1,
				Source:        FromKubernetes,
				IPAddresses:   []Address{{IP: net.ParseIP("1.1.1.1"), AddressType: v1.NodeHostName}},
				IPv4AllocCIDR: &net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0)},
				IPv6AllocCIDR: &net.IPNet{IP: net.ParseIP("fd00::1"), Mask: net.CIDRMask(64, 128)},
			},
			args: args{
				o: &Node{
					Name:          "foo",
					Cluster:       "cluster-1",
					IPv4HealthIP:  net.ParseIP("1.1.1.1"),
					IPv6HealthIP:  net.ParseIP("fd00::1"),
					ClusterID:     1,
					Source:        FromKubernetes,
					IPAddresses:   []Address{{IP: net.ParseIP("1.1.1.1"), AddressType: v1.NodeHostName}},
					IPv4AllocCIDR: &net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0)},
					IPv6AllocCIDR: &net.IPNet{IP: net.ParseIP("fd00::1"), Mask: net.CIDRMask(64, 128)},
				},
			},
			want: true,
		},
		{
			name: "test different IPAddresses length",
			fields: fields{
				Name:          "foo",
				Cluster:       "cluster-1",
				IPv4HealthIP:  net.ParseIP("1.1.1.1"),
				IPv6HealthIP:  net.ParseIP("fd00::1"),
				ClusterID:     1,
				Source:        FromKubernetes,
				IPAddresses:   []Address{{IP: net.ParseIP("1.1.1.1"), AddressType: v1.NodeHostName}},
				IPv4AllocCIDR: &net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0)},
				IPv6AllocCIDR: &net.IPNet{IP: net.ParseIP("fd00::1"), Mask: net.CIDRMask(64, 128)},
			},
			args: args{
				o: &Node{
					Name:          "foo",
					Cluster:       "cluster-1",
					IPv4HealthIP:  net.ParseIP("1.1.1.1"),
					IPv6HealthIP:  net.ParseIP("fd00::1"),
					ClusterID:     1,
					Source:        FromKubernetes,
					IPv4AllocCIDR: &net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0)},
					IPv6AllocCIDR: &net.IPNet{IP: net.ParseIP("fd00::1"), Mask: net.CIDRMask(64, 128)},
				},
			},
			want: false,
		},
		{
			name: "test different IPv4AllocCIDR",
			fields: fields{
				Name:          "foo",
				Cluster:       "cluster-1",
				IPv4HealthIP:  net.ParseIP("1.1.1.1"),
				IPv6HealthIP:  net.ParseIP("fd00::1"),
				ClusterID:     1,
				Source:        FromKubernetes,
				IPAddresses:   []Address{{IP: net.ParseIP("1.1.1.1"), AddressType: v1.NodeHostName}},
				IPv4AllocCIDR: &net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0)},
				IPv6AllocCIDR: &net.IPNet{IP: net.ParseIP("fd00::1"), Mask: net.CIDRMask(64, 128)},
			},
			args: args{
				o: &Node{
					Name:          "foo",
					Cluster:       "cluster-1",
					IPv4HealthIP:  net.ParseIP("1.1.1.1"),
					IPv6HealthIP:  net.ParseIP("fd00::1"),
					ClusterID:     1,
					Source:        FromKubernetes,
					IPAddresses:   []Address{{IP: net.ParseIP("1.1.1.0"), AddressType: v1.NodeHostName}},
					IPv6AllocCIDR: &net.IPNet{IP: net.ParseIP("fd00::1"), Mask: net.CIDRMask(64, 128)},
				},
			},
			want: false,
		},
		{
			name: "test different IPv6AllocCIDR",
			fields: fields{
				Name:          "foo",
				Cluster:       "cluster-1",
				IPv4HealthIP:  net.ParseIP("1.1.1.1"),
				IPv6HealthIP:  net.ParseIP("fd00::1"),
				ClusterID:     1,
				Source:        FromKubernetes,
				IPAddresses:   []Address{{IP: net.ParseIP("1.1.1.1"), AddressType: v1.NodeHostName}},
				IPv4AllocCIDR: &net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0)},
				IPv6AllocCIDR: &net.IPNet{IP: net.ParseIP("fd00::1"), Mask: net.CIDRMask(64, 128)},
			},
			args: args{
				o: &Node{
					Name:          "foo",
					Cluster:       "cluster-1",
					IPv4HealthIP:  net.ParseIP("1.1.1.1"),
					IPv6HealthIP:  net.ParseIP("fd00::1"),
					ClusterID:     1,
					Source:        FromKubernetes,
					IPAddresses:   []Address{{IP: net.ParseIP("1.1.1.0"), AddressType: v1.NodeHostName}},
					IPv4AllocCIDR: &net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0)},
				},
			},
			want: false,
		},
		{
			name: "test different name",
			fields: fields{
				Name:          "foo",
				Cluster:       "cluster-1",
				IPv4HealthIP:  net.ParseIP("1.1.1.1"),
				IPv6HealthIP:  net.ParseIP("fd00::1"),
				ClusterID:     1,
				Source:        FromKubernetes,
				IPAddresses:   []Address{{IP: net.ParseIP("1.1.1.1"), AddressType: v1.NodeHostName}},
				IPv4AllocCIDR: &net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0)},
				IPv6AllocCIDR: &net.IPNet{IP: net.ParseIP("fd00::1"), Mask: net.CIDRMask(64, 128)},
			},
			args: args{
				o: &Node{
					Cluster:       "cluster-1",
					IPv4HealthIP:  net.ParseIP("1.1.1.1"),
					IPv6HealthIP:  net.ParseIP("fd00::1"),
					ClusterID:     1,
					Source:        FromKubernetes,
					IPAddresses:   []Address{{IP: net.ParseIP("1.1.1.0"), AddressType: v1.NodeHostName}},
					IPv4AllocCIDR: &net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0)},
					IPv6AllocCIDR: &net.IPNet{IP: net.ParseIP("fd00::1"), Mask: net.CIDRMask(64, 128)},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		n := &Node{
			Name:          tt.fields.Name,
			Cluster:       tt.fields.Cluster,
			IPAddresses:   tt.fields.IPAddresses,
			IPv4AllocCIDR: tt.fields.IPv4AllocCIDR,
			IPv6AllocCIDR: tt.fields.IPv6AllocCIDR,
			dev:           tt.fields.dev,
			IPv4HealthIP:  tt.fields.IPv4HealthIP,
			IPv6HealthIP:  tt.fields.IPv6HealthIP,
			ClusterID:     tt.fields.ClusterID,
			cluster:       tt.fields.cluster,
			Source:        tt.fields.Source,
		}
		c.Logf(tt.name)
		got := n.PublicAttrEquals(tt.args.o)
		c.Assert(got, Equals, tt.want)
	}
}
