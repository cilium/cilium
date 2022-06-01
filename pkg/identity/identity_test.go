// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package identity

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labels/cidr"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type IdentityTestSuite struct{}

var _ = Suite(&IdentityTestSuite{})

func (s *IdentityTestSuite) TestReservedID(c *C) {
	i := GetReservedID("host")
	c.Assert(i, Equals, NumericIdentity(1))
	c.Assert(i.String(), Equals, "host")

	i = GetReservedID("world")
	c.Assert(i, Equals, NumericIdentity(2))
	c.Assert(i.String(), Equals, "world")

	// This is an obsoleted identity, we verify that it returns 0
	i = GetReservedID("cluster")
	c.Assert(i, Equals, NumericIdentity(0))
	c.Assert(i.String(), Equals, "unknown")

	i = GetReservedID("health")
	c.Assert(i, Equals, NumericIdentity(4))
	c.Assert(i.String(), Equals, "health")

	i = GetReservedID("init")
	c.Assert(i, Equals, NumericIdentity(5))
	c.Assert(i.String(), Equals, "init")

	i = GetReservedID("unmanaged")
	c.Assert(i, Equals, NumericIdentity(3))
	c.Assert(i.String(), Equals, "unmanaged")

	i = GetReservedID("kube-apiserver")
	c.Assert(i, Equals, NumericIdentity(7))
	c.Assert(i.String(), Equals, "kube-apiserver")

	c.Assert(GetReservedID("unknown"), Equals, IdentityUnknown)
	unknown := NumericIdentity(700)
	c.Assert(unknown.String(), Equals, "700")
}

func (s *IdentityTestSuite) TestIsReservedIdentity(c *C) {
	c.Assert(ReservedIdentityKubeAPIServer.IsReservedIdentity(), Equals, true)
	c.Assert(ReservedIdentityHealth.IsReservedIdentity(), Equals, true)
	c.Assert(ReservedIdentityHost.IsReservedIdentity(), Equals, true)
	c.Assert(ReservedIdentityWorld.IsReservedIdentity(), Equals, true)
	c.Assert(ReservedIdentityInit.IsReservedIdentity(), Equals, true)
	c.Assert(ReservedIdentityUnmanaged.IsReservedIdentity(), Equals, true)

	c.Assert(NumericIdentity(123456).IsReservedIdentity(), Equals, false)
}

func (s *IdentityTestSuite) TestRequiresGlobalIdentity(c *C) {
	_, ipnet, err := net.ParseCIDR("0.0.0.0/0")
	c.Assert(err, IsNil)
	c.Assert(RequiresGlobalIdentity(cidr.GetCIDRLabels(ipnet)), Equals, false)

	_, ipnet, err = net.ParseCIDR("192.168.23.0/24")
	c.Assert(err, IsNil)
	c.Assert(RequiresGlobalIdentity(cidr.GetCIDRLabels(ipnet)), Equals, false)

	c.Assert(RequiresGlobalIdentity(labels.NewLabelsFromModel([]string{"k8s:foo=bar"})), Equals, true)
}

func (s *IdentityTestSuite) TestNewIdentityFromLabelArray(c *C) {
	id := NewIdentityFromLabelArray(NumericIdentity(1001),
		labels.NewLabelArrayFromSortedList("unspec:a=;unspec:b;unspec:c=d"))

	lbls := labels.Labels{
		"a": labels.ParseLabel("a"),
		"c": labels.ParseLabel("c=d"),
		"b": labels.ParseLabel("b"),
	}
	c.Assert(id.ID, Equals, NumericIdentity(1001))
	c.Assert(id.Labels, checker.DeepEquals, lbls)
	c.Assert(id.LabelArray, checker.DeepEquals, lbls.LabelArray())
}

func TestLookupReservedIdentityByLabels(t *testing.T) {
	type args struct {
	}
	type want struct {
		id     NumericIdentity
		labels labels.Labels
	}
	tests := []struct {
		name string
		args labels.Labels
		want *want
	}{
		{
			name: "nil",
			args: nil,
			want: nil,
		},
		{
			name: "host",
			args: labels.LabelHost,
			want: &want{
				id:     ReservedIdentityHost,
				labels: labels.LabelHost,
			},
		},
		{
			name: "non-reserved",
			args: labels.NewLabelsFromModel([]string{"foo"}),
			want: nil,
		},
		{
			name: "non-reserved-2",
			args: labels.NewLabelsFromModel([]string{"reserved:init", "foo"}),
			want: nil,
		},
		{
			name: "health",
			args: labels.LabelHealth,
			want: &want{
				id:     ReservedIdentityHealth,
				labels: labels.LabelHealth,
			},
		},
		{
			name: "remote-node",
			args: labels.LabelRemoteNode,
			want: &want{
				id:     ReservedIdentityRemoteNode,
				labels: labels.LabelRemoteNode,
			},
		},
		{
			name: "kube-apiserver",
			args: labels.Map2Labels(map[string]string{
				labels.LabelKubeAPIServer.String(): "",
				labels.LabelRemoteNode.String():    "",
			}, ""),
			want: &want{
				id: ReservedIdentityKubeAPIServer,
				labels: labels.Map2Labels(map[string]string{
					labels.LabelKubeAPIServer.String(): "",
					labels.LabelRemoteNode.String():    "",
				}, ""),
			},
		},
		{
			name: "kube-apiserver-and-host",
			args: labels.Map2Labels(map[string]string{
				labels.LabelKubeAPIServer.String(): "",
				labels.LabelHost.String():          "",
			}, ""),
			want: &want{ // Should always still be host reserved identity
				id: ReservedIdentityHost,
				labels: labels.Map2Labels(map[string]string{
					labels.LabelKubeAPIServer.String(): "",
					labels.LabelHost.String():          "",
				}, ""),
			},
		},
		{
			name: "host-and-kube-apiserver",
			args: labels.Map2Labels(map[string]string{
				labels.LabelHost.String():          "",
				labels.LabelKubeAPIServer.String(): "",
			}, ""),
			want: &want{ // Should always still be host reserved identity
				id: ReservedIdentityHost,
				labels: labels.Map2Labels(map[string]string{
					labels.LabelHost.String():          "",
					labels.LabelKubeAPIServer.String(): "",
				}, ""),
			},
		},
		{
			name: "kube-apiserver-and-remote-node",
			args: labels.Map2Labels(map[string]string{
				labels.LabelKubeAPIServer.String(): "",
				labels.LabelRemoteNode.String():    "",
			}, ""),
			want: &want{
				id: ReservedIdentityKubeAPIServer,
				labels: labels.Map2Labels(map[string]string{
					labels.LabelKubeAPIServer.String(): "",
					labels.LabelRemoteNode.String():    "",
				}, ""),
			},
		},
		{
			name: "remote-node-and-kube-apiserver",
			args: labels.Map2Labels(map[string]string{
				labels.LabelRemoteNode.String():    "",
				labels.LabelKubeAPIServer.String(): "",
			}, ""),
			want: &want{
				id: ReservedIdentityKubeAPIServer,
				labels: labels.Map2Labels(map[string]string{
					labels.LabelRemoteNode.String():    "",
					labels.LabelKubeAPIServer.String(): "",
				}, ""),
			},
		},
		{
			name: "ingress",
			args: labels.LabelIngress,
			want: &want{
				id:     ReservedIdentityIngress,
				labels: labels.LabelIngress,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := LookupReservedIdentityByLabels(tt.args)
			if tt.want == nil {
				assert.Nil(t, id)
				return
			}
			assert.NotNil(t, id)
			assert.Equal(t, tt.want.id, id.ID)
			assert.Equal(t, tt.want.labels, id.Labels)
		})
	}
}
