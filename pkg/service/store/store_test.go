// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"testing"

	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { check.TestingT(t) }

type ServiceGenericSuite struct{}

var _ = check.Suite(&ServiceGenericSuite{})

func (s *ServiceGenericSuite) TestClusterService(c *check.C) {
	svc := NewClusterService("foo", "bar")
	svc.Cluster = "default"

	c.Assert(svc.Name, check.Equals, "foo")
	c.Assert(svc.Namespace, check.Equals, "bar")

	c.Assert(svc.String(), check.Equals, "default/bar/foo")

	b, err := svc.Marshal()
	c.Assert(err, check.IsNil)

	unmarshal := ClusterService{}
	err = unmarshal.Unmarshal("", b)
	c.Assert(err, check.IsNil)
	c.Assert(svc, checker.DeepEquals, unmarshal)

	c.Assert(svc.GetKeyName(), check.Equals, "default/bar/foo")
}

func (s *ServiceGenericSuite) TestPortConfigurationDeepEqual(c *check.C) {
	tests := []struct {
		a    PortConfiguration
		b    PortConfiguration
		want bool
	}{

		{
			a: PortConfiguration{
				"foo": {Protocol: loadbalancer.NONE, Port: 1},
			},
			b: PortConfiguration{
				"foo": {Protocol: loadbalancer.NONE, Port: 1},
			},
			want: true,
		},
		{
			a: PortConfiguration{
				"foo": {Protocol: loadbalancer.NONE, Port: 1},
			},
			b: PortConfiguration{
				"foz": {Protocol: loadbalancer.NONE, Port: 1},
			},
			want: false,
		},
		{
			a: PortConfiguration{
				"foo": {Protocol: loadbalancer.NONE, Port: 1},
			},
			b: PortConfiguration{
				"foo": {Protocol: loadbalancer.NONE, Port: 2},
			},
			want: false,
		},
		{
			a: PortConfiguration{
				"foo": {Protocol: loadbalancer.NONE, Port: 1},
			},
			b: PortConfiguration{
				"foo": {Protocol: loadbalancer.NONE, Port: 1},
				"baz": {Protocol: loadbalancer.NONE, Port: 2},
			},
			want: false,
		},
		{
			a: PortConfiguration{},
			b: PortConfiguration{
				"foo": {Protocol: loadbalancer.NONE, Port: 1},
			},
			want: false,
		},
		{
			want: true,
		},
	}
	for _, tt := range tests {
		if got := tt.a.DeepEqual(&tt.b); got != tt.want {
			c.Errorf("PortConfiguration.DeepEqual() = %v, want %v", got, tt.want)
		}
	}
}
