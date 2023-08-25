// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"testing"

	check "github.com/cilium/checkmate"
	"github.com/stretchr/testify/assert"

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

func TestClusterServiceValidate(t *testing.T) {
	tests := []struct {
		name   string
		svc    ClusterService
		assert assert.ErrorAssertionFunc
	}{
		{
			name:   "empty",
			svc:    ClusterService{},
			assert: assert.NoError,
		},
		{
			name: "valid",
			svc: ClusterService{
				ClusterID: 99,
				Frontends: map[string]PortConfiguration{"10.1.2.3": {}, "abcd::0001": {}},
				Backends:  map[string]PortConfiguration{"10.3.2.1": {}, "dcba::0001": {}},
			},
			assert: assert.NoError,
		},
		{
			name:   "invalid cluster ID",
			svc:    ClusterService{ClusterID: 260},
			assert: assert.Error,
		},
		{
			name:   "invalid frontend IP",
			svc:    ClusterService{Frontends: map[string]PortConfiguration{"10.1.2.3": {}, "invalid": {}}},
			assert: assert.Error,
		},
		{
			name:   "invalid backend IP",
			svc:    ClusterService{Backends: map[string]PortConfiguration{"invalid": {}, "dcba::0001": {}}},
			assert: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assert(t, tt.svc.validate())
		})
	}
}
