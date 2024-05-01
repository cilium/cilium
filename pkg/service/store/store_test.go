// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

func TestClusterService(t *testing.T) {
	svc := NewClusterService("foo", "bar")
	svc.Cluster = "default"

	require.Equal(t, "foo", svc.Name)
	require.Equal(t, "bar", svc.Namespace)

	require.Equal(t, "default/bar/foo", svc.String())

	b, err := svc.Marshal()
	require.Nil(t, err)

	unmarshal := ClusterService{}
	err = unmarshal.Unmarshal("", b)
	require.Nil(t, err)
	require.EqualValues(t, unmarshal, svc)

	require.Equal(t, "default/bar/foo", svc.GetKeyName())
}

func TestPortConfigurationDeepEqual(t *testing.T) {
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
		got := tt.a.DeepEqual(&tt.b)
		require.Equalf(t, tt.want, got, "PortConfiguration.DeepEqual() = %v, want %v", got, tt.want)
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
