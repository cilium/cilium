// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

func TestClusterService(t *testing.T) {
	svc := NewClusterService("foo", "bar")
	svc.Cluster = "default"

	require.Equal(t, "foo", svc.Name)
	require.Equal(t, "bar", svc.Namespace)

	require.Equal(t, "default/bar/foo", svc.String())

	b, err := svc.Marshal()
	require.NoError(t, err)

	unmarshal := ClusterService{}
	err = unmarshal.Unmarshal("", b)
	require.NoError(t, err)
	require.Equal(t, unmarshal, svc)

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
			assert: assert.Error,
		},
		{
			name:   "minimum information",
			svc:    ClusterService{Cluster: "foo", Namespace: "bar", Name: "qux"},
			assert: assert.NoError,
		},
		{
			name: "valid",
			svc: ClusterService{
				Cluster: "foo", Namespace: "bar", Name: "qux",
				ClusterID: 99,
				Frontends: map[string]PortConfiguration{"10.1.2.3": {}, "abcd::0001": {}},
				Backends:  map[string]PortConfiguration{"10.3.2.1": {}, "dcba::0001": {}},
			},
			assert: assert.NoError,
		},
		{
			name:   "invalid cluster ID",
			svc:    ClusterService{Cluster: "foo", Namespace: "bar", Name: "qux", ClusterID: 260},
			assert: assert.Error,
		},
		{
			name: "invalid frontend IP",
			svc: ClusterService{
				Cluster: "foo", Namespace: "bar", Name: "qux",
				Frontends: map[string]PortConfiguration{"10.1.2.3": {}, "invalid": {}},
			},
			assert: assert.Error,
		},
		{
			name: "invalid backend IP",
			svc: ClusterService{
				Cluster: "foo", Namespace: "bar", Name: "qux",
				Backends: map[string]PortConfiguration{"invalid": {}, "dcba::0001": {}},
			},
			assert: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assert(t, tt.svc.validate())
		})
	}
}

func TestValidatingClusterService(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		svc       ClusterService
		validator clusterServiceValidator
		errstr    string
	}{
		{
			name:      "valid cluster name",
			svc:       ClusterService{Cluster: "foo", Namespace: "bar", Name: "qux"},
			validator: ClusterNameValidator("foo"),
		},
		{
			name:      "invalid cluster name",
			svc:       ClusterService{Cluster: "foo", Namespace: "bar", Name: "qux"},
			validator: ClusterNameValidator("fred"),
			errstr:    "unexpected cluster name: got foo, expected fred",
		},
		{
			name:      "valid namespaced name",
			key:       "bar/qux",
			svc:       ClusterService{Cluster: "foo", Namespace: "bar", Name: "qux"},
			validator: NamespacedNameValidator(),
		},
		{
			name:      "invalid namespaced name",
			key:       "fred/qux",
			svc:       ClusterService{Cluster: "foo", Namespace: "bar", Name: "qux"},
			validator: NamespacedNameValidator(),
			errstr:    "namespaced name does not match key: got bar/qux, expected fred/qux",
		},
		{
			name:      "valid cluster ID",
			svc:       ClusterService{Cluster: "foo", Namespace: "bar", Name: "qux", ClusterID: 10},
			validator: ClusterIDValidator(ptr.To[uint32](10)),
		},
		{
			name:      "invalid cluster ID",
			svc:       ClusterService{Cluster: "foo", Namespace: "bar", Name: "qux", ClusterID: 10},
			validator: ClusterIDValidator(ptr.To[uint32](15)),
			errstr:    "unexpected cluster ID: got 10, expected 15",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.svc.Marshal()
			require.NoError(t, err)

			got := KeyCreator(tt.validator)()
			err = got.Unmarshal(tt.key, data)
			if tt.errstr != "" {
				require.EqualError(t, err, tt.errstr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.svc, got.(*ValidatingClusterService).ClusterService)
		})
	}
}
