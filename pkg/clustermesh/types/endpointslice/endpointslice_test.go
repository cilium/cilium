// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslice

import (
	"testing"

	"github.com/stretchr/testify/require"

	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
)

func TestClusterEndpointSlice(t *testing.T) {
	eps := ClusterEndpointSlice{
		Cluster:     "default",
		Namespace:   "bar",
		Name:        "foo",
		AddressType: slim_discovery_v1.AddressTypeIPv4,
	}

	b, err := eps.Marshal()
	require.NoError(t, err)
	unmarshal := ClusterEndpointSlice{}
	err = unmarshal.Unmarshal("", b)
	require.NoError(t, err)
	require.Equal(t, eps, unmarshal)

	require.Equal(t, "foo", unmarshal.Name)
	require.Equal(t, "bar", unmarshal.Namespace)
	require.Equal(t, "default/bar/foo", unmarshal.String())
	require.Equal(t, "default/bar/foo", unmarshal.GetKeyName())

	b, err = eps.MarshalJSON()
	require.NoError(t, err)
	unmarshal = ClusterEndpointSlice{}
	err = unmarshal.UnmarshalJSON(b)
	require.NoError(t, err)
	require.Equal(t, eps, unmarshal)

	require.Equal(t, "foo", unmarshal.Name)
	require.Equal(t, "bar", unmarshal.Namespace)
	require.Equal(t, "default/bar/foo", unmarshal.String())
	require.Equal(t, "default/bar/foo", unmarshal.GetKeyName())
}

func TestClusterEndpointSliceValidate(t *testing.T) {
	tests := []struct {
		name   string
		eps    ClusterEndpointSlice
		errstr string
	}{
		{
			name:   "empty",
			eps:    ClusterEndpointSlice{},
			errstr: "cluster is unset",
		},
		{
			name: "minimum information",
			eps: ClusterEndpointSlice{
				Cluster:     "foo",
				Namespace:   "bar",
				Name:        "qux",
				AddressType: slim_discovery_v1.AddressTypeIPv4,
			},
		},
		{
			name: "valid IPv4",
			eps: ClusterEndpointSlice{
				Cluster:     "foo",
				ClusterID:   99,
				Namespace:   "bar",
				Name:        "qux",
				AddressType: slim_discovery_v1.AddressTypeIPv4,
				Endpoints: []slim_discovery_v1.Endpoint{{
					Addresses: []string{"10.1.2.3"},
				}},
			},
		},
		{
			name: "valid IPv6",
			eps: ClusterEndpointSlice{
				Cluster:     "foo",
				ClusterID:   99,
				Namespace:   "bar",
				Name:        "qux",
				AddressType: slim_discovery_v1.AddressTypeIPv6,
				Endpoints: []slim_discovery_v1.Endpoint{{
					Addresses: []string{"2001:db8::1"},
				}},
			},
		},
		{
			name: "invalid IPv4 endpoint address",
			eps: ClusterEndpointSlice{
				Cluster:     "foo",
				Namespace:   "bar",
				Name:        "qux",
				AddressType: slim_discovery_v1.AddressTypeIPv4,
				Endpoints: []slim_discovery_v1.Endpoint{{
					Addresses: []string{"2001:db8::1"},
				}},
			},
			errstr: "invalid IPv4 endpoint address: 2001:db8::1",
		},
		{
			name: "invalid IPv6 endpoint address",
			eps: ClusterEndpointSlice{
				Cluster:     "foo",
				Namespace:   "bar",
				Name:        "qux",
				AddressType: slim_discovery_v1.AddressTypeIPv6,
				Endpoints: []slim_discovery_v1.Endpoint{{
					Addresses: []string{"10.1.2.3"},
				}},
			},
			errstr: "invalid IPv6 endpoint address: 10.1.2.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.eps.validate()
			if tt.errstr != "" {
				require.EqualError(t, err, tt.errstr)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestValidatingClusterEndpointSlice(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		eps       ClusterEndpointSlice
		validator clusterEndpointSliceValidator
		errstr    string
	}{
		{
			name: "valid cluster name",
			eps: ClusterEndpointSlice{
				Cluster: "foo", Namespace: "bar", Name: "qux", AddressType: slim_discovery_v1.AddressTypeIPv4,
			},
			validator: ClusterNameValidator("foo"),
		},
		{
			name: "invalid cluster name",
			eps: ClusterEndpointSlice{
				Cluster: "foo", Namespace: "bar", Name: "qux", AddressType: slim_discovery_v1.AddressTypeIPv4,
			},
			validator: ClusterNameValidator("fred"),
			errstr:    "unexpected cluster name: got foo, expected fred",
		},
		{
			name: "valid namespaced name",
			key:  "bar/qux",
			eps: ClusterEndpointSlice{
				Cluster: "foo", Namespace: "bar", Name: "qux", AddressType: slim_discovery_v1.AddressTypeIPv4,
			},
			validator: NamespacedNameValidator(),
		},
		{
			name: "invalid namespaced name",
			key:  "fred/qux",
			eps: ClusterEndpointSlice{
				Cluster: "foo", Namespace: "bar", Name: "qux", AddressType: slim_discovery_v1.AddressTypeIPv4,
			},
			validator: NamespacedNameValidator(),
			errstr:    "namespaced name does not match key: got bar/qux, expected fred/qux",
		},
		{
			name: "valid cluster ID",
			eps: ClusterEndpointSlice{
				Cluster: "foo", Namespace: "bar", Name: "qux", ClusterID: 10, AddressType: slim_discovery_v1.AddressTypeIPv4,
			},
			validator: ClusterIDValidator(new(uint32(10))),
		},
		{
			name: "invalid cluster ID",
			eps: ClusterEndpointSlice{
				Cluster: "foo", Namespace: "bar", Name: "qux", ClusterID: 10, AddressType: slim_discovery_v1.AddressTypeIPv4,
			},
			validator: ClusterIDValidator(new(uint32(15))),
			errstr:    "unexpected cluster ID: got 10, expected 15",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.eps.Marshal()
			require.NoError(t, err)

			got := KeyCreator(tt.validator)()
			err = got.Unmarshal(tt.key, data)
			if tt.errstr != "" {
				require.EqualError(t, err, tt.errstr)
				return
			}

			require.NoError(t, err)
			gotEPS := got.(*ValidatingClusterEndpointSlice).ClusterEndpointSlice
			require.Equal(t, tt.eps, gotEPS)
		})
	}
}
