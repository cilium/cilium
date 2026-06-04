// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslice

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"sync"

	"github.com/klauspost/compress/zstd"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/clustermesh/types/endpointslice/internal"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
)

// EndpointSliceStorePrefix is the kvstore prefix of the shared store
//
// WARNING - STABLE API: Changing the structure or values of this will
// break backwards compatibility
var EndpointSliceStorePrefix = path.Join(kvstore.BaseKeyPrefix, "state", "endpointslices", "v1")

func init() {
	kvstore.RegisterCommandTranscoder(
		func() kvstore.TranscodableJSON { return &ClusterEndpointSlice{} },
		EndpointSliceStorePrefix,
		kvstore.StateToCachePrefix(EndpointSliceStorePrefix),
	)
}

// ClusterEndpointSlice is the definition of an EndpointSlice in a cluster.
//
// WARNING - STABLE API: Any change to this structure must be done in a
// backwards compatible way.
type ClusterEndpointSlice internal.ClusterEndpointSlice

func (eps *ClusterEndpointSlice) String() string {
	return eps.Cluster + "/" + eps.Namespace + "/" + eps.Name
}

// NamespacedName returns the namespace and service name
func (eps *ClusterEndpointSlice) NamespacedName() types.NamespacedName {
	return types.NamespacedName{Name: eps.Name, Namespace: eps.Namespace}
}

// GetKeyName returns the kvstore key to be used for the global service
func (eps *ClusterEndpointSlice) GetKeyName() string {
	// WARNING - STABLE API: Changing the structure of the key may break
	// backwards compatibility
	return path.Join(eps.Cluster, eps.Namespace, eps.Name)
}

var (
	zstdEncoderPool sync.Pool
	zstdDecoderPool sync.Pool
)

func getZstdEncoder() (*zstd.Encoder, error) {
	if encoder := zstdEncoderPool.Get(); encoder != nil {
		return encoder.(*zstd.Encoder), nil
	}

	return zstd.NewWriter(nil)
}

func getZstdDecoder() (*zstd.Decoder, error) {
	if decoder := zstdDecoderPool.Get(); decoder != nil {
		return decoder.(*zstd.Decoder), nil
	}

	return zstd.NewReader(nil)
}

// Marshal returns the cluster EndpointSlice object as zstd-compressed protobuf
func (eps *ClusterEndpointSlice) Marshal() ([]byte, error) {
	data, err := (*internal.ClusterEndpointSlice)(eps).Marshal()
	if err != nil {
		return nil, err
	}

	encoder, err := getZstdEncoder()
	if err != nil {
		return nil, err
	}
	defer zstdEncoderPool.Put(encoder)

	return encoder.EncodeAll(data, nil), nil
}

// Unmarshal parses the zstd-compressed protobuf byte slice and updates
// the ClusterEndpointSlice receiver
func (eps *ClusterEndpointSlice) Unmarshal(_ string, data []byte) error {
	decoder, err := getZstdDecoder()
	if err != nil {
		return err
	}
	defer zstdDecoderPool.Put(decoder)

	data, err = decoder.DecodeAll(data, nil)
	if err != nil {
		return err
	}

	if err := (*internal.ClusterEndpointSlice)(eps).Unmarshal(data); err != nil {
		return err
	}

	return eps.validate()
}

// MarshalJSON returns the cluster EndpointSlice object as JSON byte slice.
func (eps *ClusterEndpointSlice) MarshalJSON() ([]byte, error) {
	return json.Marshal((*internal.ClusterEndpointSlice)(eps))
}

// UnmarshalJSON parses the JSON byte slice and updates the ClusterEndpointSlice receiver.
func (eps *ClusterEndpointSlice) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, (*internal.ClusterEndpointSlice)(eps)); err != nil {
		return err
	}

	return eps.validate()
}

func (eps *ClusterEndpointSlice) validate() error {
	switch {
	case eps.Cluster == "":
		return errors.New("cluster is unset")
	case eps.Namespace == "":
		return errors.New("namespace is unset")
	case eps.Name == "":
		return errors.New("name is unset")
	case eps.AddressType != slim_discovery_v1.AddressTypeIPv4 && eps.AddressType != slim_discovery_v1.AddressTypeIPv6:
		return errors.New("address type is invalid")
	}

	for _, endpoint := range eps.Endpoints {
		for _, address := range endpoint.Addresses {
			switch eps.AddressType {
			case slim_discovery_v1.AddressTypeIPv4:
				addr, err := netip.ParseAddr(address)
				if err != nil || !addr.Is4() {
					return fmt.Errorf("invalid IPv4 endpoint address: %s", address)
				}
			case slim_discovery_v1.AddressTypeIPv6:
				addr, err := netip.ParseAddr(address)
				if err != nil || !addr.Is6() {
					return fmt.Errorf("invalid IPv6 endpoint address: %s", address)
				}
			}
		}
	}

	return nil
}

// ValidatingClusterEndpointSlice wraps a ClusterEndpointSlice to perform additional
// validation at unmarshal time.
//
// +protobuf=false
type ValidatingClusterEndpointSlice struct {
	ClusterEndpointSlice

	validators []clusterEndpointSliceValidator
}

type clusterEndpointSliceValidator func(key string, eps *ClusterEndpointSlice) error

func (ceps *ValidatingClusterEndpointSlice) Unmarshal(key string, data []byte) error {
	if err := ceps.ClusterEndpointSlice.Unmarshal(key, data); err != nil {
		return err
	}

	for _, validator := range ceps.validators {
		if err := validator(key, &ceps.ClusterEndpointSlice); err != nil {
			return err
		}
	}

	return nil
}

// ClusterNameValidator returns a validator enforcing that the cluster field
// of the unmarshaled service matches the provided one.
func ClusterNameValidator(clusterName string) clusterEndpointSliceValidator {
	return func(_ string, eps *ClusterEndpointSlice) error {
		if eps.Cluster != clusterName {
			return fmt.Errorf("unexpected cluster name: got %s, expected %s", eps.Cluster, clusterName)
		}
		return nil
	}
}

// NamespacedNameValidator returns a validator enforcing that the namespaced
// name of the unmarshaled service matches the kvstore key.
func NamespacedNameValidator() clusterEndpointSliceValidator {
	return func(key string, eps *ClusterEndpointSlice) error {
		if got := eps.NamespacedName().String(); got != key {
			return fmt.Errorf("namespaced name does not match key: got %s, expected %s", got, key)
		}
		return nil
	}
}

// ClusterIDValidator returns a validator enforcing that the cluster ID of the
// unmarshaled service matches the provided one. The access to the provided
// clusterID value is not synchronized, and it shall not be mutated concurrently.
func ClusterIDValidator(clusterID *uint32) clusterEndpointSliceValidator {
	return func(_ string, eps *ClusterEndpointSlice) error {
		if eps.ClusterID != *clusterID {
			return fmt.Errorf("unexpected cluster ID: got %d, expected %d", eps.ClusterID, *clusterID)
		}
		return nil
	}
}

// KeyCreator returns a store.KeyCreator for ClusterEndpointSlices, configuring the
// specified extra validators.
func KeyCreator(validators ...clusterEndpointSliceValidator) store.KeyCreator {
	return func() store.Key {
		return &ValidatingClusterEndpointSlice{validators: validators}
	}
}
