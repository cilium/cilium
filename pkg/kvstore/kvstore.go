// Copyright 2016-2018 Authors of Cilium
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

package kvstore

import (
	"github.com/cilium/cilium/pkg/lock"
	"github.com/sirupsen/logrus"
)

// KeyValuePairs is a map of key=value pairs
type KeyValuePairs map[string][]byte

// Capabilities is a bitmask to indicate the capabilities of a backend
type Capabilities uint32

const (
	// CapabilityCreateIfExists is true if CreateIfExists is functional
	CapabilityCreateIfExists Capabilities = 1 << 0

	// CapabilityDeleteOnZeroCount is true if DeleteOnZeroCount is functional
	CapabilityDeleteOnZeroCount Capabilities = 1 << 1

	// BaseKeyPrefix is the base prefix that should be used for all keys
	BaseKeyPrefix = "cilium"
)

// ExtendedKVStore is a struct that export multiple kvstore methods
type ExtendedKVStore struct {
	namespace string
	mutex     lock.Mutex
}

// GetKVStoreExtendedClient returns a ExtendedKVStore struct
func GetKVStoreExtendedClient() *ExtendedKVStore {
	return &ExtendedKVStore{}
}

// GetKVStoreExtendedClientWithNamespace returns a ExtendedKVStore struct with the given namespace.
func GetKVStoreExtendedClientWithNamespace(namespace string) *ExtendedKVStore {
	return &ExtendedKVStore{
		namespace: namespace,
	}
}

func (kvClient *ExtendedKVStore) getClient() BackendOperations {
	return Client()
}

// SetNamespace set the namespace for the given client
func (kvClient *ExtendedKVStore) SetNamespace(namespace string) {
	kvClient.mutex.Lock()
	kvClient.namespace = namespace
	kvClient.mutex.Unlock()
}

// GetNamespace returns the client namespace
func (kvClient *ExtendedKVStore) GetNamespace() string {
	kvClient.mutex.Lock()
	defer kvClient.mutex.Unlock()
	return kvClient.namespace
}

// Get returns the given key from the kvstore
func (kvClient *ExtendedKVStore) Get(key string) ([]byte, error) {
	v, err := kvClient.getClient().Get(kvClient.GetNamespace(), key)
	Trace("Get", err, logrus.Fields{fieldKey: key, fieldValue: string(v)})
	return v, err
}

// Delete delete the given key from the kvstore.
func (kvClient *ExtendedKVStore) Delete(key string) error {
	err := kvClient.getClient().Delete(kvClient.GetNamespace(), key)
	Trace("Delete", err, logrus.Fields{fieldKey: key})
	return err
}

// GetPrefix returns the first key which matches the prefix
func (kvClient *ExtendedKVStore) GetPrefix(prefix string) ([]byte, error) {
	v, err := kvClient.getClient().GetPrefix(kvClient.GetNamespace(), prefix)
	Trace("GetPrefix", err, logrus.Fields{fieldPrefix: prefix, fieldValue: string(v)})
	return v, err
}

// ListPrefix returns the list of keys matching the prefix
func (kvClient *ExtendedKVStore) ListPrefix(prefix string) (KeyValuePairs, error) {
	v, err := kvClient.getClient().ListPrefix(kvClient.GetNamespace(), prefix)
	Trace("ListPrefix", err, logrus.Fields{fieldPrefix: prefix, fieldNumEntries: len(v)})
	return v, err
}

func (kvClient *ExtendedKVStore) LockPath(path string) (kvLocker, error) {
	return kvClient.getClient().LockPath(path)
}

// CreateOnly atomically creates a key or fails if it already exists
func (kvClient *ExtendedKVStore) CreateOnly(key string, value []byte, lease bool) error {
	err := kvClient.getClient().CreateOnly(kvClient.GetNamespace(), key, value, lease)
	Trace("CreateOnly", err, logrus.Fields{fieldKey: key, fieldValue: string(value), fieldAttachLease: lease})
	return err
}

// Update creates or updates a key value pair
func (kvClient *ExtendedKVStore) Update(key string, value []byte, lease bool) error {
	err := kvClient.getClient().Update(kvClient.GetNamespace(), key, value, lease)
	Trace("Update", err, logrus.Fields{fieldKey: key, fieldValue: string(value), fieldAttachLease: lease})
	return err
}

// Set sets the value of a key
func (kvClient *ExtendedKVStore) Set(key string, value []byte) error {
	err := kvClient.getClient().Set(kvClient.GetNamespace(), key, value)
	Trace("Set", err, logrus.Fields{fieldKey: key, fieldValue: string(value)})
	return err
}

//DeletePrefix deletes all keys matching a prefix
func (kvClient *ExtendedKVStore) DeletePrefix(prefix string) error {
	err := kvClient.getClient().DeletePrefix(kvClient.GetNamespace(), prefix)
	Trace("DeletePrefix", err, logrus.Fields{fieldPrefix: prefix})
	return err
}

// GetCapabilities returns the capabilities of the backend
func (kvClient *ExtendedKVStore) GetCapabilities() Capabilities {
	return kvClient.getClient().GetCapabilities(kvClient.GetNamespace())
}

// Encode encodes a binary slice into a character set that the backend supports
func (kvClient *ExtendedKVStore) Encode(in []byte) string {
	out := kvClient.getClient().Encode(in)
	Trace("Encode", nil, logrus.Fields{"in": in, "out": out})
	return out
}

// Decode decodes a key previously encoded back into the original binary slice
func (kvClient *ExtendedKVStore) Decode(in string) ([]byte, error) {
	out, err := kvClient.getClient().Decode(in)
	Trace("Decode", err, logrus.Fields{"in": in, "out": out})
	return out, err
}

// CreateIfExists creates a key with the value only if key condKey exists
func (kvClient *ExtendedKVStore) CreateIfExists(condKey, key string, value []byte, lease bool) error {
	err := kvClient.getClient().CreateIfExists(kvClient.GetNamespace(), condKey, key, value, lease)
	Trace("CreateIfExists", err, logrus.Fields{fieldKey: key, fieldValue: string(value), fieldCondition: condKey, fieldAttachLease: lease})
	return err
}

// Close closes the kvstore client
func Close() {
	defaultClient.Close()
}
