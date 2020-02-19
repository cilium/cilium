// Copyright 2016-2020 Authors of Cilium
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
	"context"
)

// Value is an abstraction of the data stored in the kvstore as well as the
// mod revision of that data.
type Value struct {
	Data        []byte
	ModRevision uint64
	LeaseID     int64
	SessionID   string
}

// KeyValuePairs is a map of key=value pairs
type KeyValuePairs map[string]Value

// Capabilities is a bitmask to indicate the capabilities of a backend
type Capabilities uint32

const (
	// CapabilityCreateIfExists is true if CreateIfExists is functional
	CapabilityCreateIfExists Capabilities = 1 << 0

	// CapabilityDeleteOnZeroCount is true if DeleteOnZeroCount is functional
	CapabilityDeleteOnZeroCount Capabilities = 1 << 1

	// BaseKeyPrefix is the base prefix that should be used for all keys
	BaseKeyPrefix = "cilium"

	// InitLockPath is the path to the init lock to test quorum
	InitLockPath = BaseKeyPrefix + "/.initlock"
)

// Get returns value of key
func Get(key string) ([]byte, error) {
	v, err := Client().Get(key)
	return v, err
}

// GetIfLocked returns value of key if the client is still holding the given lock.
func GetIfLocked(key string, lock KVLocker) ([]byte, error) {
	v, err := Client().GetIfLocked(key, lock)
	return v, err
}

// GetPrefix returns the first key which matches the prefix and its value.
func GetPrefix(ctx context.Context, prefix string) (k string, v []byte, err error) {
	k, v, err = Client().GetPrefix(ctx, prefix)
	return
}

// GetPrefixIfLocked returns the first key which matches the prefix and its value if the client is still holding the given lock.
func GetPrefixIfLocked(ctx context.Context, prefix string, lock KVLocker) (k string, v []byte, err error) {
	k, v, err = Client().GetPrefixIfLocked(ctx, prefix, lock)
	return
}

// ListPrefix returns the list of keys matching the prefix
func ListPrefix(prefix string) (KeyValuePairs, error) {
	v, err := Client().ListPrefix(prefix)
	return v, err
}

// ListPrefixIfLocked  returns a list of keys matching the prefix only if the client is still holding the given lock.
func ListPrefixIfLocked(prefix string, lock KVLocker) (KeyValuePairs, error) {
	v, err := Client().ListPrefixIfLocked(prefix, lock)
	return v, err
}

// CreateOnly atomically creates a key or fails if it already exists
func CreateOnly(ctx context.Context, key string, value []byte, lease bool) (bool, error) {
	success, err := Client().CreateOnly(ctx, key, value, lease)
	return success, err
}

// CreateOnlyIfLocked atomically creates a key if the client is still holding the given lock or fails if it already exists
func CreateOnlyIfLocked(ctx context.Context, key string, value []byte, lease bool, lock KVLocker) (bool, error) {
	success, err := Client().CreateOnlyIfLocked(ctx, key, value, lease, lock)
	return success, err
}

// Update creates or updates a key value pair
func Update(ctx context.Context, key string, value []byte, lease bool) error {
	err := Client().Update(ctx, key, value, lease)
	return err
}

// UpdateIfDifferent updates a key if the value is different
func UpdateIfDifferent(ctx context.Context, key string, value []byte, lease bool) (bool, error) {
	recreated, err := Client().UpdateIfDifferent(ctx, key, value, lease)
	return recreated, err
}

// UpdateIfDifferentIfLocked updates a key if the value is different and if the client is still holding the given lock.
func UpdateIfDifferentIfLocked(ctx context.Context, key string, value []byte, lease bool, lock KVLocker) (bool, error) {
	recreated, err := Client().UpdateIfDifferentIfLocked(ctx, key, value, lease, lock)
	return recreated, err
}

// CreateIfExists creates a key with the value only if key condKey exists
func CreateIfExists(condKey, key string, value []byte, lease bool) error {
	err := Client().CreateIfExists(condKey, key, value, lease)
	return err
}

// Set sets the value of a key
func Set(key string, value []byte) error {
	err := Client().Set(key, value)
	return err
}

// Delete deletes a key
func Delete(key string) error {
	err := Client().Delete(key)
	return err
}

// DeleteIfLocked deletes a key if the client is still holding the given lock.
func DeleteIfLocked(key string, lock KVLocker) error {
	err := Client().DeleteIfLocked(key, lock)
	return err
}

// DeletePrefix deletes all keys matching a prefix
func DeletePrefix(prefix string) error {
	err := Client().DeletePrefix(prefix)
	return err
}

// GetCapabilities returns the capabilities of the backend
func GetCapabilities() Capabilities {
	return Client().GetCapabilities()
}

// Encode encodes a binary slice into a character set that the backend supports
func Encode(in []byte) string {
	out := Client().Encode(in)
	return out
}

// Decode decodes a key previously encoded back into the original binary slice
func Decode(in string) ([]byte, error) {
	out, err := Client().Decode(in)
	return out, err
}

// Close closes the kvstore client
func Close() {
	defaultClient.Close()
}
