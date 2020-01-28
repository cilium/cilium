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

	"github.com/sirupsen/logrus"
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
func Get(ctx context.Context, key string) (*string, error) {
	bv, err := Client().Get(ctx, key)
	Trace("Get", err, logrus.Fields{fieldKey: key, fieldValue: string(bv)})
	if bv == nil {
		return nil, err
	}
	v := string(bv)
	return &v, err
}

// GetIfLocked returns value of key if the client is still holding the given lock.
func GetIfLocked(ctx context.Context, key string, lock KVLocker) (*string, error) {
	bv, err := Client().GetIfLocked(ctx, key, lock)
	Trace("GetIfLocked", err, logrus.Fields{fieldKey: key, fieldValue: string(bv)})
	if bv == nil {
		return nil, err
	}
	v := string(bv)
	return &v, err
}

// GetPrefix returns the first key which matches the prefix and its value.
func GetPrefix(ctx context.Context, prefix string) (string, *string, error) {
	k, bv, err := Client().GetPrefix(ctx, prefix)
	Trace("GetPrefix", err, logrus.Fields{fieldPrefix: prefix, fieldKey: k, fieldValue: string(bv)})
	if bv == nil {
		return k, nil, err
	}
	v := string(bv)
	return k, &v, err
}

// GetPrefixIfLocked returns the first key which matches the prefix and its value if the client is still holding the given lock.
func GetPrefixIfLocked(ctx context.Context, prefix string, lock KVLocker) (string, *string, error) {
	k, bv, err := Client().GetPrefixIfLocked(ctx, prefix, lock)
	Trace("GetPrefixIfLocked", err, logrus.Fields{fieldPrefix: prefix, fieldKey: k, fieldValue: string(bv)})
	if bv == nil {
		return k, nil, err
	}
	v := string(bv)
	return k, &v, err
}

// ListPrefix returns the list of keys matching the prefix
func ListPrefix(ctx context.Context, prefix string) (KeyValuePairs, error) {
	v, err := Client().ListPrefix(ctx, prefix)
	Trace("ListPrefix", err, logrus.Fields{fieldPrefix: prefix, fieldNumEntries: len(v)})
	return v, err
}

// ListPrefixIfLocked  returns a list of keys matching the prefix only if the client is still holding the given lock.
func ListPrefixIfLocked(ctx context.Context, prefix string, lock KVLocker) (KeyValuePairs, error) {
	v, err := Client().ListPrefixIfLocked(ctx, prefix, lock)
	Trace("ListPrefixIfLocked", err, logrus.Fields{fieldPrefix: prefix, fieldNumEntries: len(v)})
	return v, err
}

// CreateOnly atomically creates a key or fails if it already exists
func CreateOnly(ctx context.Context, key string, value string, lease bool) (bool, error) {
	success, err := Client().CreateOnly(ctx, key, []byte(value), lease)
	Trace("CreateOnly", err, logrus.Fields{
		fieldKey: key, fieldValue: value,
		fieldAttachLease: lease,
		"success":        success,
	})
	return success, err
}

// CreateOnlyIfLocked atomically creates a key if the client is still holding the given lock or fails if it already exists
func CreateOnlyIfLocked(ctx context.Context, key string, value string, lease bool, lock KVLocker) (bool, error) {
	success, err := Client().CreateOnlyIfLocked(ctx, key, []byte(value), lease, lock)
	Trace("CreateOnlyIfLocked", err, logrus.Fields{
		fieldKey: key, fieldValue: value,
		fieldAttachLease: lease,
		"success":        success,
	})
	return success, err
}

// Update creates or updates a key value pair
func Update(ctx context.Context, key string, value string, lease bool) error {
	err := Client().Update(ctx, key, []byte(value), lease)
	Trace("Update", err, logrus.Fields{fieldKey: key, fieldValue: string(value), fieldAttachLease: lease})
	return err
}

// UpdateIfDifferent updates a key if the value is different
func UpdateIfDifferent(ctx context.Context, key string, value string, lease bool) (bool, error) {
	recreated, err := Client().UpdateIfDifferent(ctx, key, []byte(value), lease)
	Trace("UpdateIfDifferent", err, logrus.Fields{
		fieldKey:         key,
		fieldValue:       value,
		fieldAttachLease: lease,
		"recreated":      recreated,
	})
	return recreated, err
}

// UpdateIfDifferentIfLocked updates a key if the value is different and if the client is still holding the given lock.
func UpdateIfDifferentIfLocked(ctx context.Context, key string, value string, lease bool, lock KVLocker) (bool, error) {
	recreated, err := Client().UpdateIfDifferentIfLocked(ctx, key, []byte(value), lease, lock)
	Trace("UpdateIfDifferentIfLocked", err, logrus.Fields{
		fieldKey:         key,
		fieldValue:       value,
		fieldAttachLease: lease,
		"recreated":      recreated,
	})
	return recreated, err
}

// CreateIfExists creates a key with the value only if key condKey exists
func CreateIfExists(ctx context.Context, condKey, key string, value string, lease bool) error {
	err := Client().CreateIfExists(ctx, condKey, key, []byte(value), lease)
	Trace("CreateIfExists", err, logrus.Fields{fieldKey: key, fieldValue: string(value), fieldCondition: condKey, fieldAttachLease: lease})
	return err
}

// Set sets the value of a key
func Set(ctx context.Context, key string, value string) error {
	err := Client().Set(ctx, key, []byte(value))
	Trace("Set", err, logrus.Fields{fieldKey: key, fieldValue: string(value)})
	return err
}

// Delete deletes a key
func Delete(ctx context.Context, key string) error {
	err := Client().Delete(ctx, key)
	Trace("Delete", err, logrus.Fields{fieldKey: key})
	return err
}

// DeleteIfLocked deletes a key if the client is still holding the given lock.
func DeleteIfLocked(ctx context.Context, key string, lock KVLocker) error {
	err := Client().DeleteIfLocked(ctx, key, lock)
	Trace("DeleteIfLocked", err, logrus.Fields{fieldKey: key})
	return err
}

// DeletePrefix deletes all keys matching a prefix
func DeletePrefix(ctx context.Context, prefix string) error {
	err := Client().DeletePrefix(ctx, prefix)
	Trace("DeletePrefix", err, logrus.Fields{fieldPrefix: prefix})
	return err
}

// GetCapabilities returns the capabilities of the backend
func GetCapabilities() Capabilities {
	return Client().GetCapabilities()
}

// Encode encodes a key string to conform to the restrictions of the backend
func Encode(in string) string {
	out := Client().Encode([]byte(in))
	Trace("Encode", nil, logrus.Fields{"in": in, "out": out})
	return out
}

// Decode decodes a key previously encoded back into the original
func Decode(in string) (string, error) {
	out, err := Client().Decode(in)
	Trace("Decode", err, logrus.Fields{"in": in, "out": out})
	return string(out), err
}

// Close closes the kvstore client
func Close() {
	defaultClient.Close()
}
