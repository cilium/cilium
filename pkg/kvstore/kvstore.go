// Copyright 2016-2019 Authors of Cilium
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

// CreateOnly atomically creates a key or fails if it already exists
func CreateOnly(ctx context.Context, key string, value string, lease bool) (bool, error) {
	success, err := Client().CreateOnly(ctx, key, []byte(value), lease)
	Trace("CreateOnly", err, logrus.Fields{
		fieldKey: key, fieldValue: value,
		FieldAttachLease: lease,
		"success":        success,
	})
	return success, err
}

// Update creates or updates a key value pair
func Update(ctx context.Context, key string, value string, lease bool) error {
	err := Client().Update(ctx, key, []byte(value), lease)
	Trace("Update", err, logrus.Fields{fieldKey: key, fieldValue: string(value), FieldAttachLease: lease})
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

// DeletePrefix deletes all keys matching a prefix
func DeletePrefix(ctx context.Context, prefix string) error {
	err := Client().DeletePrefix(ctx, prefix)
	Trace("DeletePrefix", err, logrus.Fields{fieldPrefix: prefix})
	return err
}

// Close closes the kvstore client
func Close() {
	defaultClient.Close()
}
