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

// Get returns value of key
func Get(key string) ([]byte, error) {
	v, err := Client().Get(key)
	Trace("Get", err, logrus.Fields{fieldKey: key, fieldValue: string(v)})
	return v, err
}

// GetPrefix returns the first key which matches the prefix
func GetPrefix(prefix string) ([]byte, error) {
	v, err := Client().GetPrefix(prefix)
	Trace("GetPrefix", err, logrus.Fields{fieldPrefix: prefix, fieldValue: string(v)})
	return v, err
}

// ListPrefix returns the list of keys matching the prefix
func ListPrefix(prefix string) (KeyValuePairs, error) {
	v, err := Client().ListPrefix(prefix)
	Trace("ListPrefix", err, logrus.Fields{fieldPrefix: prefix, fieldNumEntries: len(v)})
	return v, err
}

// CreateOnly atomically creates a key or fails if it already exists
func CreateOnly(key string, value []byte, lease bool) error {
	err := Client().CreateOnly(key, value, lease)
	Trace("CreateOnly", err, logrus.Fields{fieldKey: key, fieldValue: string(value), fieldAttachLease: lease})
	return err
}

// Update creates or updates a key value pair
func Update(key string, value []byte, lease bool) error {
	err := Client().Update(key, value, lease)
	Trace("Update", err, logrus.Fields{fieldKey: key, fieldValue: string(value), fieldAttachLease: lease})
	return err
}

// CreateIfExists creates a key with the value only if key condKey exists
func CreateIfExists(condKey, key string, value []byte, lease bool) error {
	err := Client().CreateIfExists(condKey, key, value, lease)
	Trace("CreateIfExists", err, logrus.Fields{fieldKey: key, fieldValue: string(value), fieldCondition: condKey, fieldAttachLease: lease})
	return err
}

// Set sets the value of a key
func Set(key string, value []byte) error {
	err := Client().Set(key, value)
	Trace("Set", err, logrus.Fields{fieldKey: key, fieldValue: string(value)})
	return err
}

// Delete deletes a key
func Delete(key string) error {
	err := Client().Delete(key)
	Trace("Delete", err, logrus.Fields{fieldKey: key})
	return err
}

// DeletePrefix deletes all keys matching a prefix
func DeletePrefix(prefix string) error {
	err := Client().DeletePrefix(prefix)
	Trace("DeletePrefix", err, logrus.Fields{fieldPrefix: prefix})
	return err
}

// GetCapabilities returns the capabilities of the backend
func GetCapabilities() Capabilities {
	return Client().GetCapabilities()
}

// Encode encodes a binary slice into a character set that the backend supports
func Encode(in []byte) string {
	out := Client().Encode(in)
	Trace("Encode", nil, logrus.Fields{"in": in, "out": out})
	return out
}

// Decode decodes a key previously encoded back into the original binary slice
func Decode(in string) ([]byte, error) {
	out, err := Client().Decode(in)
	Trace("Decode", err, logrus.Fields{"in": in, "out": out})
	return out, err
}
