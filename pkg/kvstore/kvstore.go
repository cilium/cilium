// Copyright 2016-2017 Authors of Cilium
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
	"encoding/json"
	"time"

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/policy"

	log "github.com/sirupsen/logrus"
)

type KVClient interface {
	LockPath(path string) (kvLocker, error)
	GetValue(k string) (json.RawMessage, error)
	SetValue(k string, v interface{}) error
	InitializeFreeID(path string, firstID uint32) error
	GetMaxID(key string, firstID uint32) (uint32, error)
	SetMaxID(key string, firstID, maxID uint32) error

	GASNewSecLabelID(baseKeyPath string, baseID uint32, secCtxLabels *policy.Identity) error
	GASNewL3n4AddrID(basePath string, baseID uint32, lAddrID *types.L3n4AddrID) error

	DeleteTree(path string) error

	GetWatcher(key string, timeSleep time.Duration) <-chan []policy.NumericIdentity

	Status() (string, error)

	// Get returns value of key
	Get(key string) ([]byte, error)

	// GetPrefix returns the first key which matches the prefix
	GetPrefix(prefix string) ([]byte, error)

	// Set sets value of key
	Set(key string, value []byte) error

	// Delete deletes a key
	Delete(key string) error

	// CreateOnly atomically creates a key or fails if it already exists
	CreateOnly(key string, value []byte, lease bool) error

	// ListPrefix returns a list of keys matching the prefix
	ListPrefix(prefix string) (KeyValuePairs, error)

	// Watch starts watching for changes in a prefix. If list is true, the
	// current keys matching the prefix will be listed and reported as new
	// keys first.
	Watch(w *Watcher, list bool)

	// CreateLease creates a lease with the specified ttl
	CreateLease(ttl time.Duration) (interface{}, error)

	// KeepAlive keeps a lease previously created with CreateLease alive
	KeepAlive(lease interface{}) error

	// DeleteLease deletes a lease
	DeleteLease(interface{}) error

	// Close closes the kvstore client
	Close()
}

// Get returns value of key
func Get(key string) ([]byte, error) {
	v, err := Client().Get(key)
	trace("Get", err, log.Fields{fieldKey: key, fieldValue: string(v)})
	return v, err
}

// GetPrefix returns the first key which matches the prefix
func GetPrefix(prefix string) ([]byte, error) {
	v, err := Client().GetPrefix(prefix)
	trace("GetPrefix", err, log.Fields{fieldPrefix: prefix, fieldValue: string(v)})
	return v, err
}

// ListPrefix returns the list of keys matching the prefix
func ListPrefix(prefix string) (KeyValuePairs, error) {
	v, err := Client().ListPrefix(prefix)
	trace("ListPrefix", err, log.Fields{fieldPrefix: prefix, fieldNumEntries: len(v)})
	return v, err
}

// CreateOnly atomically creates a key or fails if it already exists
func CreateOnly(key string, value []byte, lease bool) error {
	err := Client().CreateOnly(key, value, lease)
	trace("CreateOnly", err, log.Fields{fieldKey: key, fieldValue: string(value), fieldAttachLease: lease})
	return err
}

// Set sets the value of a key
func Set(key string, value []byte) error {
	err := Client().Set(key, value)
	trace("Set", err, log.Fields{fieldKey: key, fieldValue: string(value)})
	return err
}

// Delete deletes a key
func Delete(key string) error {
	err := Client().Delete(key)
	trace("Delete", err, log.Fields{fieldKey: key})
	return err
}

// DeleteTree deletes all keys matching a prefix
func DeleteTree(prefix string) error {
	err := Client().DeleteTree(prefix)
	trace("DeleteTree", err, log.Fields{fieldPrefix: prefix})
	return err
}

// KeyValuePairs is a map of key=value pairs
type KeyValuePairs map[string][]byte
