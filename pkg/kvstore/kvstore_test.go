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
	"testing"
	"time"

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/policy"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

type KVStoreSuite struct{}

var _ = Suite(&KVStoreSuite{})

func (s *KvstoreSuite) TestLock(c *C) {
	DeleteTree("locktest/")

	lock, err := LockPath("locktest/foo")
	c.Assert(err, IsNil)
	c.Assert(lock, Not(IsNil))
	lock.Unlock()
}

type KVLockerMocker struct {
	OnUnlock func() error
}

func (l KVLockerMocker) Unlock() error {
	if l.OnUnlock != nil {
		return l.OnUnlock()
	}
	panic("Unlock should not have been called")
}

type KVStoreMocker struct {
	OnLockPath         func(path string) (kvLocker, error)
	OnGetValue         func(k string) (json.RawMessage, error)
	OnSetValue         func(k string, v interface{}) error
	OnInitializeFreeID func(path string, firstID uint32) error
	OnGetMaxID         func(key string, firstID uint32) (uint32, error)
	OnSetMaxID         func(key string, firstID, maxID uint32) error

	OnGASNewSecLabelID func(baseKeyPath string, baseID uint32, secCtxLabels *policy.Identity) error
	OnGASNewL3n4AddrID func(basePath string, baseID uint32, lAddrID *types.L3n4AddrID) error

	OnDeleteTree func(path string) error

	OnGetWatcher func(key string, timeSleep time.Duration) <-chan []policy.NumericIdentity

	OnStatus func() (string, error)

	// Get returns value of key
	OnGet func(key string) ([]byte, error)

	// GetPrefix returns the first key which matches the prefix
	OnGetPrefix func(prefix string) ([]byte, error)

	// Set sets value of key
	OnSet func(key string, value []byte) error

	// Delete deletes a key
	OnDelete func(key string) error

	// CreateOnly atomically creates a key or fails if it already exists
	OnCreateOnly func(key string, value []byte, lease bool) error

	// ListPrefix returns a list of keys matching the prefix
	OnListPrefix func(prefix string) (KeyValuePairs, error)

	// Watch starts watching for changes in a prefix. If list is true, the
	// current keys matching the prefix will be listed and reported as new
	// keys first.
	OnWatch func(w *Watcher, list bool)

	// CreateLease creates a lease with the specified ttl
	OnCreateLease func(ttl time.Duration) (interface{}, error)

	// KeepAlive keeps a lease previously created with CreateLease alive
	OnKeepAlive func(lease interface{}) error

	// DeleteLease deletes a lease
	OnDeleteLease func(interface{}) error

	// Close closes the kvstore client
	OnClose func()
}

func (kv *KVStoreMocker) LockPath(path string) (kvLocker, error) {
	if kv.OnLockPath != nil {
		return kv.OnLockPath(path)
	}
	panic("LockPath should not have been called")
}

func (kv *KVStoreMocker) GetValue(k string) (json.RawMessage, error) {
	if kv.OnGetValue != nil {
		return kv.OnGetValue(k)
	}
	panic("GetValue should not have been called")
}

func (kv *KVStoreMocker) SetValue(k string, v interface{}) error {
	if kv.OnSetValue != nil {
		return kv.OnSetValue(k, v)
	}
	panic("SetValue should not have been called")
}

func (kv *KVStoreMocker) InitializeFreeID(path string, firstID uint32) error {
	if kv.OnInitializeFreeID != nil {
		return kv.OnInitializeFreeID(path, firstID)
	}
	panic("InitializeFreeID should not have been called")
}

func (kv *KVStoreMocker) GetMaxID(key string, firstID uint32) (uint32, error) {
	if kv.OnGetMaxID != nil {
		return kv.OnGetMaxID(key, firstID)
	}
	panic("GetMaxID should not have been called")
}

func (kv *KVStoreMocker) SetMaxID(key string, firstID, maxID uint32) error {
	if kv.OnSetMaxID != nil {
		return kv.OnSetMaxID(key, firstID, maxID)
	}
	panic("SetMaxID should not have been called")
}

func (kv *KVStoreMocker) GASNewSecLabelID(baseKeyPath string, baseID uint32, secCtxLabels *policy.Identity) error {
	if kv.OnGASNewSecLabelID != nil {
		return kv.OnGASNewSecLabelID(baseKeyPath, baseID, secCtxLabels)
	}
	panic("GASNewSecLabelID should not have been called")
}

func (kv *KVStoreMocker) GASNewL3n4AddrID(basePath string, baseID uint32, lAddrID *types.L3n4AddrID) error {
	if kv.OnGASNewL3n4AddrID != nil {
		return kv.OnGASNewL3n4AddrID(basePath, baseID, lAddrID)
	}
	panic("GASNewL3n4AddrID should not have been called")
}

func (kv *KVStoreMocker) DeleteTree(path string) error {
	if kv.OnDeleteTree != nil {
		return kv.OnDeleteTree(path)
	}
	panic("DeleteTree should not have been called")
}

func (kv *KVStoreMocker) GetWatcher(key string, timeSleep time.Duration) <-chan []policy.NumericIdentity {
	if kv.OnGetWatcher != nil {
		return kv.OnGetWatcher(key, timeSleep)
	}
	panic("GetWatcher should not have been called")
}

func (kv *KVStoreMocker) Status() (string, error) {
	if kv.OnStatus != nil {
		return kv.OnStatus()
	}
	panic("Status should not have been called")
}

func (kv *KVStoreMocker) Get(key string) ([]byte, error) {
	if kv.OnGet != nil {
		return kv.OnGet(key)
	}
	panic("Get should not have been called")
}

func (kv *KVStoreMocker) GetPrefix(prefix string) ([]byte, error) {
	if kv.OnGetPrefix != nil {
		return kv.OnGetPrefix(prefix)
	}
	panic("GetPrefix should not have been called")
}

func (kv *KVStoreMocker) Set(key string, value []byte) error {
	if kv.OnSet != nil {
		return kv.OnSet(key, value)
	}
	panic("Set should not have been called")
}

func (kv *KVStoreMocker) Delete(key string) error {
	if kv.OnDelete != nil {
		return kv.OnDelete(key)
	}
	panic("Delete should not have been called")
}

func (kv *KVStoreMocker) CreateOnly(key string, value []byte, lease bool) error {
	if kv.OnCreateOnly != nil {
		return kv.OnCreateOnly(key, value, lease)
	}
	panic("CreateOnly should not have been called")
}

func (kv *KVStoreMocker) ListPrefix(prefix string) (KeyValuePairs, error) {
	if kv.OnListPrefix != nil {
		return kv.OnListPrefix(prefix)
	}
	panic("ListPrefix should not have been called")
}

func (kv *KVStoreMocker) Watch(w *Watcher, list bool) {
	if kv.OnWatch != nil {
		kv.OnWatch(w, list)
		return
	}
	panic("Watch should not have been called")
}

func (kv *KVStoreMocker) CreateLease(ttl time.Duration) (interface{}, error) {
	if kv.OnCreateLease != nil {
		return kv.OnCreateLease(ttl)
	}
	panic("CreateLease should not have been called")
}

func (kv *KVStoreMocker) KeepAlive(lease interface{}) error {
	if kv.OnKeepAlive != nil {
		return kv.OnKeepAlive(lease)
	}
	panic("KeepAlive should not have been called")
}

func (kv *KVStoreMocker) DeleteLease(i interface{}) error {
	if kv.OnDeleteLease != nil {
		return kv.OnDeleteLease(i)
	}
	panic("DeleteLease should not have been called")
}

func (kv *KVStoreMocker) Close() {
	if kv.OnClose != nil {
		kv.OnClose()
		return
	}
	panic("Close should not have been called")
}
