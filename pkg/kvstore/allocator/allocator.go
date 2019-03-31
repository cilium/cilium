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

package allocator

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "kvstorebackend")
)

const (
	// maxAllocAttempts is the number of attempted allocation requests
	// performed before failing.
	maxAllocAttempts = 16

	// listTimeout is the time to wait for the initial list operation to
	// succeed when creating a new allocator
	listTimeout = 3 * time.Minute
)

type KVStoreBackend struct {
	// lockless is true if allocation can be done lockless. This depends on
	// the underlying kvstore backend
	lockless bool

	// basePrefix is the prefix in the kvstore that all keys share which
	// are being managed by this allocator. The basePrefix typically
	// consists of something like: "space/project/allocatorName"
	basePrefix string

	// IDPrefix is the kvstore key prefix for all master keys. It is being
	// derived from the basePrefix.
	IDPrefix string

	// valuePrefix is the kvstore key prefix for all slave keys. It is
	// being derived from the basePrefix.
	valuePrefix string

	// lockPrefix is the prefix to use for all kvstore locks. This prefix
	// is different from the IDPrefix and valuePrefix to simplify watching
	// for ID and key changes.
	lockPrefix string

	// suffix is the suffix attached to keys which must be node specific,
	// this is typical set to the node's IP address
	suffix string

	keyType AllocatorKey
}

func locklessCapability() bool {
	required := kvstore.CapabilityCreateIfExists | kvstore.CapabilityDeleteOnZeroCount
	return kvstore.GetCapabilities()&required == required
}

func prefixMatchesKey(prefix, key string) bool {
	// cilium/state/identities/v1/value/label;foo;bar;/172.0.124.60
	lastSlash := strings.LastIndex(key, "/")
	return len(prefix) == lastSlash
}

// NewKVStoreBackend creates a wrappper for kvstore access. It is used by
// pkg/allocator.Allocator compatible instance. The specific kvstore used is
// configured in pkg/kvstore.
func NewKVStoreBackend(basePath, suffix string, typ AllocatorKey) (*KVStoreBackend, error) {
	if kvstore.Client() == nil {
		return nil, fmt.Errorf("kvstore client not configured")
	}

	return &KVStoreBackend{
		basePrefix:  basePath,
		IDPrefix:    path.Join(basePath, "id"),
		valuePrefix: path.Join(basePath, "value"),
		lockPrefix:  path.Join(basePath, "locks"),
		suffix:      suffix,
		keyType:     typ,
		lockless:    locklessCapability(),
	}, nil
}

// lockPath locks a key in the scope of an allocator
func (k *KVStoreBackend) LockPath(ctx context.Context, key string) (*kvstore.Lock, error) {
	suffix := strings.TrimPrefix(key, k.basePrefix)
	return kvstore.LockPath(ctx, path.Join(k.lockPrefix, suffix))
}

// DeleteAllKeys will delete all keys
func (k *KVStoreBackend) DeleteAllKeys() {
	kvstore.DeletePrefix(k.basePrefix)
}

// AllocatorKey is the interface to implement in order for a type to be used as
// key for the allocator. The key's data is assumed to be a collection of
// pkg/label.Label, and the functions reflect this somewhat.
type AllocatorKey interface {
	// GetKey returns the canonical string representation of the key
	GetKey() string

	// PutKey stores the information in v into the key. This is is the inverse
	// operation to GetKey
	PutKey(v string) (AllocatorKey, error)

	// String must return the key in human readable string representation
	String() string
}

// CreateValueKey records that this "node" is using this key->ID
func (k *KVStoreBackend) CreateValueNodeKey(ctx context.Context, key string, newID idpool.ID, lock kvstore.KVLocker) error {
	// add a new key /value/<key>/<node> to account for the reference
	// The key is protected with a TTL/lease and will expire after LeaseTTL
	valueKey := path.Join(k.valuePrefix, key, k.suffix)
	if _, err := kvstore.UpdateIfDifferentIfLocked(ctx, valueKey, []byte(newID.String()), true, lock); err != nil {
		return fmt.Errorf("unable to create value-node key '%s': %s", valueKey, err)
	}

	return nil
}

// Get returns the ID which is allocated to a key in the kvstore
func (k *KVStoreBackend) Get(ctx context.Context, key AllocatorKey) (idpool.ID, error) {
	// ListPrefix() will return all keys matching the prefix, the prefix
	// can cover multiple different keys, example:
	//
	// key1 := label1;label2;
	// key2 := label1;label2;label3;
	//
	// In order to retrieve the correct key, the position of the last '/'
	// is significant, e.g.
	//
	// prefix := cilium/state/identities/v1/value/label;foo;
	//
	// key1 := cilium/state/identities/v1/value/label;foo;/172.0.124.60
	// key2 := cilium/state/identities/v1/value/label;foo;bar;/172.0.124.60
	//
	// Only key1 should match
	prefix := path.Join(k.valuePrefix, key.GetKey())
	pairs, err := kvstore.ListPrefix(prefix)
	kvstore.Trace("ListPrefix", err, logrus.Fields{fieldPrefix: prefix, "entries": len(pairs)})
	if err != nil {
		return 0, err
	}

	for k, v := range pairs {
		if prefixMatchesKey(prefix, k) {
			id, err := strconv.ParseUint(string(v.Data), 10, 64)
			if err == nil {
				return idpool.ID(id), nil
			}
		}
	}

	return idpool.NoID, nil
}

// CreateOnlyIfLocked atomically creates a key if the client is still holding the given lock or fails if it already exists
func (k *KVStoreBackend) CreateOnlyIfLocked(ctx context.Context, key string, value []byte, lease bool, lock kvstore.KVLocker) (bool, error) {
	return kvstore.CreateOnlyIfLocked(ctx, key, value, lease, lock)
}

// GetIfLocked returns the ID which is allocated to a key in the kvstore
// if the client is still holding the given lock.
func (k *KVStoreBackend) GetIfLocked(ctx context.Context, key AllocatorKey, lock kvstore.KVLocker) (idpool.ID, error) {
	// ListPrefixIfLocked() will return all keys matching the prefix, the prefix
	// can cover multiple different keys, example:
	//
	// key1 := label1;label2;
	// key2 := label1;label2;label3;
	//
	// In order to retrieve the correct key, the position of the last '/'
	// is significant, e.g.
	//
	// prefix := cilium/state/identities/v1/value/label;foo;
	//
	// key1 := cilium/state/identities/v1/value/label;foo;/172.0.124.60
	// key2 := cilium/state/identities/v1/value/label;foo;bar;/172.0.124.60
	//
	// Only key1 should match
	prefix := path.Join(k.valuePrefix, key.GetKey())
	pairs, err := kvstore.ListPrefixIfLocked(prefix, lock)
	kvstore.Trace("ListPrefixLocked", err, logrus.Fields{fieldPrefix: prefix, "entries": len(pairs)})
	if err != nil {
		return 0, err
	}

	for k, v := range pairs {
		if prefixMatchesKey(prefix, k) {
			id, err := strconv.ParseUint(string(v.Data), 10, 64)
			if err == nil {
				return idpool.ID(id), nil
			}
		}
	}

	return idpool.NoID, nil
}

// GetByID returns the key associated with an ID. Returns nil if no key is
// associated with the ID.
func (k *KVStoreBackend) GetByID(id idpool.ID) (AllocatorKey, error) {
	v, err := kvstore.Get(path.Join(k.IDPrefix, id.String()))
	if err != nil {
		return nil, err
	}

	return k.keyType.PutKey(string(v))
}

func (a *KVStoreBackend) RecreateMasterKey(id idpool.ID, value string, reliablyMissing bool) {
	var (
		err       error
		recreated bool
		keyPath   = path.Join(a.IDPrefix, id.String())
		valueKey  = path.Join(a.valuePrefix, value, a.suffix)
	)

	if reliablyMissing {
		recreated, err = kvstore.CreateOnly(context.TODO(), keyPath, []byte(value), false)
	} else {
		recreated, err = kvstore.UpdateIfDifferent(context.TODO(), keyPath, []byte(value), false)
	}
	switch {
	case err != nil:
		log.WithError(err).WithField(fieldKey, keyPath).Warning("Unable to re-create missing master key")
	case recreated:
		log.WithField(fieldKey, keyPath).Warning("Re-created missing master key")
	}

	// Also re-create the slave key in case it has been deleted. This will
	// ensure that the next garbage collection cycle of any participating
	// node does not remove the master key again.
	if reliablyMissing {
		recreated, err = kvstore.CreateOnly(context.TODO(), valueKey, []byte(id.String()), true)
	} else {
		recreated, err = kvstore.UpdateIfDifferent(context.TODO(), valueKey, []byte(id.String()), true)
	}
	switch {
	case err != nil:
		log.WithError(err).WithField(fieldKey, valueKey).Warning("Unable to re-create missing slave key")
	case recreated:
		log.WithField(fieldKey, valueKey).Warning("Re-created missing slave key")
	}
}

// Release releases the use of an ID associated with the provided key.  It does
// not guard against concurrent releases. This is currently guarded by
// Allocator.slaveKeysMutex when called from pkg/allocator.Allocator.Release.
func (k *KVStoreBackend) Release(ctx context.Context, key AllocatorKey) (err error) {
	log.WithField(fieldKey, key).Info("Releasing key")
	valueKey := path.Join(k.valuePrefix, key.GetKey(), k.suffix)
	log.WithField(fieldKey, key).Info("Released last local use of key, invoking global release")

	// does not need to be deleted with a lock as its protected by the
	// Allocator.slaveKeysMutex
	if err := kvstore.Delete(valueKey); err != nil {
		log.WithError(err).WithFields(logrus.Fields{fieldKey: key}).Warning("Ignoring node specific ID")
		return err
	}

	// if k.lockless {
	// FIXME: etcd 3.3 will make it possible to do a lockless
	// cleanup of the ID and release it right away. For now we rely
	// on the GC to kick in a release unused IDs.
	// }

	return nil
}

// RunGC scans the kvstore for unused master keys and removes them
func (k *KVStoreBackend) RunGC(staleKeysPrevRound map[string]uint64) (map[string]uint64, error) {
	// fetch list of all /id/ keys
	allocated, err := kvstore.ListPrefix(k.IDPrefix)
	if err != nil {
		return nil, fmt.Errorf("list failed: %s", err)
	}

	staleKeys := map[string]uint64{}

	// iterate over /id/
	for key, v := range allocated {
		// if k.lockless {
		// FIXME: Add DeleteOnZeroCount support
		// }

		lock, err := k.LockPath(context.Background(), key)
		if err != nil {
			log.WithError(err).WithField(fieldKey, key).Warning("allocator garbage collector was unable to lock key")
			continue
		}

		// fetch list of all /value/<key> keys
		valueKeyPrefix := path.Join(k.valuePrefix, string(v.Data))
		pairs, err := kvstore.ListPrefixIfLocked(valueKeyPrefix, lock)
		if err != nil {
			log.WithError(err).WithField(fieldPrefix, valueKeyPrefix).Warning("allocator garbage collector was unable to list keys")
			lock.Unlock()
			continue
		}

		hasUsers := false
		for prefix := range pairs {
			if prefixMatchesKey(valueKeyPrefix, prefix) {
				hasUsers = true
				break
			}
		}

		// if ID has no user, delete it
		if !hasUsers {
			scopedLog := log.WithFields(logrus.Fields{
				fieldKey: key,
				fieldID:  path.Base(key),
			})
			// Only delete if this key was previously marked as to be deleted
			if modRev, ok := staleKeysPrevRound[key]; ok && modRev == v.ModRevision {
				if err := kvstore.DeleteIfLocked(key, lock); err != nil {
					scopedLog.WithError(err).Warning("Unable to delete unused allocator master key")
				} else {
					scopedLog.Info("Deleted unused allocator master key")
				}
			} else {
				// If the key was not found mark it to be delete in the next RunGC
				staleKeys[key] = v.ModRevision
			}
		}

		lock.Unlock()
	}

	return staleKeys, nil
}

func (k *KVStoreBackend) keyToID(key string) (id idpool.ID, err error) {
	if !strings.HasPrefix(key, k.IDPrefix) {
		return idpool.NoID, fmt.Errorf("Found invalid key \"%s\" outside of prefix \"%s\"", key, k.IDPrefix)
	}

	suffix := strings.TrimPrefix(key, k.IDPrefix)
	if suffix[0] == '/' {
		suffix = suffix[1:]
	}

	idParsed, err := strconv.ParseUint(suffix, 10, 64)
	if err != nil {
		return idpool.NoID, fmt.Errorf("Cannot parse key suffix \"%s\"", suffix)
	}

	return idpool.ID(idParsed), nil
}
