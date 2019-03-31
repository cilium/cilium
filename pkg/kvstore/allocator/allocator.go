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

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "kvstore-allocator")
)

func NewKVStoreBackend(basePath, suffix string, typ allocator.AllocatorKey) (*kvstoreBackend, error) {
	if kvstore.Client() == nil {
		return nil, fmt.Errorf("kvstore client not configured")
	}

	return &kvstoreBackend{
		basePrefix:  basePath,
		idPrefix:    path.Join(basePath, "id"),
		valuePrefix: path.Join(basePath, "value"),
		lockPrefix:  path.Join(basePath, "locks"),
		suffix:      suffix,
		keyType:     typ,
		lockless:    locklessCapability(),
	}, nil
}

type kvstoreBackend struct {
	// lockless is true if allocation can be done lockless. This depends on
	// the underlying kvstore backend
	lockless bool

	// basePrefix is the prefix in the kvstore that all keys share which
	// are being managed by this allocator. The basePrefix typically
	// consists of something like: "space/project/allocatorName"
	basePrefix string

	// idPrefix is the kvstore key prefix for all master keys. It is being
	// derived from the basePrefix.
	idPrefix string

	// valuePrefix is the kvstore key prefix for all slave keys. It is
	// being derived from the basePrefix.
	valuePrefix string

	// slaveKeysMutex protects the concurrent access of the slave key by this
	// agent.
	slaveKeysMutex lock.Mutex

	// lockPrefix is the prefix to use for all kvstore locks. This prefix
	// is different from the idPrefix and valuePrefix to simplify watching
	// for ID and key changes.
	lockPrefix string

	// suffix is the suffix attached to keys which must be node specific,
	// this is typical set to the node's IP address
	suffix string

	// deleteInvalidPrefixes enables deletion of identities outside of the
	// valid prefix
	deleteInvalidPrefixes bool

	keyType allocator.AllocatorKey
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

func (k *kvstoreBackend) createValueNodeKey(ctx context.Context, key string, newID idpool.ID) error {
	// add a new key /value/<key>/<node> to account for the reference
	// The key is protected with a TTL/lease and will expire after LeaseTTL
	valueKey := path.Join(k.valuePrefix, key, k.suffix)
	if _, err := kvstore.UpdateIfDifferent(ctx, valueKey, []byte(newID.String()), true); err != nil {
		return fmt.Errorf("unable to create value-node key '%s': %s", valueKey, err)
	}

	return nil
}

// Lock locks a key in the scope of an allocator
func (k *kvstoreBackend) lock(ctx context.Context, key string) (*kvstore.Lock, error) {
	suffix := strings.TrimPrefix(key, k.basePrefix)
	return kvstore.LockPath(ctx, path.Join(k.lockPrefix, suffix))
}

// Lock locks a key in the scope of an allocator
func (k *kvstoreBackend) Lock(ctx context.Context, key allocator.AllocatorKey) (allocator.Lock, error) {
	return k.lock(ctx, key.GetKey())
}

// DeleteAllKeys will delete all keys
func (k *kvstoreBackend) DeleteAllKeys() {
	kvstore.DeletePrefix(k.basePrefix)
}

func (k *kvstoreBackend) AllocateID(ctx context.Context, id idpool.ID, key allocator.AllocatorKey) error {
	// create /id/<ID> and fail if it already exists
	keyPath := path.Join(k.idPrefix, id.String())
	success, err := kvstore.CreateOnly(ctx, keyPath, []byte(key.GetKey()), false)
	if err != nil || !success {
		return fmt.Errorf("unable to create master key '%s': %s", keyPath, err)
	}

	return nil
}

func (k *kvstoreBackend) AcquireReference(ctx context.Context, id idpool.ID, key allocator.AllocatorKey) error {
	keyString := key.GetKey()
	if err := k.createValueNodeKey(ctx, keyString, id); err != nil {
		return fmt.Errorf("unable to create slave key '%s': %s", keyString, err)
	}

	return nil
}

// RunGC scans the kvstore for unused master keys and removes them
func (k *kvstoreBackend) RunGC(staleKeysPrevRound map[string]uint64) (map[string]uint64, error) {
	// fetch list of all /id/ keys
	allocated, err := kvstore.ListPrefix(k.idPrefix)
	if err != nil {
		return nil, fmt.Errorf("list failed: %s", err)
	}

	staleKeys := map[string]uint64{}

	// iterate over /id/
	for key, v := range allocated {
		// if a.lockless {
		// FIXME: Add DeleteOnZeroCount support
		// }

		lock, err := k.lock(context.Background(), key)
		if err != nil {
			log.WithError(err).WithField(fieldKey, key).Warning("allocator garbage collector was unable to lock key")
			continue
		}

		// fetch list of all /value/<key> keys
		valueKeyPrefix := path.Join(k.valuePrefix, string(v.Data))
		pairs, err := kvstore.ListPrefix(valueKeyPrefix)
		if err != nil {
			log.WithError(err).WithField(fieldPrefix, valueKeyPrefix).Warning("allocator garbage collector was unable to list keys")
			lock.Unlock()
			continue
		}

		hasUsers := false
		for k := range pairs {
			if prefixMatchesKey(valueKeyPrefix, k) {
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
				if err := kvstore.Delete(key); err != nil {
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

func (k *kvstoreBackend) UpdateKey(id idpool.ID, key allocator.AllocatorKey, reliablyMissing bool) {
	var (
		err       error
		recreated bool
		keyPath   = path.Join(k.idPrefix, id.String())
		valueKey  = path.Join(k.valuePrefix, key.GetKey(), k.suffix)
	)

	// Use of CreateOnly() ensures that any existing potentially
	// conflicting key is never overwritten.
	success, err := kvstore.CreateOnly(context.TODO(), keyPath, []byte(key.GetKey()), false)
	switch {
	case err != nil:
		log.WithError(err).WithField(fieldKey, keyPath).Warning("Unable to re-create missing master key")
	case success:
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

// Get returns the ID which is allocated to a key in the kvstore
func (k *kvstoreBackend) Get(ctx context.Context, key allocator.AllocatorKey) (idpool.ID, error) {
	prefix := path.Join(k.valuePrefix, key.GetKey())
	_, value, err := kvstore.GetPrefix(ctx, prefix)
	kvstore.Trace("AllocateGet", err, logrus.Fields{fieldPrefix: prefix, fieldValue: value})
	if err != nil || value == nil {
		return 0, err
	}

	id, err := strconv.ParseUint(string(value), 10, 64)
	if err != nil {
		return idpool.NoID, fmt.Errorf("unable to parse value '%s': %s", value, err)
	}

	return idpool.ID(id), nil
}

// GetByID returns the key associated with an ID. Returns nil if no key is
// associated with the ID.
func (k *kvstoreBackend) GetByID(id idpool.ID) (allocator.AllocatorKey, error) {
	v, err := kvstore.Get(path.Join(k.idPrefix, id.String()))
	if err != nil {
		return nil, err
	}

	return k.keyType.PutKey(string(v))
}

// Release releases the use of an ID associated with the provided key. After
// the last user has released the ID, the key is removed in the KVstore and
// the returned lastUse value is true.
func (k *kvstoreBackend) Release(ctx context.Context, key allocator.AllocatorKey) error {
	valueKey := path.Join(k.valuePrefix, key.GetKey(), k.suffix)
	if err := kvstore.Delete(valueKey); err != nil {
		log.WithError(err).WithFields(logrus.Fields{fieldKey: key}).Warning("Ignoring node specific ID")
		return err
	}

	return nil
}

func invalidKey(key, prefix string, deleteInvalid bool) {
	log.WithFields(logrus.Fields{fieldKey: key, fieldPrefix: prefix}).Warning("Found invalid key outside of prefix")

	if deleteInvalid {
		kvstore.Delete(key)
	}
}

func (k *kvstoreBackend) keyToID(key string, deleteInvalid bool) idpool.ID {
	if !strings.HasPrefix(key, k.idPrefix) {
		invalidKey(key, k.idPrefix, deleteInvalid)
		return idpool.NoID
	}

	suffix := strings.TrimPrefix(key, k.idPrefix)
	if suffix[0] == '/' {
		suffix = suffix[1:]
	}

	id, err := strconv.ParseUint(suffix, 10, 64)
	if err != nil {
		invalidKey(key, k.idPrefix, deleteInvalid)
		return idpool.NoID
	}

	return idpool.ID(id)
}

func (k *kvstoreBackend) ListAndWatch(handler allocator.CacheMutations, stopChan chan struct{}) {
	watcher := kvstore.ListAndWatch(k.idPrefix, k.idPrefix, 512)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				goto abort
			}
			if event.Typ == kvstore.EventTypeListDone {
				handler.OnListDone()
				continue
			}

			id := k.keyToID(event.Key, k.deleteInvalidPrefixes)
			if id != 0 {
				var key allocator.AllocatorKey

				if len(event.Value) > 0 {
					var err error
					key, err = k.keyType.PutKey(string(event.Value))
					if err != nil {
						log.WithError(err).WithField(fieldKey, event.Value).
							Warning("Unable to unmarshal allocator key")
					}
				}

				switch event.Typ {
				case kvstore.EventTypeCreate:
					handler.OnAdd(id, key)

				case kvstore.EventTypeModify:
					handler.OnModify(id, key)

				case kvstore.EventTypeDelete:
					handler.OnDelete(id, key)
				}
			}

		case <-stopChan:
			goto abort
		}
	}

abort:
	watcher.Stop()
}

func (k *kvstoreBackend) Status() (string, error) {
	return kvstore.Client().Status()
}
