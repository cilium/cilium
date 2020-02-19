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

package allocator

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/allocator"
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

// kvstoreBackend is an implentaton of pkg/allocator.Backend. It store
// identities in the following format:
//
// Slave keys:
//   Slave keys are owned by individual nodes:
//     - basePath/value/key1/node1 => 1001
//     - basePath/value/key1/node2 => 1001
//     - basePath/value/key2/node1 => 1002
//     - basePath/value/key2/node2 => 1002
//
//   If at least one key exists with the prefix basePath/value/keyN then that
//   key must be considered to be in use in the allocation space.
//
//   Slave keys are protected by a lease and will automatically get removed
//   after ~ option.Config.KVstoreLeaseTTL if the node does not renew in time.
//
// Master key:
//    - basePath/id/1001 => key1
//    - basePath/id/1002 => key2
//
//   Master keys provide the mapping from ID to key. As long as a master key
//   for an ID exists, the ID is still in use. However, if a master key is no
//   longer backed by at least one slave key, the garbage collector will
//   eventually release the master key and return it back to the pool.
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

	backend kvstore.BackendOperations

	keyType allocator.AllocatorKey
}

func locklessCapability(backend kvstore.BackendOperations) bool {
	required := kvstore.CapabilityCreateIfExists | kvstore.CapabilityDeleteOnZeroCount
	return backend.GetCapabilities()&required == required
}

func prefixMatchesKey(prefix, key string) bool {
	// cilium/state/identities/v1/value/label;foo;bar;/172.0.124.60
	lastSlash := strings.LastIndex(key, "/")
	return len(prefix) == lastSlash
}

// NewKVStoreBackend creates a pkg/allocator.Backend compatible instance. The
// specific kvstore used is configured in pkg/kvstore.
func NewKVStoreBackend(basePath, suffix string, typ allocator.AllocatorKey, backend kvstore.BackendOperations) (*kvstoreBackend, error) {
	if backend == nil {
		return nil, fmt.Errorf("kvstore client not configured")
	}

	return &kvstoreBackend{
		basePrefix:  basePath,
		idPrefix:    path.Join(basePath, "id"),
		valuePrefix: path.Join(basePath, "value"),
		lockPrefix:  path.Join(basePath, "locks"),
		suffix:      suffix,
		keyType:     typ,
		lockless:    locklessCapability(backend),
		backend:     backend,
	}, nil
}

// lockPath locks a key in the scope of an allocator
func (k *kvstoreBackend) lockPath(ctx context.Context, key string) (*kvstore.Lock, error) {
	suffix := strings.TrimPrefix(key, k.basePrefix)
	return kvstore.LockPath(ctx, path.Join(k.lockPrefix, suffix))
}

// DeleteAllKeys will delete all keys
func (k *kvstoreBackend) DeleteAllKeys() {
	kvstore.Client().DeletePrefix(k.basePrefix)
}

func (k *kvstoreBackend) encodeKey(key allocator.AllocatorKey) []byte {
	return []byte(k.backend.Encode([]byte(key.GetKey())))
}

// AllocateID allocates a key->ID mapping in the kvstore.
func (k *kvstoreBackend) AllocateID(ctx context.Context, id idpool.ID, key allocator.AllocatorKey) error {
	// create /id/<ID> and fail if it already exists
	keyPath := path.Join(k.idPrefix, id.String())
	success, err := k.backend.CreateOnly(ctx, keyPath, k.encodeKey(key), false)
	if err != nil || !success {
		return fmt.Errorf("unable to create master key '%s': %s", keyPath, err)
	}

	return nil
}

// AllocateID allocates a key->ID mapping in the kvstore.
func (k *kvstoreBackend) AllocateIDIfLocked(ctx context.Context, id idpool.ID, key allocator.AllocatorKey, lock kvstore.KVLocker) error {
	// create /id/<ID> and fail if it already exists
	keyPath := path.Join(k.idPrefix, id.String())
	success, err := k.backend.CreateOnlyIfLocked(ctx, keyPath, k.encodeKey(key), false, lock)
	if err != nil || !success {
		return fmt.Errorf("unable to create master key '%s': %s", keyPath, err)
	}

	return nil
}

// AcquireReference marks that this node is using this key->ID mapping in the kvstore.
func (k *kvstoreBackend) AcquireReference(ctx context.Context, id idpool.ID, key allocator.AllocatorKey, lock kvstore.KVLocker) error {
	keyString := string(k.encodeKey(key))
	if err := k.createValueNodeKey(ctx, keyString, id, lock); err != nil {
		return fmt.Errorf("unable to create slave key '%s': %s", keyString, err)
	}
	return nil
}

// createValueKey records that this "node" is using this key->ID
func (k *kvstoreBackend) createValueNodeKey(ctx context.Context, key string, newID idpool.ID, lock kvstore.KVLocker) error {
	// add a new key /value/<key>/<node> to account for the reference
	// The key is protected with a TTL/lease and will expire after LeaseTTL
	valueKey := path.Join(k.valuePrefix, key, k.suffix)
	if _, err := k.backend.UpdateIfDifferentIfLocked(ctx, valueKey, []byte(newID.String()), true, lock); err != nil {
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
func (k *kvstoreBackend) Lock(ctx context.Context, key allocator.AllocatorKey) (kvstore.KVLocker, error) {
	return k.lock(ctx, string(k.encodeKey(key)))
}

// Get returns the ID which is allocated to a key in the kvstore
func (k *kvstoreBackend) Get(ctx context.Context, key allocator.AllocatorKey) (idpool.ID, error) {
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
	prefix := path.Join(k.valuePrefix, string(k.encodeKey(key)))
	pairs, err := k.backend.ListPrefix(prefix)
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

// GetIfLocked returns the ID which is allocated to a key in the kvstore
// if the client is still holding the given lock.
func (k *kvstoreBackend) GetIfLocked(ctx context.Context, key allocator.AllocatorKey, lock kvstore.KVLocker) (idpool.ID, error) {
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
	prefix := path.Join(k.valuePrefix, string(k.encodeKey(key)))
	pairs, err := k.backend.ListPrefixIfLocked(prefix, lock)
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
func (k *kvstoreBackend) GetByID(id idpool.ID) (allocator.AllocatorKey, error) {
	v, err := k.backend.Get(path.Join(k.idPrefix, id.String()))
	if err != nil {
		return nil, err
	}

	s, err := k.backend.Decode(string(v))
	if err != nil {
		return nil, err
	}

	return k.keyType.PutKey(string(s)), nil
}

// UpdateKey refreshes the record that this node is using this key -> id
// mapping. When reliablyMissing is set it will also recreate missing master or
// slave keys.
func (k *kvstoreBackend) UpdateKey(ctx context.Context, id idpool.ID, key allocator.AllocatorKey, reliablyMissing bool) error {
	var (
		err       error
		recreated bool
		keyPath   = path.Join(k.idPrefix, id.String())
		valueKey  = path.Join(k.valuePrefix, string(k.encodeKey(key)), k.suffix)
	)

	// Use of CreateOnly() ensures that any existing potentially
	// conflicting key is never overwritten.
	success, err := k.backend.CreateOnly(ctx, keyPath, k.encodeKey(key), false)
	switch {
	case err != nil:
		return fmt.Errorf("Unable to re-create missing master key \"%s\" -> \"%s\": %s", fieldKey, valueKey, err)
	case success:
		log.WithField(fieldKey, keyPath).Warning("Re-created missing master key")
	}

	// Also re-create the slave key in case it has been deleted. This will
	// ensure that the next garbage collection cycle of any participating
	// node does not remove the master key again.
	if reliablyMissing {
		recreated, err = k.backend.CreateOnly(ctx, valueKey, []byte(id.String()), true)
	} else {
		recreated, err = k.backend.UpdateIfDifferent(ctx, valueKey, []byte(id.String()), true)
	}
	switch {
	case err != nil:
		return fmt.Errorf("Unable to re-create missing slave key \"%s\" -> \"%s\": %s", fieldKey, valueKey, err)
	case recreated:
		log.WithField(fieldKey, valueKey).Warning("Re-created missing slave key")
	}

	return nil
}

// UpdateKeyIfLocked refreshes the record that this node is using this key -> id
// mapping. When reliablyMissing is set it will also recreate missing master or
// slave keys.
func (k *kvstoreBackend) UpdateKeyIfLocked(ctx context.Context, id idpool.ID, key allocator.AllocatorKey, reliablyMissing bool, lock kvstore.KVLocker) error {
	var (
		err       error
		recreated bool
		keyPath   = path.Join(k.idPrefix, id.String())
		valueKey  = path.Join(k.valuePrefix, string(k.encodeKey(key)), k.suffix)
	)

	// Use of CreateOnly() ensures that any existing potentially
	// conflicting key is never overwritten.
	success, err := k.backend.CreateOnlyIfLocked(ctx, keyPath, k.encodeKey(key), false, lock)
	switch {
	case err != nil:
		return fmt.Errorf("Unable to re-create missing master key \"%s\" -> \"%s\": %s", fieldKey, valueKey, err)
	case success:
		log.WithField(fieldKey, keyPath).Warning("Re-created missing master key")
	}

	// Also re-create the slave key in case it has been deleted. This will
	// ensure that the next garbage collection cycle of any participating
	// node does not remove the master key again.
	// lock is ignored since the key doesn't exist.
	if reliablyMissing {
		recreated, err = k.backend.CreateOnly(ctx, valueKey, []byte(id.String()), true)
	} else {
		recreated, err = k.backend.UpdateIfDifferentIfLocked(ctx, valueKey, []byte(id.String()), true, lock)
	}
	switch {
	case err != nil:
		return fmt.Errorf("Unable to re-create missing slave key \"%s\" -> \"%s\": %s", fieldKey, valueKey, err)
	case recreated:
		log.WithField(fieldKey, valueKey).Warning("Re-created missing slave key")
	}

	return nil
}

// Release releases the use of an ID associated with the provided key.  It does
// not guard against concurrent releases. This is currently guarded by
// Allocator.slaveKeysMutex when called from pkg/allocator.Allocator.Release.
func (k *kvstoreBackend) Release(ctx context.Context, key allocator.AllocatorKey) (err error) {
	log.WithField(fieldKey, key).Info("Releasing key")
	valueKey := path.Join(k.valuePrefix, string(k.encodeKey(key)), k.suffix)
	log.WithField(fieldKey, key).Info("Released last local use of key, invoking global release")

	// does not need to be deleted with a lock as its protected by the
	// Allocator.slaveKeysMutex
	if err := k.backend.Delete(valueKey); err != nil {
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

// RunLocksGC scans the kvstore for unused locks and removes them. Returns
// a map of locks that are currently being held, including the ones that have
// failed to be GCed.
func (k *kvstoreBackend) RunLocksGC(staleKeysPrevRound map[string]kvstore.Value) (map[string]kvstore.Value, error) {
	// fetch list of all /../locks keys
	allocated, err := k.backend.ListPrefix(k.lockPrefix)
	if err != nil {
		return nil, fmt.Errorf("list failed: %s", err)
	}

	staleKeys := map[string]kvstore.Value{}

	// iterate over /../locks
	for key, v := range allocated {
		scopedLog := log.WithFields(logrus.Fields{
			fieldKey:     key,
			fieldLeaseID: fmt.Sprintf("%x", v.LeaseID),
		})
		// Only delete if this key was previously marked as to be deleted
		if modRev, ok := staleKeysPrevRound[key]; ok &&
			// comparing ModRevision ensures the same client is still holding
			// this lock since the last GC was called.
			modRev.ModRevision == v.ModRevision &&
			modRev.LeaseID == v.LeaseID &&
			modRev.SessionID == v.SessionID {
			if err := k.backend.Delete(key); err == nil {
				scopedLog.Warning("Forcefully removed distributed lock due to client staleness." +
					" Please check the connectivity between the KVStore and the client with that lease ID.")
				continue
			}
			scopedLog.WithError(err).
				Warning("Unable to remove distributed lock due to client staleness." +
					" Please check the connectivity between the KVStore and the client with that lease ID.")
		}
		// If the key was not found mark it to be delete in the next RunGC
		staleKeys[key] = kvstore.Value{
			ModRevision: v.ModRevision,
			LeaseID:     v.LeaseID,
			SessionID:   v.SessionID,
		}
	}

	return staleKeys, nil
}

// RunGC scans the kvstore for unused master keys and removes them
func (k *kvstoreBackend) RunGC(staleKeysPrevRound map[string]uint64) (map[string]uint64, error) {
	// fetch list of all /id/ keys
	allocated, err := k.backend.ListPrefix(k.idPrefix)
	if err != nil {
		return nil, fmt.Errorf("list failed: %s", err)
	}

	staleKeys := map[string]uint64{}

	// iterate over /id/
	for key, v := range allocated {
		// if k.lockless {
		// FIXME: Add DeleteOnZeroCount support
		// }

		lock, err := k.lockPath(context.Background(), key)
		if err != nil {
			log.WithError(err).WithField(fieldKey, key).Warning("allocator garbage collector was unable to lock key")
			continue
		}

		// fetch list of all /value/<key> keys
		valueKeyPrefix := path.Join(k.valuePrefix, string(v.Data))
		pairs, err := k.backend.ListPrefixIfLocked(valueKeyPrefix, lock)
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
				if err := k.backend.DeleteIfLocked(key, lock); err != nil {
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

func (k *kvstoreBackend) keyToID(key string) (id idpool.ID, err error) {
	if !strings.HasPrefix(key, k.idPrefix) {
		return idpool.NoID, fmt.Errorf("Found invalid key \"%s\" outside of prefix \"%s\"", key, k.idPrefix)
	}

	suffix := strings.TrimPrefix(key, k.idPrefix)
	if suffix[0] == '/' {
		suffix = suffix[1:]
	}

	idParsed, err := strconv.ParseUint(suffix, 10, 64)
	if err != nil {
		return idpool.NoID, fmt.Errorf("Cannot parse key suffix \"%s\"", suffix)
	}

	return idpool.ID(idParsed), nil
}

func (k *kvstoreBackend) ListAndWatch(handler allocator.CacheMutations, stopChan chan struct{}) {
	watcher := k.backend.ListAndWatch(k.idPrefix, k.idPrefix, 512)

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

			id, err := k.keyToID(event.Key)
			switch {
			case err != nil:
				log.WithError(err).WithField(fieldKey, event.Key).Warning("Invalid key")

				if k.deleteInvalidPrefixes {
					k.backend.Delete(event.Key)
				}

			case id != idpool.NoID:
				var key allocator.AllocatorKey

				if len(event.Value) > 0 {
					s, err := k.backend.Decode(string(event.Value))
					if err != nil {
						log.WithError(err).WithFields(logrus.Fields{
							fieldKey:   event.Key,
							fieldValue: event.Value,
						}).Warning("Unable to decode key value")
					} else {
						key = k.keyType.PutKey(string(s))
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
	return k.backend.Status()
}

func (k *kvstoreBackend) Encode(v string) string {
	return k.backend.Encode([]byte(v))
}
