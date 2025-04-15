// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// listTimeoutDefault is the default timeout to wait while performing
	// the initial list operation of objects from the kvstore
	listTimeoutDefault = 3 * time.Minute
)

var (
	controllers controller.Manager

	kvstoreSyncControllerGroup = controller.NewGroup("kvstore-sync")
)

// KeyCreator is the function to create a new empty Key instances. Store
// collaborators must implement this interface and provide the implementation
// in the Configuration structure.
type KeyCreator func() Key

// Configuration is the set of configuration parameters of a shared store.
type Configuration struct {
	// Prefix is the key prefix of the store shared by all keys. The prefix
	// is the unique identification of the store. Multiple collaborators
	// connected to the same kvstore cluster configuring stores with
	// matching prefixes will automatically form a shared store. This
	// parameter is required.
	Prefix string

	// SynchronizationInterval is the interval in which locally owned keys
	// are synchronized with the kvstore. This parameter is optional.
	SynchronizationInterval time.Duration

	// SharedKeyDeleteDelay is the delay before a shared key delete is
	// handled. This parameter is optional, and defaults to 0 if unset.
	SharedKeyDeleteDelay time.Duration

	// KeyCreator is called to allocate a Key instance when a new shared
	// key is discovered. This parameter is required.
	KeyCreator KeyCreator

	// Backend is the kvstore to use as a backend. This parameter is required.
	Backend kvstore.BackendOperations

	// Observer is the observe that will receive events on key mutations
	Observer Observer

	Context context.Context
}

// validate is invoked by JoinSharedStore to validate and complete the
// configuration. It returns nil when the configuration is valid.
func (c *Configuration) validate() error {
	if c.Prefix == "" {
		return fmt.Errorf("prefix must be specified")
	}

	if c.KeyCreator == nil {
		return fmt.Errorf("KeyCreator must be specified")
	}

	if c.SynchronizationInterval == 0 {
		c.SynchronizationInterval = option.Config.KVstorePeriodicSync
	}

	if c.Backend == nil {
		return fmt.Errorf("backend must be specified")
	}

	if c.Context == nil {
		c.Context = context.Background()
	}

	return nil
}

// SharedStore is an instance of a shared store. It is created with
// JoinSharedStore() and released with the SharedStore.Close() function.
type SharedStore struct {
	logger *slog.Logger
	// conf is a copy of the store configuration. This field is never
	// mutated after JoinSharedStore() so it is safe to access this without
	// a lock.
	conf Configuration

	// name is the name of the shared store. It is derived from the kvstore
	// prefix.
	name string

	// controllerName is the name of the controller used to synchronize
	// with the kvstore. It is derived from the name.
	controllerName string

	// backend is the backend as configured via Configuration
	backend kvstore.BackendOperations

	// mutex protects mutations to localKeys and sharedKeys
	mutex lock.RWMutex

	// localKeys is a map of keys that are owned by the local instance. All
	// local keys are synchronized with the kvstore. This map can be
	// modified with UpdateLocalKey() and DeleteLocalKey().
	localKeys map[string]LocalKey

	// sharedKeys is a map of all keys that either have been discovered
	// from remote collaborators or successfully shared local keys. This
	// map represents the state in the kvstore and is updated based on
	// kvstore events.
	sharedKeys map[string]Key

	// stop stops the kvstore watcher.
	stop context.CancelFunc

	wg sync.WaitGroup
}

// Observer receives events when objects in the store mutate
type Observer interface {
	// OnDelete is called when the key has been deleted from the shared store
	OnDelete(k NamedKey)

	// OnUpdate is called whenever a change has occurred in the data
	// structure represented by the key
	OnUpdate(k Key)
}

// NamedKey is an interface that a data structure must implement in order to
// be deleted from a SharedStore.
type NamedKey interface {
	// GetKeyName must return the name of the key. The name of the key must
	// be unique within the store and stable for a particular key. The name
	// of the key must be identical across agent restarts as the keys
	// remain in the kvstore.
	GetKeyName() string
}

// Key is the interface that a data structure must implement in order to be
// stored and shared as a key in a SharedStore.
type Key interface {
	NamedKey

	// Marshal is called to retrieve the byte slice representation of the
	// data represented by the key to store it in the kvstore. The function
	// must ensure that the underlying datatype is properly locked. It is
	// typically a good idea to use json.Marshal to implement this
	// function.
	Marshal() ([]byte, error)

	// Unmarshal is called when an update from the kvstore is received. The
	// prefix configured for the store is removed from the key, and the
	// byte slice passed to the function is coming from the Marshal
	// function from another collaborator. The function must unmarshal and
	// update the underlying data type. It is typically a good idea to use
	// json.Unmarshal to implement this function.
	Unmarshal(key string, data []byte) error
}

// LocalKey is a Key owned by the local store instance
type LocalKey interface {
	Key

	// DeepKeyCopy must return a deep copy of the key
	DeepKeyCopy() LocalKey
}

// KVPair represents a basic implementation of the LocalKey interface
type KVPair struct {
	Key   string
	Value []byte
}

func NewKVPair(key, value string) *KVPair { return &KVPair{Key: key, Value: []byte(value)} }
func KVPairCreator() Key                  { return &KVPair{} }

func (kv *KVPair) GetKeyName() string       { return kv.Key }
func (kv *KVPair) Marshal() ([]byte, error) { return kv.Value, nil }

func (kv *KVPair) Unmarshal(key string, data []byte) error {
	kv.Key, kv.Value = key, data
	return nil
}

// JoinSharedStore creates a new shared store based on the provided
// configuration. An error is returned if the configuration is invalid. The
// store is initialized with the contents of the kvstore. An error is returned
// if the contents cannot be retrieved synchronously from the kvstore. Starts a
// controller to continuously synchronize the store with the kvstore.
func JoinSharedStore(logger *slog.Logger, c Configuration) (*SharedStore, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}

	s := &SharedStore{
		logger:     logger,
		conf:       c,
		localKeys:  map[string]LocalKey{},
		sharedKeys: map[string]Key{},
		backend:    c.Backend,
	}

	// Wrap the context, so that we can subsequently stop the kvstore watcher.
	s.conf.Context, s.stop = context.WithCancel(s.conf.Context)

	s.name = "store-" + s.conf.Prefix
	s.logger = s.logger.With(logfields.Name, s.name)
	s.controllerName = "kvstore-sync-" + s.name

	if err := s.listAndStartWatcher(); err != nil {
		return nil, err
	}

	controllers.UpdateController(s.controllerName,
		controller.ControllerParams{
			Group: kvstoreSyncControllerGroup,
			DoFunc: func(ctx context.Context) error {
				return s.syncLocalKeys(ctx, true)
			},
			RunInterval: s.conf.SynchronizationInterval,
		},
	)

	return s, nil
}

func (s *SharedStore) onDelete(k NamedKey) {
	if s.conf.Observer != nil {
		s.conf.Observer.OnDelete(k)
	}
}

func (s *SharedStore) onUpdate(k Key) {
	if s.conf.Observer != nil {
		s.conf.Observer.OnUpdate(k)
	}
}

// Release frees all resources own by the store but leaves all keys in the
// kvstore intact
func (s *SharedStore) Release() {
	s.stop()
	s.wg.Wait()

	controllers.RemoveController(s.controllerName)
}

// Close stops participation with a shared store and removes all keys owned by
// this node in the kvstore. This stops the controller started by
// JoinSharedStore().
func (s *SharedStore) Close(ctx context.Context) {
	s.Release()

	for name, key := range s.localKeys {
		if err := s.backend.Delete(ctx, s.keyPath(key)); err != nil {
			s.logger.Warn("Unable to delete key in kvstore", logfields.Error, err)
		}

		delete(s.localKeys, name)
		// Since we have received our own notification we also need to remove
		// it from the shared keys.
		delete(s.sharedKeys, name)

		s.onDelete(key)
	}
}

// keyPath returns the absolute kvstore path of a key
func (s *SharedStore) keyPath(key NamedKey) string {
	// WARNING - STABLE API: The composition of the absolute key path
	// cannot be changed without breaking up and downgrades.
	return path.Join(s.conf.Prefix, key.GetKeyName())
}

// syncLocalKey synchronizes a key to the kvstore
func (s *SharedStore) syncLocalKey(ctx context.Context, key LocalKey, lease bool) error {
	jsonValue, err := key.Marshal()
	if err != nil {
		return err
	}

	// Update key in kvstore, overwrite an eventual existing key. If requested, attach
	// lease to expire entry when agent dies and never comes back up.
	if _, err := s.backend.UpdateIfDifferent(ctx, s.keyPath(key), jsonValue, lease); err != nil {
		return err
	}

	return nil
}

// syncLocalKeys synchronizes all local keys with the kvstore
func (s *SharedStore) syncLocalKeys(ctx context.Context, lease bool) error {
	// Create a copy of all local keys so we can unlock and sync to kvstore
	// without holding the lock
	s.mutex.RLock()
	keys := slices.Collect(maps.Values(s.localKeys))
	s.mutex.RUnlock()

	for _, key := range keys {
		if err := s.syncLocalKey(ctx, key, lease); err != nil {
			return err
		}
	}

	return nil
}

func (s *SharedStore) lookupLocalKey(name string) LocalKey {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, key := range s.localKeys {
		if key.GetKeyName() == name {
			return key
		}
	}

	return nil
}

// NumEntries returns the number of entries in the store
func (s *SharedStore) NumEntries() int {
	if s == nil {
		return 0
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return len(s.sharedKeys)
}

// SharedKeysMap returns a copy of the SharedKeysMap, the returned map can
// be safely modified but the values of the map represent the actual data
// stored in the internal SharedStore SharedKeys map.
func (s *SharedStore) SharedKeysMap() map[string]Key {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return maps.Clone(s.sharedKeys)
}

// UpdateLocalKeySync synchronously synchronizes a local key with the kvstore
// and adds it to the list of local keys to be synchronized if the initial
// synchronous synchronization was successful
func (s *SharedStore) UpdateLocalKeySync(ctx context.Context, key LocalKey) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	err := s.syncLocalKey(ctx, key, true)
	if err == nil {
		s.localKeys[key.GetKeyName()] = key.DeepKeyCopy()
	}
	return err
}

// UpdateKeySync synchronously synchronizes a key with the kvstore.
func (s *SharedStore) UpdateKeySync(ctx context.Context, key LocalKey, lease bool) error {
	return s.syncLocalKey(ctx, key, lease)
}

// DeleteLocalKey removes a key from being synchronized with the kvstore
func (s *SharedStore) DeleteLocalKey(ctx context.Context, key NamedKey) {
	name := key.GetKeyName()

	s.mutex.Lock()
	_, ok := s.localKeys[name]
	delete(s.localKeys, name)
	s.mutex.Unlock()

	err := s.backend.Delete(ctx, s.keyPath(key))

	if ok {
		if err != nil {
			s.logger.Warn("Unable to delete key in kvstore", logfields.Error, err)
		}

		s.onDelete(key)
	}
}

func (s *SharedStore) updateKey(name string, value []byte) error {
	newKey := s.conf.KeyCreator()
	if err := newKey.Unmarshal(name, value); err != nil {
		return err
	}

	s.mutex.Lock()
	s.sharedKeys[name] = newKey
	s.mutex.Unlock()

	s.onUpdate(newKey)
	return nil
}

func (s *SharedStore) deleteSharedKey(name string) {
	s.mutex.Lock()
	existingKey, ok := s.sharedKeys[name]
	delete(s.sharedKeys, name)
	s.mutex.Unlock()

	if ok {
		go func() {
			time.Sleep(s.conf.SharedKeyDeleteDelay)
			s.mutex.RLock()
			_, ok := s.sharedKeys[name]
			s.mutex.RUnlock()
			if ok {
				s.logger.Warn(
					"Received delete event for key which re-appeared within delay time window",
					logfields.Key, name,
					logfields.TimeWindow, s.conf.SharedKeyDeleteDelay,
				)
				return
			}

			s.onDelete(existingKey)
		}()
	} else {
		s.logger.Warn(
			"Unable to find deleted key in local state",
			logfields.Key, name,
		)
	}
}

func (s *SharedStore) listAndStartWatcher() error {
	listDone := make(chan struct{})

	s.wg.Add(1)
	go func() {
		s.watcher(listDone)
		s.wg.Done()
	}()

	select {
	case <-listDone:
	case <-time.After(listTimeoutDefault):
		return fmt.Errorf("timeout while retrieving initial list of objects from kvstore")
	}

	return nil
}

func (s *SharedStore) watcher(listDone chan struct{}) {
	events := s.backend.ListAndWatch(s.conf.Context, s.conf.Prefix)

	logger := s.logger
	for event := range events {
		if event.Typ == kvstore.EventTypeListDone {
			logger.Debug("Initial list of objects received from kvstore")
			close(listDone)
			continue
		}

		logger.Debug("Received key update via kvstore",
			logfields.Value, string(event.Value),
			logfields.Key, event.Key,
			logfields.EventType, event.Typ,
		)

		keyName := strings.TrimPrefix(event.Key, s.conf.Prefix)
		if keyName[0] == '/' {
			keyName = keyName[1:]
		}

		switch event.Typ {
		case kvstore.EventTypeCreate, kvstore.EventTypeModify:
			if err := s.updateKey(keyName, event.Value); err != nil {
				logger.Warn(
					"Unable to unmarshal store value",
					logfields.Error, err,
					logfields.Value, string(event.Value),
					logfields.Key, event.Key,
					logfields.EventType, event.Typ,
				)
			}

		case kvstore.EventTypeDelete:
			if localKey := s.lookupLocalKey(keyName); localKey != nil {
				logger.Warn(
					"Received delete event for local key. Re-creating the key in the kvstore",
					logfields.Key, event.Key,
					logfields.EventType, event.Typ,
				)

				s.syncLocalKey(s.conf.Context, localKey, true)
			} else {
				s.deleteSharedKey(keyName)
			}
		}
	}
}
