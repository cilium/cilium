// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/lock"
)

type inMemoryModule struct {
	db *statedb.DB

	mu lock.Mutex

	// clients key'd by cluster name
	clients map[string]*inMemoryClient

	dummy bool
}

const InMemoryModuleName = "in-memory"

func SetupInMemory(db *statedb.DB) {
	registeredBackends[InMemoryModuleName] = &inMemoryModule{
		db:      db,
		clients: map[string]*inMemoryClient{},
	}
}

// createInstance implements backendModule.
func (i *inMemoryModule) createInstance() backendModule {
	return i
}

// getConfig implements backendModule.
func (i *inMemoryModule) getConfig() map[string]string {
	return nil
}

// getName implements backendModule.
func (i *inMemoryModule) getName() string {
	return InMemoryModuleName
}

// newClient implements backendModule.
func (im *inMemoryModule) newClient(ctx context.Context, logger *slog.Logger, opts *ExtraOptions) (BackendOperations, chan error) {
	clusterName := ""
	if im.dummy {
		// If setConfigDummy() was called all clients share the same table.
		clusterName = "dummy"
	} else if opts != nil {
		clusterName = opts.ClusterName
	}
	errChan := make(chan error)
	close(errChan)

	im.mu.Lock()
	defer im.mu.Unlock()
	if c, found := im.clients[clusterName]; found {
		return c, errChan
	}
	c := newInMemoryClient(im.db, clusterName)
	im.clients[clusterName] = c
	return c, errChan
}

// setConfig implements backendModule.
func (i *inMemoryModule) setConfig(logger *slog.Logger, opts map[string]string) error {
	return nil
}

// setConfigDummy implements backendModule.
func (im *inMemoryModule) setConfigDummy() {
	im.dummy = true
}

// setExtraConfig implements backendModule.
func (i *inMemoryModule) setExtraConfig(opts *ExtraOptions) error {
	return nil
}

var _ backendModule = &inMemoryModule{}

func newInMemoryClient(db *statedb.DB, clusterName string) *inMemoryClient {
	table, err := statedb.NewTable(
		"kvstore-"+clusterName,
		inMemoryKeyIndex,
	)
	if err != nil {
		panic(err)
	}
	if err := db.RegisterTable(table); err != nil {
		panic(err)
	}
	return &inMemoryClient{
		db:          db,
		table:       table,
		clusterName: clusterName,
	}
}

type inMemoryObject struct {
	key   string
	value []byte
}

var (
	inMemoryKeyIndex = statedb.Index[inMemoryObject, string]{
		Name: "key",
		FromObject: func(obj inMemoryObject) index.KeySet {
			return index.NewKeySet(index.String(obj.key))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}
)

type inMemoryClient struct {
	db          *statedb.DB
	table       statedb.RWTable[inMemoryObject]
	clusterName string
}

// Close implements BackendOperations.
func (c *inMemoryClient) Close() {
}

// Connected implements BackendOperations.
func (c *inMemoryClient) Connected(ctx context.Context) <-chan error {
	out := make(chan error)
	close(out)
	return out
}

// CreateOnly implements BackendOperations.
func (c *inMemoryClient) CreateOnly(ctx context.Context, key string, value []byte, lease bool) (bool, error) {
	wtxn := c.db.WriteTxn(c.table)
	defer wtxn.Abort()
	_, hadOld, _ := c.table.Insert(wtxn, inMemoryObject{
		key:   key,
		value: value,
	})
	if hadOld {
		return false, fmt.Errorf("key %q existed", key)
	}
	wtxn.Commit()
	return true, nil
}

// CreateOnlyIfLocked implements BackendOperations.
func (c *inMemoryClient) CreateOnlyIfLocked(ctx context.Context, key string, value []byte, lease bool, lock KVLocker) (bool, error) {
	return c.CreateOnly(ctx, key, value, lease)
}

// Delete implements BackendOperations.
func (c *inMemoryClient) Delete(ctx context.Context, key string) error {
	wtxn := c.db.WriteTxn(c.table)
	defer wtxn.Abort()
	_, existed, _ := c.table.Delete(wtxn, inMemoryObject{key: key})
	if !existed {
		return nil
	}
	wtxn.Commit()
	return nil
}

// DeleteIfLocked implements BackendOperations.
func (c *inMemoryClient) DeleteIfLocked(ctx context.Context, key string, lock KVLocker) error {
	return c.Delete(ctx, key)
}

// DeletePrefix implements BackendOperations.
func (c *inMemoryClient) DeletePrefix(ctx context.Context, path string) error {
	wtxn := c.db.WriteTxn(c.table)
	defer wtxn.Commit()
	for obj := range c.table.Prefix(wtxn, inMemoryKeyIndex.Query(path)) {
		c.table.Delete(wtxn, obj)
	}
	return nil
}

// Get implements BackendOperations.
func (c *inMemoryClient) Get(ctx context.Context, key string) ([]byte, error) {
	obj, _, found := c.table.Get(c.db.ReadTxn(), inMemoryKeyIndex.Query(key))
	if !found {
		return nil, nil
	}
	return obj.value, nil
}

// GetIfLocked implements BackendOperations.
func (c *inMemoryClient) GetIfLocked(ctx context.Context, key string, lock KVLocker) ([]byte, error) {
	return c.Get(ctx, key)
}

// ListAndWatch implements BackendOperations.
func (c *inMemoryClient) ListAndWatch(ctx context.Context, prefix string) EventChan {
	wtxn := c.db.WriteTxn(c.table)
	changeIter, err := c.table.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		panic(fmt.Sprintf("BUG: Changes() returned error: %s", err))
	}
	events := make(chan KeyValueEvent)

	go func() {
		defer close(events)
		initDone := false
		exists := sets.New[string]()
		for {
			changes, watch := changeIter.Next(c.db.ReadTxn())
			for change := range changes {
				obj := change.Object
				if !strings.HasPrefix(obj.key, prefix) {
					continue
				}
				var typ EventType
				switch {
				case change.Deleted:
					typ = EventTypeDelete
					exists.Delete(obj.key)
				case exists.Has(obj.key):
					typ = EventTypeModify
				default:
					typ = EventTypeCreate
					exists.Insert(obj.key)
				}
				events <- KeyValueEvent{
					Typ:   typ,
					Key:   obj.key,
					Value: obj.value,
				}
			}

			if !initDone {
				events <- KeyValueEvent{Typ: EventTypeListDone}
				initDone = true
			}

			select {
			case <-watch:
			case <-ctx.Done():
				return
			}
		}
	}()
	return events
}

// ListPrefix implements BackendOperations.
func (c *inMemoryClient) ListPrefix(ctx context.Context, prefix string) (kvs KeyValuePairs, err error) {
	kvs = KeyValuePairs{}
	for obj, rev := range c.table.Prefix(c.db.ReadTxn(), inMemoryKeyIndex.Query(prefix)) {
		kvs[obj.key] = Value{
			Data:        obj.value,
			ModRevision: rev,
			LeaseID:     0,
		}
	}
	return
}

// ListPrefixIfLocked implements BackendOperations.
func (c *inMemoryClient) ListPrefixIfLocked(ctx context.Context, prefix string, lock KVLocker) (KeyValuePairs, error) {
	return c.ListPrefix(ctx, prefix)
}

// LockPath implements BackendOperations.
func (c *inMemoryClient) LockPath(ctx context.Context, path string) (KVLocker, error) {
	panic("unimplemented")
}

// RegisterLeaseExpiredObserver implements BackendOperations.
func (c *inMemoryClient) RegisterLeaseExpiredObserver(prefix string, fn func(key string)) {
	panic("unimplemented")
}

// Status implements BackendOperations.
func (c *inMemoryClient) Status() *models.Status {
	return &models.Status{}
}

// StatusCheckErrors implements BackendOperations.
func (c *inMemoryClient) StatusCheckErrors() <-chan error {
	return nil
}

// Update implements BackendOperations.
func (c *inMemoryClient) Update(ctx context.Context, key string, value []byte, lease bool) error {
	wtxn := c.db.WriteTxn(c.table)
	defer wtxn.Commit()
	c.table.Insert(wtxn, inMemoryObject{key, value})
	wtxn.Commit()
	return nil
}

// UpdateIfDifferent implements BackendOperations.
func (c *inMemoryClient) UpdateIfDifferent(ctx context.Context, key string, value []byte, lease bool) (bool, error) {
	wtxn := c.db.WriteTxn(c.table)
	defer wtxn.Abort()
	obj, _, found := c.table.Get(wtxn, inMemoryKeyIndex.Query(key))
	if found && bytes.Equal(obj.value, value) {
		return false, nil
	}
	c.table.Insert(wtxn, inMemoryObject{key, value})
	wtxn.Commit()
	return true, nil
}

// UpdateIfDifferentIfLocked implements BackendOperations.
func (c *inMemoryClient) UpdateIfDifferentIfLocked(ctx context.Context, key string, value []byte, lease bool, lock KVLocker) (bool, error) {
	return c.UpdateIfDifferent(ctx, key, value, lease)
}

// UpdateIfLocked implements BackendOperations.
func (c *inMemoryClient) UpdateIfLocked(ctx context.Context, key string, value []byte, lease bool, lock KVLocker) error {
	return c.Update(ctx, key, value, lease)
}

// UserEnforceAbsence implements BackendOperations.
func (c *inMemoryClient) UserEnforceAbsence(ctx context.Context, name string) error {
	panic("unimplemented")
}

// UserEnforcePresence implements BackendOperations.
func (c *inMemoryClient) UserEnforcePresence(ctx context.Context, name string, roles []string) error {
	panic("unimplemented")
}

var _ BackendOperations = &inMemoryClient{}
