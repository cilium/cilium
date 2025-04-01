// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/uuid"

	"github.com/cilium/cilium/pkg/debug"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

var (
	kvstoreLocks = pathLocks{lockPaths: map[string]lockOwner{}}

	// staleLockTimeout is the timeout after which waiting for a believed
	// other local lock user for the same key is given up on and etcd is
	// asked directly. It is still highly unlikely that concurrent access
	// occurs as only one consumer will manage to acquire the newly
	// released lock. The only possibility of concurrent access is if a
	// consumer is *still* holding the lock but this is highly unlikely
	// given the duration of this timeout.
	staleLockTimeout = defaults.KVStoreStaleLockTimeout
)

type KVLocker interface {
	Unlock(ctx context.Context) error
	// Comparator returns an object that should be used by the KVStore to make
	// sure if the lock is still valid for its client or nil if no such
	// verification exists.
	Comparator() any
}

// getLockPath returns the lock path representation of the given path.
func getLockPath(path string) string {
	return path + ".lock"
}

type lockOwner struct {
	created time.Time
	id      uuid.UUID
}

type pathLocks struct {
	mutex     lock.RWMutex
	lockPaths map[string]lockOwner
}

func init() {
	debug.RegisterStatusObject("kvstore-locks", &kvstoreLocks)
}

// DebugStatus implements debug.StatusObject to provide debug status collection
// ability
func (pl *pathLocks) DebugStatus() string {
	pl.mutex.RLock()
	str := spew.Sdump(pl.lockPaths)
	pl.mutex.RUnlock()
	return str
}

func (pl *pathLocks) runGC(logger *slog.Logger) {
	pl.mutex.Lock()
	for path, owner := range pl.lockPaths {
		if time.Since(owner.created) > staleLockTimeout {
			logger.Error("Forcefully unlocking local kvstore lock", fieldKey, path)
			delete(pl.lockPaths, path)
		}
	}
	pl.mutex.Unlock()
}

func (pl *pathLocks) lock(ctx context.Context, path string) (id uuid.UUID, err error) {
	for {
		pl.mutex.Lock()
		if _, ok := pl.lockPaths[path]; !ok {
			id = uuid.New()
			pl.lockPaths[path] = lockOwner{
				created: time.Now(),
				id:      id,
			}
			pl.mutex.Unlock()
			return
		}
		pl.mutex.Unlock()

		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			err = fmt.Errorf("lock was cancelled: %w", ctx.Err())
			return
		}
	}
}

func (pl *pathLocks) unlock(path string, id uuid.UUID) {
	pl.mutex.Lock()
	if owner, ok := pl.lockPaths[path]; ok && owner.id == id {
		delete(pl.lockPaths, path)
	}
	pl.mutex.Unlock()
}

// Lock is a lock return by LockPath
type Lock struct {
	path   string
	id     uuid.UUID
	kvLock KVLocker
	logger *slog.Logger
}

// LockPath locks the specified path. The key for the lock is not the path
// provided itself but the path with a suffix of ".lock" appended. The lock
// returned also contains a patch specific local Mutex which will be held.
//
// It is required to call Unlock() on the returned Lock to unlock
func LockPath(ctx context.Context, logger *slog.Logger, backend BackendOperations, path string) (l *Lock, err error) {
	id, err := kvstoreLocks.lock(ctx, path)
	if err != nil {
		return nil, err
	}

	lock, err := backend.LockPath(ctx, path)
	if err != nil {
		kvstoreLocks.unlock(path, id)
		Trace(logger, "Failed to lock", fieldKey, path)
		err = fmt.Errorf("error while locking path %s: %w", path, err)
		return nil, err
	}

	Trace(logger, "Successful lock", fieldKey, path)
	return &Lock{kvLock: lock, path: path, id: id, logger: logger}, err
}

// RunLockGC inspects all local kvstore locks to determine whether they have
// been held longer than the stale lock timeout, and if so, unlocks them
// forceably.
func RunLockGC(logger *slog.Logger) {
	kvstoreLocks.runGC(logger)
}

// Unlock unlocks a lock
func (l *Lock) Unlock(ctx context.Context) error {
	if l == nil {
		return nil
	}

	// Unlock kvstore mutex first
	err := l.kvLock.Unlock(ctx)
	if err != nil {
		l.logger.Error("Unable to unlock kvstore lock",
			logfields.Error, err,
			fieldKey, l.path,
		)
	}

	// unlock local lock even if kvstore cannot be unlocked
	kvstoreLocks.unlock(l.path, l.id)
	Trace(l.logger, "Unlocked", fieldKey, l.path)

	return err
}

func (l *Lock) Comparator() any {
	return l.kvLock.Comparator()
}
