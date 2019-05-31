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
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/debug"
	"github.com/cilium/cilium/pkg/lock"
	uuidfactor "github.com/cilium/cilium/pkg/uuid"

	"github.com/davecgh/go-spew/spew"
	"github.com/pborman/uuid"
	"github.com/sirupsen/logrus"
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
	staleLockTimeout = time.Duration(30) * time.Second
)

type KVLocker interface {
	Unlock() error
	// Comparator returns an object that should be used by the KVStore to make
	// sure if the lock is still valid for its client.
	Comparator() interface{}
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
	go func() {
		for {
			kvstoreLocks.runGC()
			time.Sleep(staleLockTimeout)
		}
	}()

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

func (pl *pathLocks) runGC() {
	pl.mutex.Lock()
	for path, owner := range pl.lockPaths {
		if time.Since(owner.created) > staleLockTimeout {
			log.WithField("path", path).Error("Forcefully unlocking local kvstore lock")
			delete(pl.lockPaths, path)
		}
	}
	pl.mutex.Unlock()
}

func (pl *pathLocks) lock(ctx context.Context, path string) (id uuid.UUID, err error) {
	for {
		pl.mutex.Lock()
		if _, ok := pl.lockPaths[path]; !ok {
			id = uuidfactor.NewUUID()
			pl.lockPaths[path] = lockOwner{
				created: time.Now(),
				id:      id,
			}
			pl.mutex.Unlock()
			return
		}
		pl.mutex.Unlock()

		select {
		case <-time.After(time.Duration(10) * time.Millisecond):
		case <-ctx.Done():
			err = fmt.Errorf("lock was cancelled: %s", ctx.Err())
			return
		}
	}
}

func (pl *pathLocks) unlock(path string, id uuid.UUID) {
	pl.mutex.Lock()
	if owner, ok := pl.lockPaths[path]; ok && uuid.Equal(owner.id, id) {
		delete(pl.lockPaths, path)
	}
	pl.mutex.Unlock()
}

// Lock is a lock return by LockPath
type Lock struct {
	path   string
	id     uuid.UUID
	kvLock KVLocker
}

// LockPath locks the specified path. The key for the lock is not the path
// provided itself but the path with a suffix of ".lock" appended. The lock
// returned also contains a patch specific local Mutex which will be held.
//
// It is required to call Unlock() on the returned Lock to unlock
func LockPath(ctx context.Context, path string) (l *Lock, err error) {
	id, err := kvstoreLocks.lock(ctx, path)
	if err != nil {
		return nil, err
	}

	lock, err := Client().LockPath(ctx, path)
	if err != nil {
		kvstoreLocks.unlock(path, id)
		Trace("Failed to lock", err, logrus.Fields{fieldKey: path})
		err = fmt.Errorf("error while locking path %s: %s", path, err)
		return nil, err
	}

	Trace("Successful lock", err, logrus.Fields{fieldKey: path})
	return &Lock{kvLock: lock, path: path, id: id}, err
}

// Unlock unlocks a lock
func (l *Lock) Unlock() error {
	if l == nil {
		return nil
	}

	// Unlock kvstore mutex first
	err := l.kvLock.Unlock()
	if err != nil {
		log.WithError(err).WithField("path", l.path).Error("Unable to unlock kvstore lock")
	}

	// unlock local lock even if kvstore cannot be unlocked
	kvstoreLocks.unlock(l.path, l.id)
	Trace("Unlocked", nil, logrus.Fields{fieldKey: l.path})

	return err
}

func (l *Lock) Comparator() interface{} {
	return l.kvLock.Comparator()
}
