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
	"fmt"

	"github.com/cilium/cilium/pkg/lock"

	"github.com/sirupsen/logrus"
)

var (
	lockPathsMU lock.RWMutex
	lockPaths   = map[string]*localLock{}
)

type kvLocker interface {
	Unlock() error
}

// getLockPath returns the lock path representation of the given path.
func getLockPath(path string) string {
	return path + ".lock"
}

// Lock is a lock return by LockPath
type Lock struct {
	path   string
	kvLock kvLocker
}

type localLock struct {
	refCount int
	lock.Mutex
}

// incRefCount increments the reference count of this localLock
// must be called with lockPathsMU mutex held.
func (l *localLock) incRefCount() {
	l.refCount++
}

// decRefCount decrements the reference count of this localLock
// must be called with lockPathsMU mutex held.
func (l *localLock) decRefCount() int {
	l.refCount--
	return l.refCount
}

// LockPath locks the specified path. The key for the lock is not the path
// provided itself but the path with a suffix of ".lock" appended. The lock
// returned also contains a patch specific local Mutex which will be held.
//
// It is required to call Unlock() on the returned Lock to unlock
func LockPath(path string) (l *Lock, err error) {
	lockPathsMU.Lock()
	ll, ok := lockPaths[path]
	if !ok {
		ll = &localLock{}
		lockPaths[path] = ll
	}
	ll.incRefCount()
	lockPathsMU.Unlock()

	defer func() {
		if err != nil {
			lockPathsMU.Lock()
			if ll.decRefCount() == 0 {
				delete(lockPaths, path)
			}
			lockPathsMU.Unlock()
		}
	}()

	// Take the local lock as both etcd and consul protect per client
	ll.Lock()

	lock, err := Client().LockPath(path)
	if err != nil {
		ll.Unlock()
		Trace("Failed to lock", err, logrus.Fields{fieldKey: path})
		err = fmt.Errorf("Error while locking path %s: %s", path, err)
		return nil, err
	}

	Trace("Successful lock", err, logrus.Fields{fieldKey: path})
	return &Lock{kvLock: lock, path: path}, err
}

// Unlock unlocks a lock
func (l *Lock) Unlock() error {
	if l == nil {
		return nil
	}

	// Unlock kvstore mutex first
	err := l.kvLock.Unlock()

	lockPathsMU.Lock()
	ll, ok := lockPaths[l.path]
	if ok && ll.decRefCount() == 0 {
		delete(lockPaths, l.path)
	}
	lockPathsMU.Unlock()

	// Unlock local lock
	if ok {
		ll.Unlock()
	}
	if err == nil {
		Trace("Unlocked", nil, logrus.Fields{fieldKey: l.path})
	}
	return err
}
