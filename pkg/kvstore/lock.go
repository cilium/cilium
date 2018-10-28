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
	"time"

	"github.com/cilium/cilium/pkg/lock"

	"github.com/sirupsen/logrus"
)

var (
	kvstoreLocks = pathLocks{lockPaths: map[string]int{}}
)

const (
	lockTimeout = time.Duration(2) * time.Minute
)

type kvLocker interface {
	Unlock() error
}

// getLockPath returns the lock path representation of the given path.
func getLockPath(path string) string {
	return path + ".lock"
}

type pathLocks struct {
	mutex     lock.RWMutex
	lockPaths map[string]int
}

func (pl *pathLocks) lock(path string) {
	started := time.Now()

	for {
		pl.mutex.Lock()

		refcnt := pl.lockPaths[path]
		if refcnt == 0 {
			pl.lockPaths[path] = 1
			pl.mutex.Unlock()
			return
		}

		if time.Since(started) > lockTimeout {
			log.WithField("path", path).Warning("WARNING: Timeout while waiting for lock, ignoring lock")
			pl.lockPaths[path] = 1
			pl.mutex.Unlock()
			return
		}

		pl.mutex.Unlock()

		// Sleep for a short while to retry
		time.Sleep(time.Duration(10) * time.Millisecond)
	}
}

func (pl *pathLocks) unlock(path string) {
	pl.mutex.Lock()
	pl.lockPaths[path] = 0
	pl.mutex.Unlock()
}

// Lock is a lock return by LockPath
type Lock struct {
	path   string
	kvLock kvLocker
}

// LockPath locks the specified path. The key for the lock is not the path
// provided itself but the path with a suffix of ".lock" appended. The lock
// returned also contains a patch specific local Mutex which will be held.
//
// It is required to call Unlock() on the returned Lock to unlock
func LockPath(path string) (l *Lock, err error) {
	kvstoreLocks.lock(path)

	lock, err := Client().LockPath(path)
	if err != nil {
		kvstoreLocks.unlock(path)
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

	// unlock local lock even if kvstore cannot be unlocked
	kvstoreLocks.unlock(l.path)
	Trace("Unlocked", nil, logrus.Fields{fieldKey: l.path})

	return err
}
