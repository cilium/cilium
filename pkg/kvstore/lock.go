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
	"fmt"

	"github.com/cilium/cilium/pkg/lock"

	log "github.com/sirupsen/logrus"
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
	path string
	lock kvLocker
}

var (
	lockPathsMU lock.Mutex
	lockPaths   = map[string]*lock.Mutex{}
)

// LockPath locks the specified path and returns the Lock
func LockPath(path string) (*Lock, error) {
	lockPathsMU.Lock()
	if lockPaths[path] == nil {
		lockPaths[path] = &lock.Mutex{}
	}
	lockPathsMU.Unlock()

	trace("Creating lock", nil, log.Fields{fieldKey: path})

	// Take the local lock as both etcd and consul protect per client
	lockPaths[path].Lock()

	lock, err := Client().LockPath(path)
	if err != nil {
		lockPaths[path].Unlock()
		return nil, fmt.Errorf("Error while locking path %s: %s", path, err)
	}

	trace("Successful lock", nil, log.Fields{fieldKey: path})
	return &Lock{lock: lock, path: path}, nil
}

// Unlock unlocks a lock
func (l *Lock) Unlock() error {
	err := l.lock.Unlock()

	lockPaths[l.path].Unlock()
	if err == nil {
		trace("Unlocked", nil, log.Fields{fieldKey: l.path})
	}
	return err
}
