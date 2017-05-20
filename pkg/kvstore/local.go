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
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/policy"
)

type LocalClient struct {
	lock  sync.RWMutex // lock protects the `store` map
	store map[string]string
}

type LocalLocker struct {
}

func NewLocalClient() KVClient {
	return &LocalClient{store: map[string]string{}}
}

func (l *LocalClient) LockPath(path string) (KVLocker, error) {
	return &LocalLocker{}, nil
}

func (l *LocalLocker) Unlock() error {
	return nil
}

func (l *LocalClient) GetValue(k string) (json.RawMessage, error) {
	l.lock.RLock()
	defer l.lock.RUnlock()

	if v, ok := l.store[k]; ok {
		return json.RawMessage(v), nil
	}
	return nil, nil
}

func (l *LocalClient) SetValue(k string, v interface{}) error {
	vByte, err := json.Marshal(v)
	if err != nil {
		return err
	}

	l.lock.Lock()
	l.store[k] = string(vByte)
	l.lock.Unlock()

	return nil
}

func (l *LocalClient) InitializeFreeID(path string, firstID uint32) error {
	kvLocker, _ := l.LockPath(path)
	defer kvLocker.Unlock()

	k, _ := l.GetValue(path)
	if k != nil {
		return nil
	}

	if err := l.SetValue(path, firstID); err != nil {
		return err
	}

	return nil
}

func (l *LocalClient) GetMaxID(key string, firstID uint32) (uint32, error) {
	var (
		attempts = 3
		value    json.RawMessage
		err      error
		freeID   uint32
	)
	for {
		switch value, err = l.GetValue(key); {
		case attempts == 0:
			err = fmt.Errorf("Unable to retrieve last free ID because key is always empty")
			log.Error(err)
			fallthrough
		case value == nil:
			log.Infof("Empty FreeID, setting it up with default value %d", firstID)
			if err := l.InitializeFreeID(key, firstID); err != nil {
				return 0, err
			}
			attempts--
		case err == nil:
			if err := json.Unmarshal(value, &freeID); err != nil {
				return 0, err
			}
			log.Debugf("Retrieving max free ID %d", freeID)
			return freeID, nil
		}
	}
}

func (l *LocalClient) SetMaxID(key string, firstID, maxID uint32) error {
	value, _ := l.GetValue(key)
	if value == nil {
		// FreeID is empty? We should set it out!
		log.Infof("Empty FreeID, setting it up with default value %d", firstID)
		if err := l.InitializeFreeID(key, firstID); err != nil {
			return err
		}
		k, _ := l.GetValue(key)
		if k == nil {
			// Something is really wrong
			errMsg := "Unable to setting ID because the key is always empty\n"
			log.Errorf(errMsg)
			return fmt.Errorf(errMsg)
		}
	}
	return l.SetValue(key, maxID)
}

func (l *LocalClient) updateSecLabelIDRef(id policy.Identity) error {
	key := path.Join(common.LabelIDKeyPath, strconv.FormatUint(uint64(id.ID), 10))
	return l.SetValue(key, id)
}

func (l *LocalClient) setMaxLabelID(maxID uint32) error {
	return l.SetMaxID(common.LastFreeLabelIDKeyPath, policy.MinimalNumericIdentity.Uint32(), maxID)
}

func (l *LocalClient) GASNewSecLabelID(basePath string, baseID uint32, pI *policy.Identity) error {
	setID2Label := func(new_id uint32) error {
		pI.ID = policy.NumericIdentity(new_id)
		keyPath := path.Join(basePath, pI.ID.StringID())
		if err := l.SetValue(keyPath, pI); err != nil {
			return err
		}
		return l.setMaxLabelID(new_id + 1)
	}

	acquireFreeID := func(firstID uint32, incID *uint32) (bool, error) {
		log.Debugf("Trying to acquire a new free ID %d", *incID)
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(*incID), 10))

		locker, _ := l.LockPath(GetLockPath(keyPath))
		defer locker.Unlock()

		value, _ := l.GetValue(keyPath)
		if value == nil {
			return false, setID2Label(*incID)
		}
		var consulLabels policy.Identity
		if err := json.Unmarshal(value, &consulLabels); err != nil {
			return false, err
		}
		if consulLabels.RefCount() == 0 {
			log.Infof("Recycling ID %d", *incID)
			return false, setID2Label(*incID)
		}

		*incID++
		if *incID > common.MaxSetOfLabels {
			*incID = policy.MinimalNumericIdentity.Uint32()
		}
		if firstID == *incID {
			return false, fmt.Errorf("reached maximum set of labels available.")
		}
		return true, nil
	}

	beginning := baseID
	for {
		retry, err := acquireFreeID(beginning, &baseID)
		if err != nil {
			return err
		} else if !retry {
			return nil
		}
	}
}

func (l *LocalClient) setMaxL3n4AddrID(maxID uint32) error {
	return l.SetMaxID(common.LastFreeServiceIDKeyPath, common.FirstFreeServiceID, maxID)
}

func (l *LocalClient) GASNewL3n4AddrID(basePath string, baseID uint32, lAddrID *types.L3n4AddrID) error {
	setIDtoL3n4Addr := func(id uint32) error {
		lAddrID.ID = types.ServiceID(id)
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(lAddrID.ID), 10))
		if err := l.SetValue(keyPath, lAddrID); err != nil {
			return err
		}
		return l.setMaxL3n4AddrID(id + 1)
	}

	acquireFreeID := func(firstID uint32, incID *uint32) error {
		log.Debugf("Trying to acquire a new free ID %d", *incID)
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(*incID), 10))

		locker, _ := l.LockPath(GetLockPath(keyPath))
		defer locker.Unlock()

		value, _ := l.GetValue(keyPath)
		if value == nil {
			return setIDtoL3n4Addr(*incID)
		}
		var consulL3n4AddrID types.L3n4AddrID
		if err := json.Unmarshal(value, &consulL3n4AddrID); err != nil {
			return err
		}
		if consulL3n4AddrID.ID == 0 {
			log.Infof("Recycling Service ID %d", *incID)
			return setIDtoL3n4Addr(*incID)
		}

		*incID++
		if *incID > common.MaxSetOfServiceID {
			*incID = common.FirstFreeServiceID
		}
		if firstID == *incID {
			return fmt.Errorf("reached maximum set of serviceIDs available.")
		}
		return nil
	}

	var err error
	beginning := baseID
	for {
		if err = acquireFreeID(beginning, &baseID); err != nil {
			return err
		} else if beginning == baseID {
			return nil
		}
	}
}

func (l *LocalClient) DeleteTree(path string) error {
	for k := range l.store {
		if strings.HasPrefix(k, path) {
			delete(l.store, k)
		}
	}

	return nil
}

func (l *LocalClient) GetWatcher(key string, timeSleep time.Duration) <-chan []policy.NumericIdentity {
	return make(chan []policy.NumericIdentity, 1)
}

func (l *LocalClient) Status() (string, error) {
	return "Local: OK", nil
}
