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

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strconv"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func updateL3n4AddrIDRef(id loadbalancer.ID, l3n4AddrID loadbalancer.L3n4AddrID) error {
	key := path.Join(ServiceIDKeyPath, strconv.FormatUint(uint64(id), 10))
	value, err := json.Marshal(l3n4AddrID)
	if err != nil {
		return err
	}
	return kvstore.Client().Set(key, value)
}

func initializeFreeID(path string, firstID uint32) error {

	client := kvstore.Client()
	kvLocker, err := client.LockPath(context.Background(), path)
	if err != nil {
		return err
	}
	defer kvLocker.Unlock()

	log.Debug("Trying to acquire free ID...")
	k, err := client.Get(path)
	if err != nil {
		return err
	}
	if k != nil {
		// FreeID already set
		return nil
	}

	marshaledID, err := json.Marshal(firstID)
	if err != nil {
		return fmt.Errorf("cannot marshal initialize id: %s", err)
	}

	err = client.Set(path, marshaledID)
	if err != nil {
		return err
	}

	return nil
}

// getMaxID returns the maximum possible free UUID stored.
func getMaxID(key string, firstID uint32) (uint32, error) {
	client := kvstore.Client()
	k, err := client.Get(key)
	if err != nil {
		return 0, err
	}
	if k == nil {
		// FreeID is empty? We should set it out!
		if err := initializeFreeID(key, firstID); err != nil {
			return 0, err
		}
		// Due other goroutine can take the ID, still need to get the key from the kvstore.
		k, err = client.Get(key)
		if err != nil {
			return 0, err
		}
		if k == nil {
			// Something is really wrong
			errMsg := "unable to retrieve last free ID because the key is always empty"
			log.Error(errMsg)
			return 0, fmt.Errorf(errMsg)
		}
	}
	var freeID uint32
	if err := json.Unmarshal(k, &freeID); err != nil {
		return 0, err
	}
	return freeID, nil
}

func setMaxID(key string, firstID, maxID uint32) error {
	client := kvstore.Client()
	value, err := client.Get(key)
	if err != nil {
		return err
	}
	if value == nil {
		// FreeID is empty? We should set it out!
		if err := initializeFreeID(key, firstID); err != nil {
			return err
		}
		k, err := client.Get(key)
		if err != nil {
			return err
		}
		if k == nil {
			// Something is really wrong
			errMsg := "unable to set ID because the key is always empty"
			log.Error(errMsg)
			return fmt.Errorf("%s", errMsg)
		}
	}
	marshaledID, err := json.Marshal(maxID)
	if err != nil {
		return nil
	}
	return client.Set(key, marshaledID)
}

// gasNewL3n4AddrID gets and sets a new L3n4Addr ID. If baseID is different than zero,
// KVStore tries to assign that ID first.
func gasNewL3n4AddrID(l3n4AddrID *loadbalancer.L3n4AddrID, baseID uint32) error {
	client := kvstore.Client()

	if baseID == 0 {
		var err error
		baseID, err = getGlobalMaxServiceID()
		if err != nil {
			return err
		}
	}

	setIDtoL3n4Addr := func(id uint32) error {
		l3n4AddrID.ID = loadbalancer.ID(id)
		marshaledL3n4AddrID, err := json.Marshal(l3n4AddrID)
		if err != nil {
			return err
		}
		keyPath := path.Join(ServiceIDKeyPath, strconv.FormatUint(uint64(l3n4AddrID.ID), 10))
		if err := client.Set(keyPath, marshaledL3n4AddrID); err != nil {
			return err
		}

		return setMaxID(LastFreeServiceIDKeyPath, FirstFreeServiceID, id+1)
	}

	acquireFreeID := func(firstID uint32, incID *uint32) (bool, error) {
		keyPath := path.Join(ServiceIDKeyPath, strconv.FormatUint(uint64(*incID), 10))

		locker, err := client.LockPath(context.Background(), keyPath)
		if err != nil {
			return false, err
		}
		defer locker.Unlock()

		value, err := client.Get(keyPath)
		if err != nil {
			return false, err
		}
		if value == nil {
			return false, setIDtoL3n4Addr(*incID)
		}
		var kvstoreL3n4AddrID loadbalancer.L3n4AddrID
		if err := json.Unmarshal(value, &kvstoreL3n4AddrID); err != nil {
			return false, err
		}
		if kvstoreL3n4AddrID.ID == 0 {
			log.WithField(logfields.Identity, *incID).Info("Recycling Service ID")
			return false, setIDtoL3n4Addr(*incID)
		}

		*incID++
		if *incID > MaxSetOfServiceID {
			*incID = FirstFreeServiceID
		}
		if firstID == *incID {
			return false, fmt.Errorf("reached maximum set of serviceIDs available")
		}
		// Only retry if we have incremented the service ID
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

// acquireGlobalID stores the given service in the kvstore and returns the L3n4AddrID
// created for the given l3n4Addr. If baseID is different than 0, it tries to acquire that
// ID to the l3n4Addr.
func acquireGlobalID(l3n4Addr loadbalancer.L3n4Addr, baseID uint32) (*loadbalancer.L3n4AddrID, error) {
	// Retrieve unique SHA256Sum for service
	sha256Sum := l3n4Addr.SHA256Sum()
	svcPath := path.Join(common.ServicesKeyPath, sha256Sum)

	// Lock that sha256Sum
	lockKey, err := kvstore.LockPath(context.Background(), kvstore.Client(), svcPath)
	if err != nil {
		return nil, err
	}
	defer lockKey.Unlock()

	// After lock complete, get svc's path
	rmsg, err := kvstore.Client().Get(svcPath)
	if err != nil {
		return nil, err
	}

	sl4KV := loadbalancer.L3n4AddrID{}
	if rmsg != nil {
		if err := json.Unmarshal(rmsg, &sl4KV); err != nil {
			return nil, err
		}
	}
	if sl4KV.ID == 0 {
		sl4KV.L3n4Addr = l3n4Addr
		if err := gasNewL3n4AddrID(&sl4KV, baseID); err != nil {
			return nil, err
		}
		marshaledSl4Kv, err := json.Marshal(sl4KV)
		if err != nil {
			return nil, err
		}
		err = kvstore.Client().Set(svcPath, marshaledSl4Kv)
		if err != nil {
			return nil, err
		}
	}

	return &sl4KV, err
}

func getL3n4AddrID(keyPath string) (*loadbalancer.L3n4AddrID, error) {
	rmsg, err := kvstore.Client().Get(keyPath)
	if err != nil {
		return nil, err
	}
	if rmsg == nil {
		log.WithField("key", keyPath).Debug("no value mapped to key in KVStore")
		return nil, nil
	}

	var l3n4AddrID loadbalancer.L3n4AddrID
	if err := json.Unmarshal(rmsg, &l3n4AddrID); err != nil || l3n4AddrID.ID == 0 {
		return nil, err
	}
	return &l3n4AddrID, nil
}

// getGlobalID returns the L3n4AddrID that belongs to the given id.
func getGlobalID(id uint32) (*loadbalancer.L3n4AddrID, error) {
	strID := strconv.FormatUint(uint64(id), 10)
	log.WithField(logfields.L3n4AddrID, strID).Debug("getting L3n4AddrID for ID")

	return getL3n4AddrID(path.Join(ServiceIDKeyPath, strID))
}

// deleteGlobalID deletes the L3n4AddrID belonging to the given id from the kvstore.
func deleteGlobalID(id uint32) error {
	l3n4AddrID, err := getGlobalID(id)
	if err != nil {
		return err
	}
	if l3n4AddrID == nil {
		return nil
	}

	return deleteL3n4AddrIDBySHA256(l3n4AddrID.SHA256Sum())
}

// deleteL3n4AddrIDBySHA256 deletes the L3n4AddrID from the kvstore corresponding to the service's
// sha256Sum.
func deleteL3n4AddrIDBySHA256(sha256Sum string) error {
	log.WithField(logfields.SHA, sha256Sum).Debug("deleting L3n4AddrID with SHA256")
	if sha256Sum == "" {
		return nil
	}
	svcPath := path.Join(common.ServicesKeyPath, sha256Sum)
	// Lock that sha256Sum
	lockKey, err := kvstore.LockPath(context.Background(), kvstore.Client(), svcPath)
	if err != nil {
		return err
	}
	defer lockKey.Unlock()

	// After lock complete, get label's path
	rmsg, err := kvstore.Client().Get(svcPath)
	if err != nil {
		return err
	}
	if rmsg == nil {
		return nil
	}

	var l3n4AddrID loadbalancer.L3n4AddrID
	if err := json.Unmarshal(rmsg, &l3n4AddrID); err != nil {
		return err
	}
	oldL3n4ID := l3n4AddrID.ID
	l3n4AddrID.ID = 0

	// update the value in the kvstore
	if err := updateL3n4AddrIDRef(oldL3n4ID, l3n4AddrID); err != nil {
		return err
	}
	marshaledL3n4AddrID, err := json.Marshal(l3n4AddrID)
	if err != nil {
		return err
	}
	return kvstore.Client().Set(svcPath, marshaledL3n4AddrID)
}

func getGlobalMaxServiceID() (uint32, error) {
	return getMaxID(LastFreeServiceIDKeyPath, FirstFreeServiceID)
}

func setGlobalIDSpace(next, max uint32) error {
	return setMaxID(LastFreeServiceIDKeyPath, next, max)
}
