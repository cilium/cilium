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

package main

import (
	"encoding/json"
	"path"
	"strconv"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logfields"

	log "github.com/sirupsen/logrus"
)

func updateL3n4AddrIDRef(id types.ServiceID, l3n4AddrID types.L3n4AddrID) error {
	key := path.Join(common.ServiceIDKeyPath, strconv.FormatUint(uint64(id), 10))
	return kvstore.Client().SetValue(key, l3n4AddrID)
}

// gasNewL3n4AddrID gets and sets a new L3n4Addr ID. If baseID is different than zero,
// KVStore tries to assign that ID first.
func gasNewL3n4AddrID(l3n4AddrID *types.L3n4AddrID, baseID uint32) error {
	if baseID == 0 {
		var err error
		baseID, err = GetMaxServiceID()
		if err != nil {
			return err
		}
	}

	return kvstore.Client().GASNewL3n4AddrID(common.ServiceIDKeyPath, baseID, l3n4AddrID)
}

// PutL3n4Addr stores the given service in the kvstore and returns the L3n4AddrID
// created for the given l3n4Addr. If baseID is different than 0, it tries to acquire that
// ID to the l3n4Addr.
func PutL3n4Addr(l3n4Addr types.L3n4Addr, baseID uint32) (*types.L3n4AddrID, error) {
	log.WithField(logfields.L3n4Addr, logfields.Repr(l3n4Addr)).Debug("Resolving service")

	// Retrieve unique SHA256Sum for service
	sha256Sum := l3n4Addr.SHA256Sum()
	svcPath := path.Join(common.ServicesKeyPath, sha256Sum)

	// Lock that sha256Sum
	lockKey, err := kvstore.LockPath(svcPath)
	if err != nil {
		return nil, err
	}
	defer lockKey.Unlock()

	// After lock complete, get svc's path
	rmsg, err := kvstore.Client().GetValue(svcPath)
	if err != nil {
		return nil, err
	}

	sl4KV := types.L3n4AddrID{}
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
		err = kvstore.Client().SetValue(svcPath, sl4KV)
	}

	return &sl4KV, err
}

func getL3n4AddrID(keyPath string) (*types.L3n4AddrID, error) {
	rmsg, err := kvstore.Client().GetValue(keyPath)
	if err != nil {
		return nil, err
	}
	if rmsg == nil {
		log.WithField("key", keyPath).Debug("no value mapped to key in KVStore")
		return nil, nil
	}

	var l3n4AddrID types.L3n4AddrID
	if err := json.Unmarshal(rmsg, &l3n4AddrID); err != nil || l3n4AddrID.ID == 0 {
		return nil, err
	}
	return &l3n4AddrID, nil
}

// GetL3n4AddrID returns the L3n4AddrID that belongs to the given id.
func GetL3n4AddrID(id uint32) (*types.L3n4AddrID, error) {
	strID := strconv.FormatUint(uint64(id), 10)
	log.WithField(logfields.L3n4AddrID, strID).Debug("getting L3n4AddrID for ID")

	return getL3n4AddrID(path.Join(common.ServiceIDKeyPath, strID))
}

// GetL3n4AddrIDBySHA256 returns the L3n4AddrID that have the given SHA256SUM.
func GetL3n4AddrIDBySHA256(sha256sum string) (*types.L3n4AddrID, error) {
	return getL3n4AddrID(path.Join(common.ServicesKeyPath, sha256sum))
}

// DeleteL3n4AddrIDByUUID deletes the L3n4AddrID belonging to the given id from the kvstore.
func DeleteL3n4AddrIDByUUID(id uint32) error {
	log.WithField(logfields.L3n4AddrID, id).Debug("deleting L3n4Addr by ID")
	l3n4AddrID, err := GetL3n4AddrID(id)
	if err != nil {
		return err
	}
	if l3n4AddrID == nil {
		return nil
	}

	return DeleteL3n4AddrIDBySHA256(l3n4AddrID.SHA256Sum())
}

// DeleteL3n4AddrIDBySHA256 deletes the L3n4AddrID from the kvstore corresponding to the service's
// sha256Sum.
func DeleteL3n4AddrIDBySHA256(sha256Sum string) error {
	log.WithField(logfields.SHA, sha256Sum).Debug("deleting L3n4AddrID with SHA256")
	if sha256Sum == "" {
		return nil
	}
	svcPath := path.Join(common.ServicesKeyPath, sha256Sum)
	// Lock that sha256Sum
	lockKey, err := kvstore.LockPath(svcPath)
	if err != nil {
		return err
	}
	defer lockKey.Unlock()

	// After lock complete, get label's path
	rmsg, err := kvstore.Client().GetValue(svcPath)
	if err != nil {
		return err
	}
	if rmsg == nil {
		return nil
	}

	var l3n4AddrID types.L3n4AddrID
	if err := json.Unmarshal(rmsg, &l3n4AddrID); err != nil {
		return err
	}
	oldL3n4ID := l3n4AddrID.ID
	l3n4AddrID.ID = 0

	// update the value in the kvstore
	if err := updateL3n4AddrIDRef(oldL3n4ID, l3n4AddrID); err != nil {
		return err
	}
	return kvstore.Client().SetValue(svcPath, l3n4AddrID)
}

// GetMaxServiceID returns the maximum possible free UUID stored in the kvstore.
func GetMaxServiceID() (uint32, error) {
	return kvstore.Client().GetMaxID(common.LastFreeServiceIDKeyPath, common.FirstFreeServiceID)
}
