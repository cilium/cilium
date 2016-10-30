//
// Copyright 2016 Authors of Cilium
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
//
package daemon

import (
	"encoding/json"
	"path"
	"strconv"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"
)

func (d *Daemon) updateL3n4AddrIDRef(id types.ServiceID, l3n4AddrID types.L3n4AddrID) error {
	key := path.Join(common.ServiceIDKeyPath, strconv.FormatUint(uint64(id), 10))
	return d.kvClient.SetValue(key, l3n4AddrID)
}

// gasNewL3n4AddrID gets and sets a new L3n4Addr ID.
func (d *Daemon) gasNewL3n4AddrID(l3n4AddrID *types.L3n4AddrID) error {
	baseID, err := d.GetMaxServiceID()
	if err != nil {
		return err
	}

	return d.kvClient.GASNewL3n4AddrID(common.ServiceIDKeyPath, baseID, l3n4AddrID)
}

// PutL3n4Addr stores the given service in the kvstore and returns the L3n4AddrID
// created for the given l3n4Addr.
func (d *Daemon) PutL3n4Addr(l3n4Addr types.L3n4Addr) (*types.L3n4AddrID, error) {
	log.Debugf("Resolving service %+v", l3n4Addr)

	// Retrieve unique SHA256Sum for service
	sha256Sum, err := l3n4Addr.SHA256Sum()
	if err != nil {
		return nil, err
	}
	svcPath := path.Join(common.ServicesKeyPath, sha256Sum)

	// Lock that sha256Sum
	lockKey, err := d.kvClient.LockPath(svcPath)
	if err != nil {
		return nil, err
	}
	defer lockKey.Unlock()

	// After lock complete, get svc's path
	rmsg, err := d.kvClient.GetValue(svcPath)
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
		if err := d.gasNewL3n4AddrID(&sl4KV); err != nil {
			return nil, err
		}
		err = d.kvClient.SetValue(svcPath, sl4KV)
	}

	return &sl4KV, err
}

func (d *Daemon) getL3n4AddrID(keyPath string) (*types.L3n4AddrID, error) {
	rmsg, err := d.kvClient.GetValue(keyPath)
	if err != nil {
		return nil, err
	}
	if rmsg == nil {
		return nil, nil
	}

	var l3n4AddrID types.L3n4AddrID
	if err := json.Unmarshal(rmsg, &l3n4AddrID); err != nil || l3n4AddrID.ID == 0 {
		return nil, err
	}
	return &l3n4AddrID, nil
}

// GetL3n4AddrID returns the L3n4AddrID that belongs to the given id.
func (d *Daemon) GetL3n4AddrID(id uint32) (*types.L3n4AddrID, error) {
	strID := strconv.FormatUint(uint64(id), 10)
	return d.getL3n4AddrID(path.Join(common.ServiceIDKeyPath, strID))
}

// GetL3n4AddrIDBySHA256 returns the L3n4AddrID that have the given SHA256SUM.
func (d *Daemon) GetL3n4AddrIDBySHA256(sha256sum string) (*types.L3n4AddrID, error) {
	return d.getL3n4AddrID(path.Join(common.ServicesKeyPath, sha256sum))
}

// DeleteL3n4AddrIDByUUID deletes the L3n4AddrID belonging to the given id.
func (d *Daemon) DeleteL3n4AddrIDByUUID(id uint32) error {
	l3n4AddrID, err := d.GetL3n4AddrID(id)
	if err != nil {
		return err
	}
	if l3n4AddrID == nil {
		return nil
	}
	sha256sum, err := l3n4AddrID.SHA256Sum()
	if err != nil {
		return err
	}

	return d.DeleteL3n4AddrIDBySHA256(sha256sum)
}

// DeleteL3n4AddrIDBySHA256 deletes the L3n4AddrID that belong to the serviceL4ID'
// sha256Sum.
func (d *Daemon) DeleteL3n4AddrIDBySHA256(sha256Sum string) error {
	if sha256Sum == "" {
		return nil
	}
	svcPath := path.Join(common.ServicesKeyPath, sha256Sum)
	// Lock that sha256Sum
	lockKey, err := d.kvClient.LockPath(svcPath)
	if err != nil {
		return err
	}
	defer lockKey.Unlock()

	// After lock complete, get label's path
	rmsg, err := d.kvClient.GetValue(svcPath)
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
	if err := d.updateL3n4AddrIDRef(oldL3n4ID, l3n4AddrID); err != nil {
		return err
	}

	return d.kvClient.SetValue(svcPath, l3n4AddrID)
}

// GetMaxServiceID returns the maximum possible free UUID stored in the kvstore.
func (d *Daemon) GetMaxServiceID() (uint32, error) {
	return d.kvClient.GetMaxID(common.LastFreeServiceIDKeyPath, common.FirstFreeServiceID)
}
