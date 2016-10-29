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

func (d *Daemon) updateServiceL4IDRef(serviceID uint16, svcl4ID types.L3n4AddrID) error {
	key := path.Join(common.ServiceIDKeyPath, strconv.FormatUint(uint64(serviceID), 10))
	return d.kvClient.SetValue(key, svcl4ID)
}

// gasNewServiceL4ID gets and sets a New ServiceL4 ID.
func (d *Daemon) gasNewServiceL4ID(svcl4 *types.L3n4AddrID) error {
	baseID, err := d.GetMaxServiceID()
	if err != nil {
		return err
	}

	return d.kvClient.GASNewServiceL4ID(common.ServiceIDKeyPath, baseID, svcl4)
}

// PutServiceL4 stores the given service in the kvstore and returns the ServiceL4ID
// created for the given servicel4.
func (d *Daemon) PutServiceL4(svcl4 types.L3n4Addr) (*types.L3n4AddrID, error) {
	log.Debugf("Resolving service %+v", svcl4)

	// Retrieve unique SHA256Sum for service
	sha256Sum, err := svcl4.SHA256Sum()
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
		sl4KV.L3n4Addr = svcl4
		if err := d.gasNewServiceL4ID(&sl4KV); err != nil {
			return nil, err
		}
		err = d.kvClient.SetValue(svcPath, sl4KV)
	}

	return &sl4KV, err
}

func (d *Daemon) getServiceL4ID(keyPath string) (*types.L3n4AddrID, error) {
	rmsg, err := d.kvClient.GetValue(keyPath)
	if err != nil {
		return nil, err
	}
	if rmsg == nil {
		return nil, nil
	}

	var svcl4ID types.L3n4AddrID
	if err := json.Unmarshal(rmsg, &svcl4ID); err != nil || svcl4ID.ID == 0 {
		return nil, err
	}
	return &svcl4ID, nil
}

// GetServiceL4ID returns the ServiceL4ID that belongs to the given id.
func (d *Daemon) GetServiceL4ID(id uint32) (*types.L3n4AddrID, error) {
	strID := strconv.FormatUint(uint64(id), 10)
	return d.getServiceL4ID(path.Join(common.ServiceIDKeyPath, strID))
}

// GetServiceL4IDBySHA256 returns the ServiceL4ID that have the given SHA256SUM.
func (d *Daemon) GetServiceL4IDBySHA256(sha256sum string) (*types.L3n4AddrID, error) {
	return d.getServiceL4ID(path.Join(common.ServicesKeyPath, sha256sum))
}

// DeleteServiceL4IDByUUID deletes the ServiceL4ID belonging to the given id.
func (d *Daemon) DeleteServiceL4IDByUUID(id uint32) error {
	svcl4ID, err := d.GetServiceL4ID(id)
	if err != nil {
		return err
	}
	if svcl4ID == nil {
		return nil
	}
	sha256sum, err := svcl4ID.SHA256Sum()
	if err != nil {
		return err
	}

	return d.DeleteServiceL4IDBySHA256(sha256sum)
}

// DeleteServiceL4IDBySHA256 deletes the ServiceL4ID that belong to the serviceL4ID'
// sha256Sum.
func (d *Daemon) DeleteServiceL4IDBySHA256(sha256Sum string) error {
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

	var svcL4ID types.L3n4AddrID
	if err := json.Unmarshal(rmsg, &svcL4ID); err != nil {
		return err
	}
	oldSvcID := svcL4ID.ID
	svcL4ID.ID = 0

	// update the value in the kvstore
	if err := d.updateServiceL4IDRef(uint16(oldSvcID), svcL4ID); err != nil {
		return err
	}

	return d.kvClient.SetValue(svcPath, svcL4ID)
}

// GetMaxServiceID returns the maximum possible free UUID stored in the kvstore.
func (d *Daemon) GetMaxServiceID() (uint32, error) {
	return d.kvClient.GetMaxID(common.LastFreeServiceIDKeyPath, common.FirstFreeServiceID)
}
