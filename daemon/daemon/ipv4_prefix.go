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
	"github.com/cilium/cilium/common/addressing"
)

func (d *Daemon) updateIPv4Prefix(nodeIPv4 *addressing.NodeIPv4Prefix) error {
	key := path.Join(common.IPv4PrefixKeyPath, strconv.FormatUint(uint64(nodeIPv4.ID), 10))
	return d.kvClient.SetValue(key, nodeIPv4)
}

// gasNewSecLabelID gets and sets a New SecLabel ID.
func (d *Daemon) gasNewIPv4Prefix(nodeIPv4 *addressing.NodeIPv4Prefix) error {
	baseIPv4Prefix, err := d.GetMaxIPv4Prefix()
	if err != nil {
		return err
	}

	return d.kvClient.GASNewIPv4Prefix(common.IPv4PrefixKeyPath, baseIPv4Prefix, nodeIPv4)
}

// PutNodeAddr stores the given nodeAddr in the KVStore and returns the NodeIPv4Prefix
// created for the given nodeAddr.
func (d *Daemon) PutNodeAddr(nodeAddr string) (*addressing.NodeIPv4Prefix, bool, error) {
	isNew := false

	nodeAddrPath := path.Join(common.NodeAddrKeyPath, nodeAddr)

	// Lock that sha256Sum
	lockKey, err := d.kvClient.LockPath(nodeAddrPath)
	if err != nil {
		return nil, false, err
	}
	defer lockKey.Unlock()

	// After lock complete, get label's path
	ipv4PrefixRaw, err := d.kvClient.GetValue(nodeAddrPath)
	if err != nil {
		return nil, false, err
	}

	ipv4Prefix := addressing.NodeIPv4Prefix{NodeAddr: nodeAddr}

	if ipv4PrefixRaw != nil {
		if err := json.Unmarshal(ipv4PrefixRaw, &ipv4Prefix); err != nil {
			return nil, false, err
		}
		if !ipv4Prefix.IsValid() {
			isNew = true
		}
	} else {
		isNew = true
	}

	if isNew {
		if err := d.gasNewIPv4Prefix(&ipv4Prefix); err != nil {
			return nil, false, err
		}
	} else {
		ipv4Prefix.RefreshLastTimeSeen()
		if err := d.updateIPv4Prefix(&ipv4Prefix); err != nil {
			return nil, false, err
		}
	}

	log.Debugf("Setting NodeIPv4Prefix for %s: %s\n", nodeAddrPath, ipv4Prefix)

	err = d.kvClient.SetValue(nodeAddrPath, ipv4Prefix)

	return &ipv4Prefix, isNew, err
}

// GetNodeIPv4Prefix returns the NodeIPv4Prefix that belongs to the IPv4 prefix ID.
func (d *Daemon) GetNodeIPv4Prefix(id uint32) (*addressing.NodeIPv4Prefix, error) {
	strID := strconv.FormatUint(uint64(id), 10)
	rmsg, err := d.kvClient.GetValue(path.Join(common.IPv4PrefixKeyPath, strID))
	if err != nil {
		return nil, err
	}
	if rmsg == nil {
		return nil, nil
	}

	var nodeIPv4Prefix addressing.NodeIPv4Prefix
	if err := json.Unmarshal(rmsg, &nodeIPv4Prefix); err != nil {
		return nil, err
	}
	if !nodeIPv4Prefix.IsValid() {
		return nil, nil
	}
	return &nodeIPv4Prefix, nil
}

// GetNodeIPv4PrefixByNodeAddr returns the NodeIPv4Prefix that have the given nodeAddr.
func (d *Daemon) GetNodeIPv4PrefixByNodeAddr(nodeAddr string) (*addressing.NodeIPv4Prefix, error) {
	path := path.Join(common.NodeAddrKeyPath, nodeAddr)
	rmsg, err := d.kvClient.GetValue(path)
	if err != nil {
		return nil, err
	}
	if rmsg == nil {
		return nil, nil
	}

	var nodeIPv4Prefix addressing.NodeIPv4Prefix
	if err := json.Unmarshal(rmsg, &nodeIPv4Prefix); err != nil {
		return nil, err
	}
	if !nodeIPv4Prefix.IsValid() {
		return nil, nil
	}
	return &nodeIPv4Prefix, nil
}

// DeleteNodeIPv4PrefixByUUID deletes the NodeIPv4Prefix belonging to the given id.
func (d *Daemon) DeleteNodeIPv4PrefixByUUID(id uint32) error {
	nodeIPv4Prefix, err := d.GetNodeIPv4Prefix(id)
	if err != nil {
		return err
	}
	if nodeIPv4Prefix == nil {
		return nil
	}
	return d.DeleteNodeIPv4PrefixByNodeAddr(nodeIPv4Prefix.NodeAddr)
}

// DeleteNodeIPv4PrefixByNodeAddr deletes the NodeIPv4Prefix that belong to the nodeAddr.
func (d *Daemon) DeleteNodeIPv4PrefixByNodeAddr(nodeAddr string) error {
	if nodeAddr == "" {
		return nil
	}
	nodeAddrPath := path.Join(common.NodeAddrKeyPath, nodeAddr)
	// Lock that sha256Sum
	lockKey, err := d.kvClient.LockPath(nodeAddrPath)
	if err != nil {
		return err
	}
	defer lockKey.Unlock()

	// After lock complete, get nodeAddr's value
	rmsg, err := d.kvClient.GetValue(nodeAddrPath)
	if err != nil {
		return err
	}
	if rmsg == nil {
		return nil
	}

	var nodeIPv4Prefix addressing.NodeIPv4Prefix
	if err := json.Unmarshal(rmsg, &nodeIPv4Prefix); err != nil {
		return err
	}

	nodeIPv4Prefix.SetInvalid()

	log.Debugf("Deleting node addr %s\n", nodeAddr)

	if err := d.updateIPv4Prefix(&nodeIPv4Prefix); err != nil {
		return err
	}

	return d.kvClient.SetValue(nodeAddrPath, nodeIPv4Prefix)
}

// GetMaxIPv4Prefix returns the maximum possible free IPv4Prefix stored in the KVStore.
func (d *Daemon) GetMaxIPv4Prefix() (uint32, error) {
	return d.kvClient.GetMaxID(common.LastFreeIPv4PrefixKeyPath, common.FirstFreeIPv4Prefix)
}
