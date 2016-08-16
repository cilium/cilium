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
	"fmt"
	"path"
	"strconv"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"

	consulAPI "github.com/hashicorp/consul/api"
)

func (d *Daemon) initializeFreeID() error {
	path := common.LastFreeIDKeyPath
	freeIDByte, err := json.Marshal(common.FirstFreeID)
	if err != nil {
		return err
	}
	session, _, err := d.consul.Session().CreateNoChecks(nil, nil)
	if err != nil {
		return err
	}

	p := &consulAPI.KVPair{Key: path, Value: freeIDByte}
	lockPair := &consulAPI.KVPair{Key: common.GetLockPath(path), Session: session}
	log.Debug("Trying to acquire lock for free ID...")
	acq, _, err := d.consul.KV().Acquire(lockPair, nil)
	if err != nil {
		return err
	}
	if !acq {
		return nil
	}
	defer d.consul.KV().Release(lockPair, nil)

	log.Debug("Trying to acquire free ID...")
	k, _, err := d.consul.KV().Get(path, nil)
	if err != nil {
		return err
	}
	if k != nil {
		// FreeID already set
		return nil
	}
	log.Info("Trying to put free ID...")
	_, err = d.consul.KV().Put(p, nil)
	if err != nil {
		return err
	}
	log.Info("Free ID successfully initialized")

	return nil
}

func (d *Daemon) updateIDRef(secCtxLabels *types.SecCtxLabel) error {
	var err error
	lblKey := &consulAPI.KVPair{Key: path.Join(common.IDKeyPath, strconv.FormatUint(uint64(secCtxLabels.ID), 10))}
	lblKey.Value, err = json.Marshal(secCtxLabels)
	if err != nil {
		return err
	}
	_, err = d.consul.KV().Put(lblKey, nil)
	return err
}

// gasNewID gets and sets a New ID.
func (d *Daemon) gasNewID(labels *types.SecCtxLabel) error {
	freeID, err := d.GetMaxID()
	if err != nil {
		return err
	}

	setID2Label := func(lockPair *consulAPI.KVPair) error {
		defer d.consul.KV().Release(lockPair, nil)
		labels.ID = freeID
		if err := d.updateIDRef(labels); err != nil {
			return err
		}
		return d.setMaxID(freeID + 1)
	}

	session, _, err := d.consul.Session().CreateNoChecks(nil, nil)
	if err != nil {
		return err
	}

	beginning := freeID
	for {
		log.Debugf("Trying to aquire a new free ID %d", freeID)
		lockPath := path.Join(common.IDKeyPath, strconv.FormatUint(uint64(freeID), 10))

		lockPair := &consulAPI.KVPair{Key: common.GetLockPath(lockPath), Session: session}
		acq, _, err := d.consul.KV().Acquire(lockPair, nil)
		if err != nil {
			return err
		}

		if acq {
			lblKey, _, err := d.consul.KV().Get(lockPath, nil)
			if err != nil {
				d.consul.KV().Release(lockPair, nil)
				return err
			}
			if lblKey == nil {
				return setID2Label(lockPair)
			}
			var consulLabels types.SecCtxLabel
			if err := json.Unmarshal(lblKey.Value, &consulLabels); err != nil {
				d.consul.KV().Release(lockPair, nil)
				return err
			}
			if consulLabels.RefCount() == 0 {
				log.Info("Recycling ID %d", freeID)
				return setID2Label(lockPair)
			}
			d.consul.KV().Release(lockPair, nil)
		}
		freeID++
		if freeID > common.MaxSetOfLabels {
			freeID = common.FirstFreeID
		}
		if beginning == freeID {
			return fmt.Errorf("Reached maximum set of labels available.")
		}
	}
}

func (d *Daemon) lockPath(path string) (*consulAPI.Lock, <-chan struct{}, error) {
	log.Debugf("Creating lock for %s", path)
	opts := &consulAPI.LockOptions{
		Key: common.GetLockPath(path),
	}
	lockKey, err := d.consul.LockOpts(opts)
	if err != nil {
		return nil, nil, err
	}
	c, err := lockKey.Lock(nil)
	defer func() {
		if err == nil {
			log.Debugf("Locked for %s", path)
		}
	}()
	return lockKey, c, err
}

// PutLabels stores to given labels in consul and returns the SecCtxLabels created for
// the given labels.
func (d *Daemon) PutLabels(labels types.Labels, contID string) (*types.SecCtxLabel, bool, error) {
	log.Debugf("Resolving labels %+v of %s", labels, contID)

	isNew := false

	// Retrieve unique SHA256Sum for labels
	sha256Sum, err := labels.SHA256Sum()
	if err != nil {
		return nil, false, err
	}
	lblPath := path.Join(common.LabelsKeyPath, sha256Sum)

	// Lock that sha256Sum
	lockKey, locker, err := d.lockPath(lblPath)
	if err != nil {
		return nil, false, err
	}
	if locker == nil {
		return nil, false, fmt.Errorf("locker is nil\n")
	}
	defer lockKey.Unlock()

	// After lock complete, get label's path
	pair, _, err := d.consul.KV().Get(lblPath, nil)
	if err != nil {
		return nil, false, err
	}

	secCtxLbls := types.NewSecCtxLabel()
	if pair == nil {
		pair = &consulAPI.KVPair{Key: lblPath}
		secCtxLbls.Labels = labels
		isNew = true
	} else {
		if err := json.Unmarshal(pair.Value, &secCtxLbls); err != nil {
			return nil, false, err
		}
		// If RefCount is 0 then we have to retrieve a new ID
		if secCtxLbls.RefCount() == 0 {
			isNew = true
			secCtxLbls.Containers = make(map[string]time.Time)
		}
	}
	secCtxLbls.AddOrUpdateContainer(contID)

	if isNew {
		if err := d.gasNewID(secCtxLbls); err != nil {
			return nil, false, err
		}
	} else if err := d.updateIDRef(secCtxLbls); err != nil {
		return nil, false, err
	}
	log.Debugf("Incrementing label %d ref-count to %d\n", secCtxLbls.ID, secCtxLbls.RefCount())

	d.AddOrUpdateUINode(secCtxLbls.ID, secCtxLbls.Labels.ToSlice(), secCtxLbls.RefCount())

	secCtxLblsByte, err := json.Marshal(secCtxLbls)
	if err != nil {
		return nil, false, err
	}

	pair.Value = secCtxLblsByte
	_, err = d.consul.KV().Put(pair, nil)
	if err != nil {
		return nil, false, err
	}

	return secCtxLbls, isNew, nil
}

// GetLabels returns the SecCtxLabels that belongs to the given id.
func (d *Daemon) GetLabels(id uint32) (*types.SecCtxLabel, error) {
	if id > 0 && id < common.FirstFreeID {
		key := types.ReservedID(id).String()
		if key == "" {
			return nil, nil
		}

		lbl := types.NewLabel(
			key, "", common.ReservedLabelSource,
		)
		secLbl := types.NewSecCtxLabel()
		secLbl.AddOrUpdateContainer(lbl.String())
		secLbl.ID = id
		secLbl.Labels = types.Labels{
			common.ReservedLabelSource: lbl,
		}

		return secLbl, nil
	}

	strID := strconv.FormatUint(uint64(id), 10)
	pair, _, err := d.consul.KV().Get(path.Join(common.IDKeyPath, strID), nil)
	if err != nil {
		return nil, err
	}
	if pair == nil {
		return nil, nil
	}
	var secCtxLabels types.SecCtxLabel
	if err := json.Unmarshal(pair.Value, &secCtxLabels); err != nil {
		return nil, err
	}
	if secCtxLabels.RefCount() == 0 {
		return nil, nil
	}
	return &secCtxLabels, nil
}

// GetLabelsBySHA256 returns the SecCtxLabels that have the given SHA256SUM.
func (d *Daemon) GetLabelsBySHA256(sha256sum string) (*types.SecCtxLabel, error) {
	pair, _, err := d.consul.KV().Get(path.Join(common.LabelsKeyPath, sha256sum), nil)
	if err != nil {
		return nil, err
	}
	if pair == nil {
		return nil, nil
	}
	var secCtxLabels types.SecCtxLabel
	if err := json.Unmarshal(pair.Value, &secCtxLabels); err != nil {
		return nil, err
	}
	if secCtxLabels.RefCount() == 0 {
		return nil, nil
	}
	return &secCtxLabels, nil
}

// DeleteLabelsByUUID deletes the SecCtxLabels belonging to the given id.
func (d *Daemon) DeleteLabelsByUUID(id uint32, contID string) error {
	secCtxLabels, err := d.GetLabels(id)
	if err != nil {
		return err
	}
	if secCtxLabels == nil {
		return nil
	}
	sha256sum, err := secCtxLabels.Labels.SHA256Sum()
	if err != nil {
		return err
	}

	return d.DeleteLabelsBySHA256(sha256sum, contID)
}

// DeleteLabelsBySHA256 deletes the SecCtxLabels that belong to the labels' sha256Sum.
func (d *Daemon) DeleteLabelsBySHA256(sha256Sum string, contID string) error {
	if sha256Sum == "" {
		return nil
	}
	lblPath := path.Join(common.LabelsKeyPath, sha256Sum)
	// Lock that sha256Sum
	lockKey, locker, err := d.lockPath(lblPath)
	if err != nil {
		return err
	}
	if locker == nil {
		return fmt.Errorf("locker is nil\n")
	}
	defer lockKey.Unlock()

	// After lock complete, get label's path
	pair, _, err := d.consul.KV().Get(lblPath, nil)
	if err != nil {
		return err
	}
	if pair == nil {
		return nil
	}

	var dbSecCtxLbls types.SecCtxLabel
	if err := json.Unmarshal(pair.Value, &dbSecCtxLbls); err != nil {
		return err
	}
	dbSecCtxLbls.DelContainer(contID)
	if err := d.updateIDRef(&dbSecCtxLbls); err != nil {
		return err
	}

	if dbSecCtxLbls.RefCount() == 0 {
		d.DeleteUINode(dbSecCtxLbls.ID)
	} else {
		d.AddOrUpdateUINode(dbSecCtxLbls.ID, dbSecCtxLbls.Labels.ToSlice(), dbSecCtxLbls.RefCount())
	}

	log.Debugf("Decremented label %d ref-count to %d\n", dbSecCtxLbls.ID, dbSecCtxLbls.RefCount())

	secCtxLblsByte, err := json.Marshal(dbSecCtxLbls)
	if err != nil {
		return err
	}

	pair.Value = secCtxLblsByte
	_, err = d.consul.KV().Put(pair, nil)
	if err != nil {
		return err
	}

	return nil
}

// GetMaxID returns the maximum possible free UUID stored in consul.
func (d *Daemon) GetMaxID() (uint32, error) {
	k, _, err := d.consul.KV().Get(common.LastFreeIDKeyPath, nil)
	if err != nil {
		return 0, err
	}
	if k == nil {
		// FreeID is empty? We should set it out!
		log.Infof("Empty FreeID, setting it up with default value %d", common.FirstFreeID)
		if err := d.initializeFreeID(); err != nil {
			return 0, err
		}
		k, _, err = d.consul.KV().Get(common.LastFreeIDKeyPath, nil)
		if k == nil {
			// Something is really wrong
			errMsg := "Unable to retrieve last free ID because the key is always empty\n"
			log.Errorf(errMsg)
			return 0, fmt.Errorf(errMsg)
		}
	}
	var freeID uint32
	log.Debugf("Retrieving max free ID %v", k.Value)
	if err := json.Unmarshal(k.Value, &freeID); err != nil {
		return 0, err
	}
	return freeID, nil
}

func (d *Daemon) setMaxID(freeID uint32) error {
	k, _, err := d.consul.KV().Get(common.LastFreeIDKeyPath, nil)
	if err != nil {
		return err
	}
	if k == nil {
		// FreeIDs is empty? We should set it out!
		if err := d.initializeFreeID(); err != nil {
			return err
		}
		k, _, err = d.consul.KV().Get(common.LastFreeIDKeyPath, nil)
		if k == nil {
			// Something is really wrong
			errMsg := "Unable to setting ID because the key is always empty\n"
			log.Errorf(errMsg)
			return fmt.Errorf(errMsg)
		}
	}
	k.Value, err = json.Marshal(freeID)
	if err != nil {
		return err
	}
	_, err = d.consul.KV().Put(k, nil)
	return err
}
