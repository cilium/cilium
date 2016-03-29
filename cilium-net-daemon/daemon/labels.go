package daemon

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	consulAPI "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/hashicorp/consul/api"
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

func (d *Daemon) updateIDRef(secCtxLabels *types.SecCtxLabels) error {
	var err error
	lblKey := &consulAPI.KVPair{Key: common.IDKeyPath + strconv.Itoa(secCtxLabels.ID)}
	lblKey.Value, err = json.Marshal(secCtxLabels)
	if err != nil {
		return err
	}
	_, err = d.consul.KV().Put(lblKey, nil)
	return err
}

// SAGNewID gets and sets a New ID,
func (d *Daemon) gasNewID(labels *types.SecCtxLabels) error {
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
		path := common.IDKeyPath + strconv.Itoa(freeID)

		lockPair := &consulAPI.KVPair{Key: common.GetLockPath(path), Session: session}
		acq, _, err := d.consul.KV().Acquire(lockPair, nil)
		if err != nil {
			return err
		}

		if acq {
			lblKey, _, err := d.consul.KV().Get(path, nil)
			if err != nil {
				d.consul.KV().Release(lockPair, nil)
				return err
			}
			if lblKey == nil {
				return setID2Label(lockPair)
			} else {
				var consulLabels types.SecCtxLabels
				if err := json.Unmarshal(lblKey.Value, &consulLabels); err != nil {
					d.consul.KV().Release(lockPair, nil)
					return err
				}
				if consulLabels.RefCount == 0 {
					log.Info("Recycling ID %d", freeID)
					return setID2Label(lockPair)
				}
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
	return nil
}

func (d *Daemon) PutLabels(labels types.Labels) (*types.SecCtxLabels, bool, error) {
	isNew := false

	// Retrieve unique SHA256Sum for labels
	sha256Sum, err := labels.SHA256Sum()
	if err != nil {
		return nil, false, err
	}
	lblPath := common.LabelsKeyPath + sha256Sum

	// Lock that sha256Sum
	log.Debugf("Creating lock for %s", sha256Sum)
	opts := &consulAPI.LockOptions{
		Key: common.GetLockPath(lblPath),
	}
	lockKey, err := d.consul.LockOpts(opts)
	if err != nil {
		return nil, false, err
	}
	log.Debugf("Locking for %s", sha256Sum)
	locker, err := lockKey.Lock(nil)
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

	var secCtxLbls types.SecCtxLabels
	if pair == nil {
		pair = &consulAPI.KVPair{Key: lblPath}
		secCtxLbls.Labels = labels
		secCtxLbls.RefCount = 1
		isNew = true
	} else {
		if err := json.Unmarshal(pair.Value, &secCtxLbls); err != nil {
			return nil, false, err
		}
		// If RefCount is 0 then we have to retrieve a new ID
		if secCtxLbls.RefCount == 0 {
			isNew = true
		}
		secCtxLbls.RefCount++
	}

	if isNew {
		if err := d.gasNewID(&secCtxLbls); err != nil {
			return nil, false, err
		}
	} else {
		if err := d.updateIDRef(&secCtxLbls); err != nil {
			return nil, false, err
		}
	}
	log.Debugf("Incrementing label %d ref-count to %d\n", secCtxLbls.ID, secCtxLbls.RefCount)

	secCtxLblsByte, err := json.Marshal(secCtxLbls)
	if err != nil {
		return nil, false, err
	}

	pair.Value = secCtxLblsByte
	_, err = d.consul.KV().Put(pair, nil)
	if err != nil {
		return nil, false, err
	}

	return &secCtxLbls, isNew, nil
}

func (d *Daemon) GetLabels(id int) (*types.SecCtxLabels, error) {
	strID := strconv.Itoa(id)
	pair, _, err := d.consul.KV().Get(common.IDKeyPath+strID, nil)
	if err != nil {
		return nil, err
	}
	if pair == nil {
		return nil, nil
	}
	var secCtxLabels types.SecCtxLabels
	if err := json.Unmarshal(pair.Value, &secCtxLabels); err != nil {
		return nil, err
	}
	return &secCtxLabels, nil
}

func (d *Daemon) GetMaxID() (int, error) {
	k, _, err := d.consul.KV().Get(common.LastFreeIDKeyPath, nil)
	if err != nil {
		return -1, err
	}
	if k == nil {
		// FreeID is empty? We should set it out!
		log.Infof("Empty FreeID, setting it up with default value %d", common.FirstFreeID)
		if err := d.initializeFreeID(); err != nil {
			return -1, err
		}
		k, _, err = d.consul.KV().Get(common.LastFreeIDKeyPath, nil)
		if k == nil {
			// Something is really wrong
			errMsg := "Unable to retrieve last free ID because the key is always empty\n"
			log.Errorf(errMsg)
			return -1, fmt.Errorf(errMsg)
		}
	}
	var freeID int
	log.Debugf("Retrieving max free ID %v", k.Value)
	if err := json.Unmarshal(k.Value, &freeID); err != nil {
		return -1, err
	}
	return freeID, nil
}

func (d *Daemon) setMaxID(freeID int) error {
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
