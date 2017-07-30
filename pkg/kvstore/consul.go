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
	"errors"
	"fmt"
	"path"
	"strconv"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/policy"

	log "github.com/Sirupsen/logrus"
	consulAPI "github.com/hashicorp/consul/api"
)

const (
	// cAddr is the string representing the key mapping to the value of the
	// address for Consul.
	cAddr = "consul.address"
)

// / ConsulOpts is the set of supported options for Consul configuration.
var ConsulOpts = map[string]bool{
	cAddr: true,
}

var (
	maxRetries = 30
	retrySleep = 2 * time.Second
)

type ConsulClient struct {
	*consulAPI.Client
}

func newConsulClient(config *consulAPI.Config) (KVClient, error) {
	var (
		c   *consulAPI.Client
		err error
	)
	if config != nil {
		c, err = consulAPI.NewClient(config)
	} else {
		c, err = consulAPI.NewClient(consulAPI.DefaultConfig())
	}
	if err != nil {
		return nil, err
	}

	for i := 0; i < maxRetries; i++ {
		var leader string
		leader, err = c.Status().Leader()

		if err == nil {
			if leader != "" {
				// happy path
				break
			} else {
				err = errors.New("no leader returned")
			}
		}

		log.Info("Waiting for consul client to be ready...")
		time.Sleep(retrySleep)
	}

	if err != nil {
		e := fmt.Errorf("Unable to contact consul: %s", err)
		log.Error(e)
		return nil, e
	}
	cc := &ConsulClient{c}
	// Clean-up old services path
	cc.DeleteTree(common.ServicePathV1)

	log.Info("Consul client ready")
	return cc, nil
}

func (c *ConsulClient) LockPath(path string) (KVLocker, error) {
	log.Debugf("Creating lock for %s", path)
	opts := &consulAPI.LockOptions{
		Key: GetLockPath(path),
	}
	lockKey, err := c.LockOpts(opts)
	if err != nil {
		return nil, err
	}
	ch, err := lockKey.Lock(nil)
	defer func() {
		if err == nil {
			log.Debugf("Locked for %s", path)
		}
	}()
	if ch == nil {
		return nil, fmt.Errorf("locker is nil\n")
	}
	return lockKey, err
}

func (c *ConsulClient) InitializeFreeID(path string, firstID uint32) error {
	freeIDByte, err := json.Marshal(firstID)
	if err != nil {
		return err
	}
	session, _, err := c.Session().CreateNoChecks(nil, nil)
	if err != nil {
		return err
	}

	p := &consulAPI.KVPair{Key: path, Value: freeIDByte}
	lockPair := &consulAPI.KVPair{Key: GetLockPath(path), Session: session}
	log.Debug("Trying to acquire lock for free ID...")
	acq, _, err := c.KV().Acquire(lockPair, nil)
	if err != nil {
		return err
	}
	if !acq {
		return nil
	}
	defer c.KV().Release(lockPair, nil)

	log.Debug("Trying to acquire free ID...")
	k, _, err := c.KV().Get(path, nil)
	if err != nil {
		return err
	}
	if k != nil {
		// FreeID already set
		return nil
	}
	log.Debugf("Trying to put free ID...")
	_, err = c.KV().Put(p, nil)
	if err != nil {
		return err
	}
	log.Debugf("Free ID for path %s successfully initialized", path)

	return nil
}

func (c *ConsulClient) SetValue(k string, v interface{}) error {
	var err error
	lblKey := &consulAPI.KVPair{Key: k}
	lblKey.Value, err = json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = c.KV().Put(lblKey, nil)
	return err
}

func (c *ConsulClient) GetValue(k string) (json.RawMessage, error) {
	pair, _, err := c.KV().Get(k, nil)
	if err != nil {
		return nil, err
	}
	if pair == nil {
		return nil, nil
	}
	return json.RawMessage(pair.Value), nil
}

// GetMaxID returns the maximum possible free UUID stored in consul.
func (c *ConsulClient) GetMaxID(key string, firstID uint32) (uint32, error) {
	k, _, err := c.KV().Get(key, nil)
	if err != nil {
		return 0, err
	}
	if k == nil {
		// FreeID is empty? We should set it out!
		log.Debugf("Empty FreeID, setting it up with default value %d", firstID)
		if err := c.InitializeFreeID(key, firstID); err != nil {
			return 0, err
		}
		k, _, err = c.KV().Get(key, nil)
		if err != nil {
			return 0, err
		}
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

func (c *ConsulClient) SetMaxID(key string, firstID, maxID uint32) error {
	k, _, err := c.KV().Get(key, nil)
	if err != nil {
		return err
	}
	if k == nil {
		// FreeIDs is empty? We should set it out!
		if err := c.InitializeFreeID(key, firstID); err != nil {
			return err
		}
		k, _, err = c.KV().Get(key, nil)
		if k == nil {
			// Something is really wrong
			errMsg := "Unable to setting ID because the key is always empty\n"
			log.Errorf(errMsg)
			return fmt.Errorf(errMsg)
		}
	}
	k.Value, err = json.Marshal(maxID)
	if err != nil {
		return err
	}
	_, err = c.KV().Put(k, nil)
	return err
}

func (c *ConsulClient) updateSecLabelIDRef(id policy.Identity) error {
	key := path.Join(common.LabelIDKeyPath, strconv.FormatUint(uint64(id.ID), 10))
	return c.SetValue(key, id)
}

func (c *ConsulClient) setMaxLabelID(maxID uint32) error {
	return c.SetMaxID(common.LastFreeLabelIDKeyPath, uint32(policy.MinimalNumericIdentity), maxID)
}

func (c *ConsulClient) GASNewSecLabelID(basePath string, baseID uint32, pI *policy.Identity) error {
	setID2Label := func(new_id uint32) error {
		pI.ID = policy.NumericIdentity(new_id)
		keyPath := path.Join(basePath, pI.ID.StringID())
		if err := c.SetValue(keyPath, pI); err != nil {
			return err
		}
		return c.setMaxLabelID(new_id + 1)
	}

	session, _, err := c.Session().CreateNoChecks(nil, nil)
	if err != nil {
		return err
	}

	acquireFreeID := func(firstID uint32, incID *uint32) (bool, error) {
		log.Debugf("Trying to acquire a new free seclabel ID %d", *incID)
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(*incID), 10))

		lockPair := &consulAPI.KVPair{Key: GetLockPath(keyPath), Session: session}
		acq, _, err := c.KV().Acquire(lockPair, nil)
		if err != nil {
			return false, err
		}
		defer c.KV().Release(lockPair, nil)

		if acq {
			value, err := c.GetValue(keyPath)
			if err != nil {
				return false, err
			}
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

func (c *ConsulClient) setMaxL3n4AddrID(maxID uint32) error {
	return c.SetMaxID(common.LastFreeServiceIDKeyPath, common.FirstFreeServiceID, maxID)
}

func (c *ConsulClient) GASNewL3n4AddrID(basePath string, baseID uint32, lAddrID *types.L3n4AddrID) error {
	setIDtoL3n4Addr := func(id uint32) error {
		lAddrID.ID = types.ServiceID(id)
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(lAddrID.ID), 10))
		if err := c.SetValue(keyPath, lAddrID); err != nil {
			return err
		}
		return c.setMaxL3n4AddrID(id + 1)
	}

	session, _, err := c.Session().CreateNoChecks(nil, nil)
	if err != nil {
		return err
	}

	acquireFreeID := func(firstID uint32, incID *uint32) (bool, error) {
		log.Debugf("Trying to acquire a new free service ID %d", *incID)
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(*incID), 10))

		lockPair := &consulAPI.KVPair{Key: GetLockPath(keyPath), Session: session}
		acq, _, err := c.KV().Acquire(lockPair, nil)
		if err != nil {
			return false, err
		}
		defer c.KV().Release(lockPair, nil)

		if acq {
			svcKey, _, err := c.KV().Get(keyPath, nil)
			if err != nil {
				return false, err
			}
			if svcKey == nil {
				return false, setIDtoL3n4Addr(*incID)
			}
			var consulL3n4AddrID types.L3n4AddrID
			if err := json.Unmarshal(svcKey.Value, &consulL3n4AddrID); err != nil {
				return false, err
			}
			if consulL3n4AddrID.ID == 0 {
				log.Infof("Recycling Service ID %d", baseID)
				return false, setIDtoL3n4Addr(*incID)
			}
		}

		*incID++
		if *incID > common.MaxSetOfServiceID {
			*incID = common.FirstFreeServiceID
		}
		if firstID == *incID {
			return false, fmt.Errorf("reached maximum set of serviceIDs available.")
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

// GetWatcher watches for kvstore changes in the given key. Triggers the returned channel
// every time the key path is changed.
// FIXME This function is highly tightened to the maxFreeID, change name accordingly
func (c *ConsulClient) GetWatcher(key string, timeSleep time.Duration) <-chan []policy.NumericIdentity {
	ch := make(chan []policy.NumericIdentity, 100)
	go func(ch chan []policy.NumericIdentity) {
		curSeconds := time.Second
		var (
			k   *consulAPI.KVPair
			q   *consulAPI.QueryMeta
			qo  consulAPI.QueryOptions
			err error
		)
		for {
			k, q, err = c.KV().Get(key, &qo)
			if err != nil {
				log.Errorf("Unable to retrieve last free Index: %s", err)
			}
			if k == nil || q == nil {
				log.Warning("Unable to retrieve last free Index, please start some containers with labels.")
				time.Sleep(curSeconds)
				if curSeconds < timeSleep {
					curSeconds += time.Second
				}
				continue
			}
			curSeconds = time.Second
			qo.WaitIndex = q.LastIndex
			maxFreeID := uint32(0)
			if err := json.Unmarshal(k.Value, &maxFreeID); err == nil {
				ch <- []policy.NumericIdentity{policy.NumericIdentity(maxFreeID)}
			}
		}
	}(ch)
	return ch
}

func (c *ConsulClient) Status() (string, error) {
	leader, err := c.Client.Status().Leader()
	return "Consul: " + leader, err
}

func (c *ConsulClient) DeleteTree(path string) error {
	_, err := c.Client.KV().DeleteTree(path, nil)
	return err
}

// StartWatch starts watching for changes in a prefix
func (c *ConsulClient) StartWatch(w *Watcher) {
	go func(w *Watcher) {
		nextIndex := uint64(0)

		// block Get() calls for 5 seconds maximum
		qo := consulAPI.QueryOptions{
			WaitTime: time.Duration(5) * time.Second,
		}

		for {
			// if all goes well we don't sleep between watch cycles
			sleepTime := time.Duration(1) * time.Millisecond

			qo.WaitIndex = nextIndex
			res, q, err := c.KV().Get(w.prefix, &qo)
			if err != nil {
				// in case of error, sleep for 15 seconds before retrying
				sleepTime = time.Duration(15) * time.Second
				log.Debugf("watcher %s failed (consul): %s", w.name, err)
			}

			if q != nil {
				nextIndex = q.LastIndex
			}

			// WaitIndex == 0 means that this was the first ever
			// Get() and there is no change, trigger a follow-up
			// Get() with updated WaitIndex immediately
			if qo.WaitIndex == 0 {
				continue
			}

			// If Get() returned a response, check if the LastIndex
			// is different or whether this was a timed out
			// blocking Get() call
			if res != nil && (q == nil || q.LastIndex != qo.WaitIndex) {
				w.Events <- KeyValueEvent{
					Typ:   EventTypeModify,
					Key:   res.Key,
					Value: res.Value,
				}
			}

			select {
			case <-time.After(sleepTime):
			case <-w.stopWatch:
				return
			}
		}
	}(w)
}
