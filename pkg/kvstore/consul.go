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
package kvstore

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

type ConsulClient struct {
	*consulAPI.Client
}

func NewConsulClient(config *consulAPI.Config) (KVClient, error) {
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
	maxRetries := 30
	i := 0
	for {
		leader, err := c.Status().Leader()
		if err != nil || leader == "" {
			log.Info("Waiting for consul client to be ready...")
			time.Sleep(2 * time.Second)
			i++
			if i > maxRetries {
				e := fmt.Errorf("Unable to contact consul: %s", err)
				log.Error(e)
				return nil, e
			}
		} else {
			log.Info("Consul client ready")
			break
		}
	}
	return &ConsulClient{c}, nil
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
	log.Info("Trying to put free ID...")
	_, err = c.KV().Put(p, nil)
	if err != nil {
		return err
	}
	log.Info("Free ID for path %s successfully initialized", path)

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
		log.Infof("Empty FreeID, setting it up with default value %d", firstID)
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

func (c *ConsulClient) updateSecLabelIDRef(secCtxLabels types.SecCtxLabel) error {
	key := path.Join(common.LabelIDKeyPath, strconv.FormatUint(uint64(secCtxLabels.ID), 10))
	return c.SetValue(key, secCtxLabels)
}

func (c *ConsulClient) setMaxLabelID(maxID uint32) error {
	return c.SetMaxID(common.LastFreeLabelIDKeyPath, common.FirstFreeLabelID, maxID)
}

func (c *ConsulClient) GASNewSecLabelID(basePath string, baseID uint32, secCtxLabels *types.SecCtxLabel) error {

	setID2Label := func(lockPair *consulAPI.KVPair) error {
		defer c.KV().Release(lockPair, nil)
		secCtxLabels.ID = baseID
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(secCtxLabels.ID), 10))
		if err := c.SetValue(keyPath, secCtxLabels); err != nil {
			return err
		}
		return c.setMaxLabelID(baseID + 1)
	}

	session, _, err := c.Session().CreateNoChecks(nil, nil)
	if err != nil {
		return err
	}

	beginning := baseID
	for {
		log.Debugf("Trying to acquire a new free ID %d", baseID)
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(baseID), 10))

		lockPair := &consulAPI.KVPair{Key: GetLockPath(keyPath), Session: session}
		acq, _, err := c.KV().Acquire(lockPair, nil)
		if err != nil {
			return err
		}

		if acq {
			lblKey, _, err := c.KV().Get(keyPath, nil)
			if err != nil {
				c.KV().Release(lockPair, nil)
				return err
			}
			if lblKey == nil {
				return setID2Label(lockPair)
			}
			var consulLabels types.SecCtxLabel
			if err := json.Unmarshal(lblKey.Value, &consulLabels); err != nil {
				c.KV().Release(lockPair, nil)
				return err
			}
			if consulLabels.RefCount() == 0 {
				log.Infof("Recycling ID %d", baseID)
				return setID2Label(lockPair)
			}
			c.KV().Release(lockPair, nil)
		}
		baseID++
		if baseID > common.MaxSetOfLabels {
			baseID = common.FirstFreeLabelID
		}
		if beginning == baseID {
			return fmt.Errorf("reached maximum set of labels available.")
		}
	}
}

func (c *ConsulClient) setMaxServiceL4ID(maxID uint32) error {
	return c.SetMaxID(common.LastFreeServiceIDKeyPath, common.FirstFreeServiceID, maxID)
}

func (c *ConsulClient) GASNewServiceL4ID(basePath string, baseID uint32, sl4 *types.L3n4AddrID) error {

	setID2ServiceL4 := func(lockPair *consulAPI.KVPair) error {
		defer c.KV().Release(lockPair, nil)
		sl4.ID = types.ServiceID(baseID)
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(sl4.ID), 10))
		if err := c.SetValue(keyPath, sl4); err != nil {
			return err
		}
		return c.setMaxServiceL4ID(baseID + 1)
	}

	session, _, err := c.Session().CreateNoChecks(nil, nil)
	if err != nil {
		return err
	}

	beginning := baseID
	for {
		log.Debugf("Trying to aquire a new free ID %d", baseID)
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(baseID), 10))

		lockPair := &consulAPI.KVPair{Key: GetLockPath(keyPath), Session: session}
		acq, _, err := c.KV().Acquire(lockPair, nil)
		if err != nil {
			return err
		}

		if acq {
			svcKey, _, err := c.KV().Get(keyPath, nil)
			if err != nil {
				c.KV().Release(lockPair, nil)
				return err
			}
			if svcKey == nil {
				return setID2ServiceL4(lockPair)
			}
			var consulServiceL4ID types.L3n4AddrID
			if err := json.Unmarshal(svcKey.Value, &consulServiceL4ID); err != nil {
				c.KV().Release(lockPair, nil)
				return err
			}
			if consulServiceL4ID.ID == 0 {
				log.Infof("Recycling Service ID %d", baseID)
				return setID2ServiceL4(lockPair)
			}
			c.KV().Release(lockPair, nil)
		}
		baseID++
		if baseID > common.MaxSetOfServiceID {
			baseID = common.FirstFreeServiceID
		}
		if beginning == baseID {
			return fmt.Errorf("reached maximum set of serviceIDs available.")
		}
	}
}

// GetWatcher watches for kvstore changes in the given key. Triggers the returned channel
// every time the key path is changed.
func (c *ConsulClient) GetWatcher(key string, timeSleep time.Duration) <-chan []uint32 {
	ch := make(chan []uint32, 100)
	go func() {
		curSeconds := time.Second
		var (
			k   *consulAPI.KVPair
			q   *consulAPI.QueryMeta
			qo  consulAPI.QueryOptions
			err error
		)
		for {
			k, q, err = c.KV().Get(key, nil)
			if err != nil {
				log.Errorf("Unable to retrieve last free Index: %s", err)
			}
			if k != nil {
				break
			} else {
				log.Debugf("Unable to retrieve last free Index, please start some containers with labels.")
			}
			time.Sleep(timeSleep)
		}

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
			go func() {
				ch <- []uint32{}
			}()
		}
	}()
	return ch
}

func (c *ConsulClient) Status() (string, error) {
	return c.Client.Status().Leader()
}

func (c *ConsulClient) DeleteTree(path string) error {
	_, err := c.Client.KV().DeleteTree(path, nil)
	return err
}
