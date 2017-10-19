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
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/policy"

	consulAPI "github.com/hashicorp/consul/api"
	log "github.com/sirupsen/logrus"
)

const (
	// cAddr is the string representing the key mapping to the value of the
	// address for Consul.
	cAddr = "consul.address"

	// MaxLockRetries is the number of retries attempted when acquiring a lock
	MaxLockRetries = 10
)

// ConsulOpts is the set of supported options for Consul configuration.
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
		log.WithError(err).Fatal("Unable to contact consul server")
	}
	cc := &ConsulClient{c}
	// Clean-up old services path
	cc.DeleteTree(common.ServicePathV1)

	log.Info("Consul client ready")
	return cc, nil
}

func (c *ConsulClient) LockPath(path string) (kvLocker, error) {
	retries := 0

	opts := &consulAPI.LockOptions{
		Key: getLockPath(path),
	}
	lockKey, err := c.LockOpts(opts)
	if err != nil {
		return nil, err
	}

retry:
	retries++
	if retries > MaxLockRetries {
		return nil, fmt.Errorf("maximum retries (%d) reached", MaxLockRetries)
	}

	ch, err := lockKey.Lock(nil)
	if ch == nil && err == nil {
		trace("Acquiring lock timed out", nil, log.Fields{fieldKey: path})
		goto retry
	}

	if err != nil {
		return nil, err
	}

	return lockKey, nil
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
	lockPair := &consulAPI.KVPair{Key: getLockPath(path), Session: session}
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
	_, err = c.KV().Put(p, nil)
	if err != nil {
		return err
	}

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
			log.Error(errMsg)
			return 0, fmt.Errorf(errMsg)
		}
	}
	var freeID uint32
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
			log.Error(errMsg)
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
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(*incID), 10))

		lockPair := &consulAPI.KVPair{Key: getLockPath(keyPath), Session: session}
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
				log.WithField(logfields.Identity, *incID).Info("Recycling ID")
				return false, setID2Label(*incID)
			}
		}

		*incID++
		if *incID > common.MaxSetOfLabels {
			*incID = policy.MinimalNumericIdentity.Uint32()
		}
		if firstID == *incID {
			return false, fmt.Errorf("reached maximum set of labels available")
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
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(*incID), 10))

		lockPair := &consulAPI.KVPair{Key: getLockPath(keyPath), Session: session}
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
				log.WithField(logfields.Identity, baseID).Info("Recycling Service ID")
				return false, setIDtoL3n4Addr(*incID)
			}
		}

		*incID++
		if *incID > common.MaxSetOfServiceID {
			*incID = common.FirstFreeServiceID
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

// Watch starts watching for changes in a prefix
func (c *ConsulClient) Watch(w *Watcher, list bool) {
	// Last known state of all KVPairs matching the prefix
	localState := map[string]consulAPI.KVPair{}
	nextIndex := uint64(0)

	// block Get() calls for 5 seconds maximum
	qo := consulAPI.QueryOptions{
		WaitTime: 5 * time.Second,
	}

	for {
		// Initialize sleep time to a millisecond as we don't
		// want to sleep in between successful watch cycles
		sleepTime := 1 * time.Millisecond

		qo.WaitIndex = nextIndex
		pairs, q, err := c.KV().List(w.prefix, &qo)
		if err != nil {
			// in case of error, sleep for 15 seconds before retrying
			sleepTime = 15 * time.Second
			log.WithFields(log.Fields{
				fieldWatcher:      w,
				fieldListAndWatch: list,
			}).WithError(err).Debug("Consul watcher failed, will retry")
		}

		if q != nil {
			nextIndex = q.LastIndex
		}

		// WaitIndex == 0 means that this was the first ever
		// List() and there is no change, trigger a follow-up
		// List() with updated WaitIndex immediately
		if qo.WaitIndex == 0 && !list {
			continue
		}

		// timeout while watching for changes, re-schedule
		if q == nil || q.LastIndex == qo.WaitIndex {
			continue
		}

		for _, newPair := range pairs {
			oldPair, ok := localState[newPair.Key]

			// Keys reported for the first time must be new
			if !ok {
				if newPair.CreateIndex == newPair.ModifyIndex {
					w.Events <- KeyValueEvent{
						Typ:   EventTypeCreate,
						Key:   newPair.Key,
						Value: newPair.Value,
					}
				} else {
					log.Warnf("consul: Previously unknown key %s received with CreateIndex(%d) != ModifyIndex(%d); ignoring update",
						newPair.Key, newPair.CreateIndex, newPair.ModifyIndex)
				}
			} else if oldPair.ModifyIndex != newPair.ModifyIndex {
				w.Events <- KeyValueEvent{
					Typ:   EventTypeModify,
					Key:   newPair.Key,
					Value: newPair.Value,
				}
			}

			delete(localState, newPair.Key)
		}

		for k, deletedPair := range localState {
			w.Events <- KeyValueEvent{
				Typ:   EventTypeDelete,
				Key:   deletedPair.Key,
				Value: deletedPair.Value,
			}
			delete(localState, k)
		}

		for _, newPair := range pairs {
			localState[newPair.Key] = *newPair

		}

		select {
		case <-time.After(sleepTime):
		case <-w.stopWatch:
			return
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
				log.WithError(err).Error("Unable to retrieve last free Index")
			}
			if k == nil || q == nil {
				log.Warn("Unable to retrieve last free Index, please start some containers with labels")
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

// Set sets value of key
func (c *ConsulClient) Set(key string, value []byte) error {
	_, err := c.KV().Put(&consulAPI.KVPair{Key: key, Value: value}, nil)
	return err
}

// Delete deletes a key
func (c *ConsulClient) Delete(key string) error {
	_, err := c.KV().Delete(key, nil)
	return err
}

// Get returns value of key
func (c *ConsulClient) Get(key string) ([]byte, error) {
	pair, _, err := c.KV().Get(key, nil)
	if err != nil {
		return nil, err
	}
	if pair == nil {
		return nil, nil
	}
	return pair.Value, nil
}

// GetPrefix returns the first key which matches the prefix
func (c *ConsulClient) GetPrefix(prefix string) ([]byte, error) {
	pairs, _, err := c.KV().List(prefix, nil)
	if err != nil {
		return nil, err
	}

	if len(pairs) == 0 {
		return nil, nil
	}

	return pairs[0].Value, nil
}

// CreateOnly creates a key with the value and will fail if the key already exists
func (c *ConsulClient) CreateOnly(key string, value []byte, lease bool) error {
	k := &consulAPI.KVPair{
		Key:         key,
		Value:       value,
		CreateIndex: 0,
	}

	if lease {
		id, ok := leaseInstance.(string)
		if !ok {
			return fmt.Errorf("argument not a LeaseID")
		}

		k.Session = id
	}

	success, _, err := c.KV().CAS(k, nil)
	if err != nil {
		return fmt.Errorf("unable to compare-and-swap: %s", err)
	}
	if !success {
		return fmt.Errorf("compare-and-swap unsuccessful")
	}

	return nil
}

// ListPrefix returns a map of matching keys
func (c *ConsulClient) ListPrefix(prefix string) (KeyValuePairs, error) {
	pairs, _, err := c.KV().List(prefix, nil)
	if err != nil {
		return nil, err
	}

	p := KeyValuePairs(make(map[string][]byte, len(pairs)))
	for i := 0; i < len(pairs); i++ {
		p[pairs[i].Key] = pairs[i].Value
	}

	return p, nil
}

// CreateLease creates a new lease with the given ttl
func (c *ConsulClient) CreateLease(ttl time.Duration) (interface{}, error) {
	entry := &consulAPI.SessionEntry{
		TTL:      fmt.Sprintf("%ds", int(ttl.Seconds())),
		Behavior: consulAPI.SessionBehaviorDelete,
	}

	id, _, err := c.Session().Create(entry, nil)
	return id, err
}

// KeepAlive keeps a lease created with CreateLease alive
func (c *ConsulClient) KeepAlive(lease interface{}) error {
	id, ok := lease.(string)
	if !ok {
		return fmt.Errorf("argument not a LeaseID")
	}

	_, _, err := c.Session().Renew(id, nil)
	return err
}

// DeleteLease deletes a lease
func (c *ConsulClient) DeleteLease(lease interface{}) error {
	id, ok := lease.(string)
	if !ok {
		return fmt.Errorf("argument not a LeaseID")
	}

	_, err := c.Session().Destroy(id, nil)
	return err
}

// Close closes the kvstore client
func (c *ConsulClient) Close() {
}
