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
	"fmt"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/policy"

	client "github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/clientv3/concurrency"
	"github.com/coreos/etcd/mvcc/mvccpb"
	ctx "golang.org/x/net/context"
)

type EtcdClient struct {
	cli         *client.Client
	sessionMU   sync.RWMutex
	session     *concurrency.Session
	lockPathsMU sync.Mutex
	lockPaths   map[string]*sync.Mutex
}

type EtcdLocker struct {
	mutex     *concurrency.Mutex
	localLock *sync.Mutex
	path      string
}

func NewEtcdClient(config *client.Config, cfgPath string) (KVClient, error) {
	var (
		c   *client.Client
		err error
	)
	if cfgPath != "" {
		c, err = client.NewFromConfigFile(cfgPath)
	} else if config != nil {
		c, err = client.New(*config)
	} else {
		err = fmt.Errorf("empty configuration provided")
	}
	if err != nil {
		return nil, err
	}
	log.Info("Waiting for etcd client to be ready...")
	s, err := concurrency.NewSession(c)
	if err != nil {
		return nil, fmt.Errorf("Unable to contact etcd: %s", err)
	}
	log.Info("Etcd client ready")
	ec := &EtcdClient{
		cli:       c,
		session:   s,
		lockPaths: map[string]*sync.Mutex{},
	}
	go func() {
		for {
			<-ec.session.Done()
			newSession, err := concurrency.NewSession(c)
			if err != nil {
				log.Errorf("Error while renewing etcd session %s", err)
				time.Sleep(10 * time.Second)
			} else {
				ec.sessionMU.Lock()
				ec.session = newSession
				ec.sessionMU.Unlock()
				log.Debugf("Renewing etcd session")
			}
		}
	}()
	return ec, nil
}

func (e *EtcdClient) LockPath(path string) (KVLocker, error) {
	e.lockPathsMU.Lock()
	if e.lockPaths[path] == nil {
		e.lockPaths[path] = &sync.Mutex{}
	}
	e.lockPathsMU.Unlock()

	log.Debugf("Locking path %s", path)
	// First we lock the local lock for this path
	e.lockPaths[path].Lock()
	e.sessionMU.RLock()
	mu := concurrency.NewMutex(e.session, path)
	e.sessionMU.RUnlock()
	// Then we lock the global lock
	err := mu.Lock(ctx.Background())
	if err != nil {
		e.lockPaths[path].Unlock()
		return nil, fmt.Errorf("Error while locking path %s: %s", path, err)
	}
	log.Debugf("Locked path %s", path)
	return &EtcdLocker{mutex: mu, path: path, localLock: e.lockPaths[path]}, nil
}

func (e *EtcdLocker) Unlock() error {
	err := e.mutex.Unlock(ctx.Background())
	e.localLock.Unlock()
	if err == nil {
		log.Debugf("Unlocked path %s", e.path)
	}
	return err
}

func (e *EtcdClient) GetValue(k string) (json.RawMessage, error) {
	gresp, err := e.cli.Get(ctx.Background(), k)
	if err != nil {
		return nil, err
	}
	if gresp.Count == 0 {
		return nil, nil
	}
	return json.RawMessage(gresp.Kvs[0].Value), nil
}

func (e *EtcdClient) SetValue(k string, v interface{}) error {
	vByte, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = e.cli.Put(ctx.Background(), k, string(vByte))
	return err
}

func (e *EtcdClient) InitializeFreeID(path string, firstID uint32) error {
	kvLocker, err := e.LockPath(path)
	if err != nil {
		return err
	}
	defer kvLocker.Unlock()

	log.Debug("Trying to acquire free ID...")
	k, err := e.GetValue(path)
	if err != nil {
		return err
	}
	if k != nil {
		// FreeID already set
		return nil
	}
	log.Info("Trying to put free ID...")
	err = e.SetValue(path, firstID)
	if err != nil {
		return err
	}
	log.Info("Free ID for path %s successfully initialized", path)

	return nil
}

func (e *EtcdClient) GetMaxID(key string, firstID uint32) (uint32, error) {
	var (
		attempts = 3
		value    json.RawMessage
		err      error
		freeID   uint32
	)
	for {
		switch value, err = e.GetValue(key); {
		case attempts == 0:
			err = fmt.Errorf("Unable to retrieve last free ID because key is always empty")
			log.Error(err)
			fallthrough
		case err != nil:
			return 0, err
		case value == nil:
			log.Infof("Empty FreeID, setting it up with default value %d", firstID)
			if err := e.InitializeFreeID(key, firstID); err != nil {
				return 0, err
			}
			attempts--
		case err == nil:
			if err := json.Unmarshal(value, &freeID); err != nil {
				return 0, err
			}
			log.Debugf("Retrieving max free ID %d", freeID)
			return freeID, nil
		}
	}
}

func (e *EtcdClient) SetMaxID(key string, firstID, maxID uint32) error {
	value, err := e.GetValue(key)
	if err != nil {
		return err
	}
	if value == nil {
		// FreeID is empty? We should set it out!
		log.Infof("Empty FreeID, setting it up with default value %d", firstID)
		if err := e.InitializeFreeID(key, firstID); err != nil {
			return err
		}
		k, err := e.GetValue(key)
		if err != nil {
			return err
		}
		if k == nil {
			// Something is really wrong
			errMsg := "Unable to setting ID because the key is always empty\n"
			log.Errorf(errMsg)
			return fmt.Errorf(errMsg)
		}
	}
	return e.SetValue(key, maxID)
}

func (e *EtcdClient) updateSecLabelIDRef(id policy.Identity) error {
	key := path.Join(common.LabelIDKeyPath, strconv.FormatUint(uint64(id.ID), 10))
	return e.SetValue(key, id)
}

func (e *EtcdClient) setMaxLabelID(maxID uint32) error {
	return e.SetMaxID(common.LastFreeLabelIDKeyPath, policy.MinimalNumericIdentity.Uint32(), maxID)
}

// GASNewSecLabelID gets the next available LabelID and sets it in id. After
// assigning the LabelID to id it sets the LabelID + 1 in
// common.LastFreeLabelIDKeyPath path.
func (e *EtcdClient) GASNewSecLabelID(basePath string, baseID uint32, pI *policy.Identity) error {
	setID2Label := func(new_id uint32) error {
		pI.ID = policy.NumericIdentity(new_id)
		keyPath := path.Join(basePath, pI.ID.StringID())
		if err := e.SetValue(keyPath, pI); err != nil {
			return err
		}
		return e.setMaxLabelID(new_id + 1)
	}

	acquireFreeID := func(firstID uint32, incID *uint32) (bool, error) {
		log.Debugf("Trying to acquire a new free ID %d", *incID)
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(*incID), 10))

		locker, err := e.LockPath(GetLockPath(keyPath))
		if err != nil {
			return false, err
		}
		defer locker.Unlock()

		value, err := e.GetValue(keyPath)
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

func (e *EtcdClient) setMaxL3n4AddrID(maxID uint32) error {
	return e.SetMaxID(common.LastFreeServiceIDKeyPath, common.FirstFreeServiceID, maxID)
}

// GASNewL3n4AddrID gets the next available ServiceID and sets it in lAddrID. After
// assigning the ServiceID to lAddrID it sets the ServiceID + 1 in
// common.LastFreeServiceIDKeyPath path.
func (e *EtcdClient) GASNewL3n4AddrID(basePath string, baseID uint32, lAddrID *types.L3n4AddrID) error {
	setIDtoL3n4Addr := func(id uint32) error {
		lAddrID.ID = types.ServiceID(id)
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(lAddrID.ID), 10))
		if err := e.SetValue(keyPath, lAddrID); err != nil {
			return err
		}
		return e.setMaxL3n4AddrID(id + 1)
	}

	acquireFreeID := func(firstID uint32, incID *uint32) error {
		log.Debugf("Trying to acquire a new free ID %d", *incID)
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(*incID), 10))

		locker, err := e.LockPath(GetLockPath(keyPath))
		if err != nil {
			return err
		}
		defer locker.Unlock()

		value, err := e.GetValue(keyPath)
		if err != nil {
			return err
		}
		if value == nil {
			return setIDtoL3n4Addr(*incID)
		}
		var consulL3n4AddrID types.L3n4AddrID
		if err := json.Unmarshal(value, &consulL3n4AddrID); err != nil {
			return err
		}
		if consulL3n4AddrID.ID == 0 {
			log.Infof("Recycling Service ID %d", *incID)
			return setIDtoL3n4Addr(*incID)
		}

		*incID++
		if *incID > common.MaxSetOfServiceID {
			*incID = common.FirstFreeServiceID
		}
		if firstID == *incID {
			return fmt.Errorf("reached maximum set of serviceIDs available.")
		}
		return nil
	}

	var err error
	beginning := baseID
	for {
		if err = acquireFreeID(beginning, &baseID); err != nil {
			return err
		} else if beginning == baseID {
			return nil
		}
	}
}

func (e *EtcdClient) DeleteTree(path string) error {
	_, err := e.cli.Delete(ctx.Background(), path, client.WithPrefix())
	return err
}

// GetWatcher watches for kvstore changes in the given key. Triggers the returned channel
// every time the key path is changed.
// FIXME This function is highly tightened to the maxFreeID, change name accordingly
func (e *EtcdClient) GetWatcher(key string, timeSleep time.Duration) <-chan []policy.NumericIdentity {
	ch := make(chan []policy.NumericIdentity, 100)
	go func() {
		curSeconds := time.Second
		lastRevision := int64(0)
		for {
			w := <-e.cli.Watch(ctx.Background(), key, client.WithRev(lastRevision))
			if w.Err() != nil {
				log.Warning("Unable to watch key %s, retrying...", key)
				time.Sleep(curSeconds)
				if curSeconds < timeSleep {
					curSeconds += time.Second
				}
				continue
			}
			curSeconds = time.Second
			lastRevision = w.CompactRevision
			go func() {
				freeID := uint32(0)
				maxFreeID := uint32(0)
				for _, event := range w.Events {
					if event.Type != mvccpb.PUT ||
						event.Kv == nil {
						continue
					}
					if err := json.Unmarshal(event.Kv.Value, &freeID); err != nil {
						continue
					}
					if freeID > maxFreeID {
						maxFreeID = freeID
					}
				}
				ch <- []policy.NumericIdentity{policy.NumericIdentity(maxFreeID)}
			}()
		}
	}()
	return ch
}

func (e *EtcdClient) Status() (string, error) {
	eps := e.cli.Endpoints()
	var err1 error
	for i, ep := range eps {
		if sr, err := e.cli.Status(ctx.Background(), ep); err != nil {
			err1 = err
		} else if sr.Header.MemberId == sr.Leader {
			eps[i] = fmt.Sprintf("%s - (Leader) %s", ep, sr.Version)
		} else {
			eps[i] = fmt.Sprintf("%s - %s", ep, sr.Version)
		}
	}
	return "Etcd: " + strings.Join(eps, "; "), err1
}
