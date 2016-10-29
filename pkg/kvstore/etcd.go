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
	"sync"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"

	client "github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/clientv3/concurrency"
	ctx "golang.org/x/net/context"
)

type EtcdClient struct {
	cli         *client.Client
	session     *concurrency.Session
	sessionMU   sync.RWMutex
	lockPaths   map[string]*sync.Mutex
	lockPathsMU sync.Mutex
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
			err = fmt.Errorf("Unable to retreive last free ID because key is always empty")
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

func (e *EtcdClient) updateSecLabelIDRef(secCtxLabels types.SecCtxLabel) error {
	key := path.Join(common.LabelIDKeyPath, strconv.FormatUint(uint64(secCtxLabels.ID), 10))
	return e.SetValue(key, secCtxLabels)
}

func (e *EtcdClient) setMaxLabelID(maxID uint32) error {
	return e.SetMaxID(common.LastFreeLabelIDKeyPath, common.FirstFreeLabelID, maxID)
}

// GASNewSecLabelID gets the next available LabelID and sets it in secCtxLabels. After
// assigning the LabelID to secCtxLabels it sets the LabelID + 1 in
// common.LastFreeLabelIDKeyPath path.
func (e *EtcdClient) GASNewSecLabelID(basePath string, baseID uint32, secCtxLabels *types.SecCtxLabel) error {
	setID2Label := func(id uint32) error {
		secCtxLabels.ID = id
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(secCtxLabels.ID), 10))
		if err := e.SetValue(keyPath, secCtxLabels); err != nil {
			return err
		}
		return e.setMaxLabelID(id + 1)
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
		var consulLabels types.SecCtxLabel
		if err := json.Unmarshal(value, &consulLabels); err != nil {
			return false, err
		}
		if consulLabels.RefCount() == 0 {
			log.Infof("Recycling ID %d", *incID)
			return false, setID2Label(*incID)
		}

		*incID++
		if *incID > common.MaxSetOfLabels {
			*incID = common.FirstFreeLabelID
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

func (e *EtcdClient) setMaxServiceL4ID(maxID uint32) error {
	return e.SetMaxID(common.LastFreeServiceIDKeyPath, common.FirstFreeServiceID, maxID)
}

// GASNewServiceL4ID gets the next available ServiceID and sets it in sl4. After assigning
// the ServiceID to sl4 it sets the ServiceID + 1 in common.LastFreeServiceIDKeyPath path.
func (e *EtcdClient) GASNewServiceL4ID(basePath string, baseID uint32, sl4 *types.L3n4AddrID) error {
	setID2ServiceL4 := func(id uint32) error {
		sl4.ID = types.ServiceID(id)
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(sl4.ID), 10))
		if err := e.SetValue(keyPath, sl4); err != nil {
			return err
		}
		return e.setMaxServiceL4ID(id + 1)
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
			return setID2ServiceL4(*incID)
		}
		var consulServiceL4ID types.L3n4AddrID
		if err := json.Unmarshal(value, &consulServiceL4ID); err != nil {
			return err
		}
		if consulServiceL4ID.ID == 0 {
			log.Infof("Recycling Service ID %d", *incID)
			return setID2ServiceL4(*incID)
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
func (e *EtcdClient) GetWatcher(key string, timeSleep time.Duration) <-chan []uint32 {
	ch := make(chan []uint32, 100)
	go func() {
		curSeconds := time.Second
		for {
			w := <-e.cli.Watch(ctx.Background(), key)
			if w.Err() != nil {
				log.Warning("Unable to watch key %s, retrying...", key)
				time.Sleep(curSeconds)
				if curSeconds < timeSleep {
					curSeconds += time.Second
				}
				continue
			}
			curSeconds = time.Second
			go func() {
				ch <- []uint32{}
			}()
		}
	}()
	return ch
}

func (e *EtcdClient) Status() (string, error) {
	c, cancel := ctx.WithTimeout(ctx.Background(), 2*time.Second)
	defer cancel()
	_, err := e.cli.MemberList(c)
	if err == nil {
		return "Etcd connected", nil
	}
	return "", fmt.Errorf("Etcd client not connected")
}
