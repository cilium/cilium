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
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/policy"

	client "github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/clientv3/concurrency"
	clientyaml "github.com/coreos/etcd/clientv3/yaml"
	"github.com/coreos/etcd/mvcc/mvccpb"
	"github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"
	ctx "golang.org/x/net/context"
)

const (
	// eAddr is the string representing the key mapping to the value of the
	// address for Etcd.
	eAddr = "etcd.address"
	// eCfg is the string representing the key mapping to the path of the
	// configuration for Etcd.
	eCfg = "etcd.config"
)

var (
	minEVersion, _ = version.NewConstraint(">= 3.1.0")
)

// EtcdOpts is the set of supported options for Etcd configuration.
var EtcdOpts = map[string]bool{
	eAddr: true,
	eCfg:  true,
}

type EtcdClient struct {
	cli         *client.Client
	sessionMU   lock.RWMutex
	session     *concurrency.Session
	lockPathsMU lock.Mutex
	lockPaths   map[string]*lock.Mutex
}

type EtcdLocker struct {
	mutex *concurrency.Mutex
}

func newEtcdClient(config *client.Config, cfgPath string) (KVClient, error) {
	var (
		c   *client.Client
		err error
	)
	if cfgPath != "" {
		config, err = clientyaml.NewConfig(cfgPath)
		if err != nil {
			return nil, err
		}
	}
	if config != nil {
		if config.DialTimeout == 0 {
			config.DialTimeout = 10 * time.Second
		}
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
	ec := &EtcdClient{
		cli:       c,
		session:   s,
		lockPaths: map[string]*lock.Mutex{},
	}
	if err := ec.CheckMinVersion(15 * time.Second); err != nil {
		log.WithError(err).Fatal("Error checking etcd min version")
	}
	// Clean-up old services path
	ec.DeleteTree(common.ServicePathV1)
	go func() {
		for {
			<-ec.session.Done()
			newSession, err := concurrency.NewSession(c)
			if err != nil {
				log.WithError(err).Warn("Error while renewing etcd session")
				time.Sleep(3 * time.Second)
			} else {
				ec.sessionMU.Lock()
				ec.session = newSession
				ec.sessionMU.Unlock()
				log.WithField(fieldSession, newSession).Debug("Renewing session")
				if err := ec.CheckMinVersion(10 * time.Second); err != nil {
					log.WithError(err).Fatal("Error checking etcd min version")
				}
			}
		}
	}()
	return ec, nil
}

func getEPVersion(cli client.Maintenance, etcdEP string, timeout time.Duration) (*version.Version, error) {
	ctxTimeout, cancel := ctx.WithTimeout(ctx.Background(), timeout)
	defer cancel()
	sr, err := cli.Status(ctxTimeout, etcdEP)
	if err != nil {
		return nil, err
	}
	v, err := version.NewVersion(sr.Version)
	if err != nil {
		return nil, fmt.Errorf("error parsing server version %q: %s", sr.Version, err)
	}
	return v, nil
}

// CheckMinVersion checks the minimal version running on etcd cluster. If the
// minimal version running doesn't meet cilium minimal requirements, returns
// an error.
func (e *EtcdClient) CheckMinVersion(timeout time.Duration) error {
	eps := e.cli.Endpoints()
	var errors bool
	for _, ep := range eps {
		v, err := getEPVersion(e.cli.Maintenance, ep, timeout)
		if err != nil {
			log.WithError(err).Debug("Unable to check etcd min version")
			log.WithError(err).WithField(fieldEtcdEndpoint, ep).Warn("Checking version of etcd endpoint")
			errors = true
			continue
		}
		if !minEVersion.Check(v) {
			// FIXME: after we rework the refetching IDs for a connection lost
			// remove this Errorf and replace it with a warning
			return fmt.Errorf("Minimal etcd version not met in %q,"+
				" required: %s, found: %s", ep, minEVersion.String(), v.String())
		}
		log.WithFields(log.Fields{
			fieldEtcdEndpoint: ep,
			"version":         v,
		}).Info("Version of etcd endpoint OK")
	}
	if len(eps) == 0 {
		log.Warn("Minimal etcd version unknown: No etcd endpoints available")
	} else if errors {
		log.WithField("version.min", minEVersion).Warn("Unable to check etcd's cluster version." +
			" Please make sure the minimal etcd version is running on all endpoints")
	}
	return nil
}

func (e *EtcdClient) LockPath(path string) (kvLocker, error) {
	e.sessionMU.RLock()
	mu := concurrency.NewMutex(e.session, path)
	e.sessionMU.RUnlock()

	err := mu.Lock(ctx.Background())
	if err != nil {
		return nil, err
	}

	return &EtcdLocker{mutex: mu}, nil
}

func (e *EtcdLocker) Unlock() error {
	return e.mutex.Unlock(ctx.Background())
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
	kvLocker, err := LockPath(path)
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
	err = e.SetValue(path, firstID)
	if err != nil {
		return err
	}

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
			if err = e.InitializeFreeID(key, firstID); err != nil {
				return 0, err
			}
			attempts--
		case err == nil:
			if err = json.Unmarshal(value, &freeID); err != nil {
				return 0, err
			}
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
		if err := e.InitializeFreeID(key, firstID); err != nil {
			return err
		}
		k, err := e.GetValue(key)
		if err != nil {
			return err
		}
		if k == nil {
			// Something is really wrong
			errMsg := "Unable to set ID because the key is always empty"
			log.Error(errMsg)
			return fmt.Errorf("%s\n", errMsg)
		}
	}
	return e.SetValue(key, maxID)
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
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(*incID), 10))

		locker, err := LockPath(getLockPath(keyPath))
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
			log.WithField(logfields.Identity, *incID).Info("Recycling ID")
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

	acquireFreeID := func(firstID uint32, incID *uint32) (bool, error) {
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(*incID), 10))

		locker, err := LockPath(getLockPath(keyPath))
		if err != nil {
			return false, err
		}
		defer locker.Unlock()

		value, err := e.GetValue(keyPath)
		if err != nil {
			return false, err
		}
		if value == nil {
			return false, setIDtoL3n4Addr(*incID)
		}
		var consulL3n4AddrID types.L3n4AddrID
		if err := json.Unmarshal(value, &consulL3n4AddrID); err != nil {
			return false, err
		}
		if consulL3n4AddrID.ID == 0 {
			log.WithField(logfields.Identity, *incID).Info("Recycling Service ID")
			return false, setIDtoL3n4Addr(*incID)
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

func (e *EtcdClient) DeleteTree(path string) error {
	_, err := e.cli.Delete(ctx.Background(), path, client.WithPrefix())
	return err
}

// Watch starts watching for changes in a prefix
func (e *EtcdClient) Watch(w *Watcher, list bool) {
	lastRev := int64(0)

	for {
		res, err := e.cli.Get(ctx.Background(), w.prefix, client.WithPrefix(),
			client.WithRev(lastRev), client.WithSerializable())
		if err != nil {
			log.WithFields(log.Fields{
				fieldRev:     lastRev,
				fieldPrefix:  w.prefix,
				fieldWatcher: w,
			}).WithError(err).Warn("Unable to list keys before watching")
			continue
		}

		lastRev := res.Header.Revision

		if res.Count > 0 {
			for _, key := range res.Kvs {
				w.Events <- KeyValueEvent{
					Key:   string(key.Key),
					Value: key.Value,
					Typ:   EventTypeCreate,
				}
			}
		}

		// More keys to be read, call Get() again
		if res.More {
			continue
		}

	recreateWatcher:
		lastRev++

		etcdWatch := e.cli.Watch(ctx.Background(), w.prefix,
			client.WithPrefix(), client.WithRev(lastRev))
		for {
			select {
			case <-w.stopWatch:
				return

			case r, ok := <-etcdWatch:
				if !ok {
					goto recreateWatcher
				}

				lastRev = r.Header.Revision

				if err := r.Err(); err != nil {
					log.WithFields(log.Fields{
						fieldRev:     lastRev,
						fieldWatcher: w,
					}).WithError(err).Warn("etcd watcher received error")
					continue
				}

				for _, ev := range r.Events {
					event := KeyValueEvent{
						Key:   string(ev.Kv.Key),
						Value: ev.Kv.Value,
						Typ:   EventTypeModify,
					}

					if ev.Type == client.EventTypeDelete {
						event.Typ = EventTypeDelete
					} else if ev.IsCreate() {
						event.Typ = EventTypeCreate
					}

					w.Events <- event
				}
			}
		}
	}
}

// GetWatcher watches for kvstore changes in the given key. Triggers the returned channel
// every time the key path is changed.
// FIXME This function is highly tightened to the maxFreeID, change name accordingly
func (e *EtcdClient) GetWatcher(key string, timeSleep time.Duration) <-chan []policy.NumericIdentity {
	ch := make(chan []policy.NumericIdentity, 100)
	go func(ch chan []policy.NumericIdentity) {
		curSeconds := time.Second
		lastRevision := int64(0)
		for {
			w := <-e.cli.Watch(ctx.Background(), key, client.WithRev(lastRevision))
			if w.Err() != nil {
				log.WithField(fieldKey, key).Warn("Unable to watch key, retrying...")
				time.Sleep(curSeconds)
				if curSeconds < timeSleep {
					curSeconds += time.Second
				}
				continue
			}
			curSeconds = time.Second
			lastRevision = w.CompactRevision
			freeID := uint32(0)
			maxFreeID := uint32(0)
			for _, event := range w.Events {
				if event.Type != mvccpb.PUT || event.Kv == nil {
					continue
				}
				if err := json.Unmarshal(event.Kv.Value, &freeID); err != nil {
					continue
				}
				if freeID > maxFreeID {
					maxFreeID = freeID
				}
			}
			if maxFreeID != 0 {
				ch <- []policy.NumericIdentity{policy.NumericIdentity(maxFreeID)}
			}
		}
	}(ch)
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

// Get returns value of key
func (e *EtcdClient) Get(key string) ([]byte, error) {
	getR, err := e.cli.Get(ctx.Background(), key)
	if err != nil {
		return nil, err
	}

	if getR.Count == 0 {
		return nil, nil
	}
	return getR.Kvs[0].Value, nil
}

// GetPrefix returns the first key which matches the prefix
func (e *EtcdClient) GetPrefix(prefix string) ([]byte, error) {
	getR, err := e.cli.Get(ctx.Background(), prefix, client.WithPrefix())
	if err != nil {
		return nil, err
	}

	if getR.Count == 0 {
		return nil, nil
	}
	return getR.Kvs[0].Value, nil
}

// Set sets value of key
func (e *EtcdClient) Set(key string, value []byte) error {
	_, err := e.cli.Put(ctx.Background(), key, string(value))
	return err
}

// Delete deletes a key
func (e *EtcdClient) Delete(key string) error {
	_, err := e.cli.Delete(ctx.Background(), key)
	return err
}

func createOpPut(key string, value []byte, lease bool) (*client.Op, error) {
	if lease {
		r, ok := leaseInstance.(*client.LeaseGrantResponse)
		if !ok {
			return nil, fmt.Errorf("argument not a LeaseID")
		}
		op := client.OpPut(key, string(value), client.WithLease(r.ID))
		return &op, nil
	}

	op := client.OpPut(key, string(value))
	return &op, nil
}

// CreateOnly creates a key with the value and will fail if the key already exists
func (e *EtcdClient) CreateOnly(key string, value []byte, lease bool) error {
	req, err := createOpPut(key, value, lease)
	if err != nil {
		return err
	}

	cond := client.Compare(client.Version(key), "=", 0)
	txnresp, err := e.cli.Txn(ctx.TODO()).If(cond).Then(*req).Commit()
	if err != nil {
		return err
	}

	if txnresp.Succeeded == false {
		return fmt.Errorf("create was unsuccessful")
	}

	return nil
}

// ListPrefix returns a map of matching keys
func (e *EtcdClient) ListPrefix(prefix string) (KeyValuePairs, error) {
	getR, err := e.cli.Get(ctx.Background(), prefix, client.WithPrefix())
	if err != nil {
		return nil, err
	}

	pairs := KeyValuePairs{}
	for i := int64(0); i < getR.Count; i++ {
		pairs[string(getR.Kvs[i].Key)] = getR.Kvs[i].Value

	}

	return pairs, nil
}

// CreateLease creates a new lease with the given ttl
func (e *EtcdClient) CreateLease(ttl time.Duration) (interface{}, error) {
	return e.cli.Grant(ctx.TODO(), int64(ttl.Seconds()))
}

// KeepAlive keeps a lease created with CreateLease alive
func (e *EtcdClient) KeepAlive(lease interface{}) error {
	r, ok := lease.(*client.LeaseGrantResponse)
	if !ok {
		return fmt.Errorf("argument not a LeaseID")
	}

	_, err := e.cli.KeepAliveOnce(ctx.TODO(), r.ID)
	return err
}

// DeleteLease deletes a lease
func (e *EtcdClient) DeleteLease(lease interface{}) error {
	r, ok := lease.(*client.LeaseGrantResponse)
	if !ok {
		return fmt.Errorf("argument not a LeaseID")
	}

	_, err := e.cli.Revoke(ctx.TODO(), r.ID)
	return err
}

// Close closes the kvstore client
func (e *EtcdClient) Close() {
	e.cli.Close()
}
