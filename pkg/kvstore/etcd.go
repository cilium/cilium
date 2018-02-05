// Copyright 2016-2018 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/logging/logfields"

	client "github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/clientv3/concurrency"
	clientyaml "github.com/coreos/etcd/clientv3/yaml"
	"github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
	ctx "golang.org/x/net/context"
)

const (
	etcdName = "etcd"

	addrOption = "etcd.address"
	cfgOption  = "etcd.config"

	// sessionCreateRetryInterval is the retry interval when a session
	// can't be created
	sessionCreateRetryInterval = 3 * time.Second
)

type etcdModule struct {
	opts   backendOptions
	config *client.Config
}

var (
	minRequiredVersion, _ = version.NewConstraint(">= 3.1.0")

	// etcdDummyAddress can be overwritten from test invokers using ldflags
	etcdDummyAddress = "http://127.0.0.1:4002"

	etcdInstance = &etcdModule{
		opts: backendOptions{
			addrOption: &backendOption{
				description: "Addresses of etcd cluster",
			},
			cfgOption: &backendOption{
				description: "Path to etcd configuration file",
			},
		},
	}
)

func (e *etcdModule) getName() string {
	return etcdName
}

func (e *etcdModule) setConfigDummy() {
	e.config = &client.Config{}
	e.config.Endpoints = []string{etcdDummyAddress}
}

func (e *etcdModule) setConfig(opts map[string]string) error {
	return setOpts(opts, e.opts)
}

func (e *etcdModule) getConfig() map[string]string {
	return getOpts(e.opts)
}

func (e *etcdModule) newClient() (BackendOperations, error) {
	endpointsOpt, endpointsSet := e.opts[addrOption]
	configPathOpt, configSet := e.opts[cfgOption]
	configPath := ""

	if e.config == nil {
		if !endpointsSet && !configSet {
			return nil, fmt.Errorf("invalid etcd configuration, %s or %s must be specified", cfgOption, addrOption)
		}

		e.config = &client.Config{}

		if endpointsSet {
			e.config.Endpoints = []string{endpointsOpt.value}
		}

		if configSet {
			configPath = configPathOpt.value
		}
	}

	return newEtcdClient(e.config, configPath)
}

func init() {
	// register etcd module for use
	registerBackend(etcdName, etcdInstance)
}

type etcdClient struct {
	// protects all members of etcdClient from concurrent access
	lock.RWMutex

	client      *client.Client
	session     *concurrency.Session
	lockPathsMU lock.Mutex
	lockPaths   map[string]*lock.Mutex
}

type etcdMutex struct {
	mutex *concurrency.Mutex
}

func (e *etcdMutex) Unlock() error {
	return e.mutex.Unlock(ctx.Background())
}

func (e *etcdClient) renewSessionRoutine() {
	for {
		<-e.session.Done()

		newSession, err := concurrency.NewSession(e.client)
		if err != nil {
			log.WithError(err).Warn("Error while renewing etcd session")
			time.Sleep(sessionCreateRetryInterval)
		} else {
			e.Lock()
			e.session = newSession
			e.Unlock()

			log.WithField(fieldSession, newSession).Debug("Renewing etcd session")

			if err := e.checkMinVersion(10 * time.Second); err != nil {
				log.WithError(err).Fatal("Error checking etcd min version")
			}
		}
	}
}

func newEtcdClient(config *client.Config, cfgPath string) (BackendOperations, error) {
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
	ec := &etcdClient{
		client:    c,
		session:   s,
		lockPaths: map[string]*lock.Mutex{},
	}
	if err := ec.checkMinVersion(15 * time.Second); err != nil {
		log.WithError(err).Fatal("Error checking etcd min version")
	}

	go ec.renewSessionRoutine()

	return ec, nil
}

func getEPVersion(c client.Maintenance, etcdEP string, timeout time.Duration) (*version.Version, error) {
	ctxTimeout, cancel := ctx.WithTimeout(ctx.Background(), timeout)
	defer cancel()
	sr, err := c.Status(ctxTimeout, etcdEP)
	if err != nil {
		return nil, err
	}
	v, err := version.NewVersion(sr.Version)
	if err != nil {
		return nil, fmt.Errorf("error parsing server version %q: %s", sr.Version, err)
	}
	return v, nil
}

// checkMinVersion checks the minimal version running on etcd cluster. If the
// minimal version running doesn't meet cilium minimal requirements, returns
// an error.
func (e *etcdClient) checkMinVersion(timeout time.Duration) error {
	eps := e.client.Endpoints()
	var errors bool
	for _, ep := range eps {
		v, err := getEPVersion(e.client.Maintenance, ep, timeout)
		if err != nil {
			log.WithError(err).Debug("Unable to check etcd min version")
			log.WithError(err).WithField(fieldEtcdEndpoint, ep).Warn("Checking version of etcd endpoint")
			errors = true
			continue
		}
		if !minRequiredVersion.Check(v) {
			// FIXME: after we rework the refetching IDs for a connection lost
			// remove this Errorf and replace it with a warning
			return fmt.Errorf("Minimal etcd version not met in %q,"+
				" required: %s, found: %s", ep, minRequiredVersion.String(), v.String())
		}
		log.WithFields(logrus.Fields{
			fieldEtcdEndpoint: ep,
			"version":         v,
		}).Info("Version of etcd endpoint OK")
	}
	if len(eps) == 0 {
		log.Warn("Minimal etcd version unknown: No etcd endpoints available")
	} else if errors {
		log.WithField("version.min", minRequiredVersion).Warn("Unable to check etcd's cluster version." +
			" Please make sure the minimal etcd version is running on all endpoints")
	}
	return nil
}

func (e *etcdClient) LockPath(path string) (kvLocker, error) {
	e.RLock()
	mu := concurrency.NewMutex(e.session, path)
	e.RUnlock()

	err := mu.Lock(ctx.Background())
	if err != nil {
		return nil, err
	}

	return &etcdMutex{mutex: mu}, nil
}

// FIXME: Obsolete, remove
func (e *etcdClient) GetValue(k string) (json.RawMessage, error) {
	gresp, err := e.client.Get(ctx.Background(), k)
	if err != nil {
		return nil, err
	}
	if gresp.Count == 0 {
		return nil, nil
	}
	return json.RawMessage(gresp.Kvs[0].Value), nil
}

// FIXME: Obsolete, remove
func (e *etcdClient) SetValue(k string, v interface{}) error {
	vByte, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = e.client.Put(ctx.Background(), k, string(vByte))
	return err
}

// FIXME: Obsolete, remove
func (e *etcdClient) InitializeFreeID(path string, firstID uint32) error {
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

// FIXME: Obsolete, remove
func (e *etcdClient) GetMaxID(key string, firstID uint32) (uint32, error) {
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

// FIXME: Obsolete, remove
func (e *etcdClient) SetMaxID(key string, firstID, maxID uint32) error {
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

// FIXME: Obsolete, remove
func (e *etcdClient) setMaxL3n4AddrID(maxID uint32) error {
	return e.SetMaxID(common.LastFreeServiceIDKeyPath, common.FirstFreeServiceID, maxID)
}

// GASNewL3n4AddrID gets the next available ServiceID and sets it in lAddrID. After
// assigning the ServiceID to lAddrID it sets the ServiceID + 1 in
// common.LastFreeServiceIDKeyPath path.
//
// FIXME: Obsolete, remove
func (e *etcdClient) GASNewL3n4AddrID(basePath string, baseID uint32, lAddrID *types.L3n4AddrID) error {
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

		locker, err := e.LockPath(getLockPath(keyPath))
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

func (e *etcdClient) DeletePrefix(path string) error {
	_, err := e.client.Delete(ctx.Background(), path, client.WithPrefix())
	return err
}

// Watch starts watching for changes in a prefix
func (e *etcdClient) Watch(w *Watcher) {
	lastRev := int64(0)

	for {
		res, err := e.client.Get(ctx.Background(), w.prefix, client.WithPrefix(),
			client.WithRev(lastRev), client.WithSerializable())
		if err != nil {
			log.WithFields(logrus.Fields{
				fieldRev:     lastRev,
				fieldPrefix:  w.prefix,
				fieldWatcher: w,
			}).WithError(err).Warn("Unable to list keys before starting watcher")
			continue
		}

		lastRev := res.Header.Revision

		log.WithFields(logrus.Fields{
			fieldRev:     lastRev,
			fieldWatcher: w,
		}).Debugf("List response from etcd len=%d: %+v", res.Count, res)

		if res.Count > 0 {
			for _, key := range res.Kvs {
				log.WithFields(logrus.Fields{
					fieldRev:     lastRev,
					fieldWatcher: w,
				}).Debugf("Emiting list result as %v event for %s=%v", EventTypeCreate, key.Key, key.Value)
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

		w.Events <- KeyValueEvent{Typ: EventTypeListDone}

	recreateWatcher:
		lastRev++

		log.WithFields(logrus.Fields{
			fieldRev:     lastRev,
			fieldWatcher: w,
		}).Debugf("Starting to watch %s", w.prefix)
		etcdWatch := e.client.Watch(ctx.Background(), w.prefix,
			client.WithPrefix(), client.WithRev(lastRev))
		for {
			select {
			case <-w.stopWatch:
				close(w.Events)
				return

			case r, ok := <-etcdWatch:
				if !ok {
					goto recreateWatcher
				}

				lastRev = r.Header.Revision

				if err := r.Err(); err != nil {
					log.WithFields(logrus.Fields{
						fieldRev:     lastRev,
						fieldWatcher: w,
					}).WithError(err).Warningf("etcd watcher received error")
					continue
				}

				log.WithFields(logrus.Fields{
					fieldRev:     lastRev,
					fieldWatcher: w,
				}).Debugf("Received event from etcd: %+v", r)

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

					log.WithFields(logrus.Fields{
						fieldRev:     lastRev,
						fieldWatcher: w,
					}).Debugf("Emiting %v event for %s=%v", event.Typ, event.Key, event.Value)

					w.Events <- event
				}
			}
		}
	}
}

func (e *etcdClient) Status() (string, error) {
	eps := e.client.Endpoints()
	var err1 error
	for i, ep := range eps {
		if sr, err := e.client.Status(ctx.Background(), ep); err != nil {
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
func (e *etcdClient) Get(key string) ([]byte, error) {
	getR, err := e.client.Get(ctx.Background(), key)
	if err != nil {
		return nil, err
	}

	if getR.Count == 0 {
		return nil, nil
	}
	return getR.Kvs[0].Value, nil
}

// GetPrefix returns the first key which matches the prefix
func (e *etcdClient) GetPrefix(prefix string) ([]byte, error) {
	getR, err := e.client.Get(ctx.Background(), prefix, client.WithPrefix())
	if err != nil {
		return nil, err
	}

	if getR.Count == 0 {
		return nil, nil
	}
	return getR.Kvs[0].Value, nil
}

// Set sets value of key
func (e *etcdClient) Set(key string, value []byte) error {
	_, err := e.client.Put(ctx.Background(), key, string(value))
	return err
}

// Delete deletes a key
func (e *etcdClient) Delete(key string) error {
	_, err := e.client.Delete(ctx.Background(), key)
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

// Update creates or updates a key
func (e *etcdClient) Update(key string, value []byte, lease bool) error {
	if lease {
		r, ok := leaseInstance.(*client.LeaseGrantResponse)
		if !ok {
			return fmt.Errorf("argument not a LeaseID")
		}
		_, err := e.client.Put(ctx.Background(), key, string(value), client.WithLease(r.ID))
		return err
	}

	_, err := e.client.Put(ctx.Background(), key, string(value))
	return err
}

// CreateOnly creates a key with the value and will fail if the key already exists
func (e *etcdClient) CreateOnly(key string, value []byte, lease bool) error {
	req, err := createOpPut(key, value, lease)
	if err != nil {
		return err
	}

	cond := client.Compare(client.Version(key), "=", 0)
	txnresp, err := e.client.Txn(ctx.TODO()).If(cond).Then(*req).Commit()
	if err != nil {
		return err
	}

	if txnresp.Succeeded == false {
		return fmt.Errorf("create was unsuccessful")
	}

	return nil
}

// CreateIfExists creates a key with the value only if key condKey exists
func (e *etcdClient) CreateIfExists(condKey, key string, value []byte, lease bool) error {
	req, err := createOpPut(key, value, lease)
	if err != nil {
		return err
	}

	cond := client.Compare(client.Version(condKey), "!=", 0)
	txnresp, err := e.client.Txn(ctx.TODO()).If(cond).Then(*req).Commit()
	if err != nil {
		return err
	}

	if txnresp.Succeeded == false {
		return fmt.Errorf("create was unsuccessful")
	}

	return nil
}

// FIXME: When we rebase to etcd 3.3
//
// DeleteOnZeroCount deletes the key if no matching keys for prefix exist
//func (e *etcdClient) DeleteOnZeroCount(key, prefix string) error {
//	txnresp, err := e.client.Txn(ctx.TODO()).
//		If(client.Compare(client.Version(prefix).WithPrefix(), "=", 0)).
//		Then(client.OpDelete(key)).
//		Commit()
//	if err != nil {
//		return err
//	}
//
//	if txnresp.Succeeded == false {
//		return fmt.Errorf("delete was unsuccessful")
//	}
//
//	return nil
//}

// ListPrefix returns a map of matching keys
func (e *etcdClient) ListPrefix(prefix string) (KeyValuePairs, error) {
	getR, err := e.client.Get(ctx.Background(), prefix, client.WithPrefix())
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
func (e *etcdClient) CreateLease(ttl time.Duration) (interface{}, error) {
	return e.client.Grant(ctx.TODO(), int64(ttl.Seconds()))
}

// KeepAlive keeps a lease created with CreateLease alive
func (e *etcdClient) KeepAlive(lease interface{}) error {
	r, ok := lease.(*client.LeaseGrantResponse)
	if !ok {
		return fmt.Errorf("argument not a LeaseID")
	}

	_, err := e.client.KeepAliveOnce(ctx.TODO(), r.ID)
	return err
}

// DeleteLease deletes a lease
func (e *etcdClient) DeleteLease(lease interface{}) error {
	r, ok := lease.(*client.LeaseGrantResponse)
	if !ok {
		return fmt.Errorf("argument not a LeaseID")
	}

	_, err := e.client.Revoke(ctx.TODO(), r.ID)
	return err
}

// Close closes the kvstore client
func (e *etcdClient) Close() {
	e.client.Close()
}

// GetCapabilities returns the capabilities of the backend
//
func (e *etcdClient) GetCapabilities() Capabilities {
	return Capabilities(CapabilityCreateIfExists)
}

// Encode encodes a binary slice into a character set that the backend supports
func (e *etcdClient) Encode(in []byte) string {
	return string(in)
}

// Decode decodes a key previously encoded back into the original binary slice
func (e *etcdClient) Decode(in string) ([]byte, error) {
	return []byte(in), nil
}
