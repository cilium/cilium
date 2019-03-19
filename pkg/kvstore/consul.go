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
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/spanstat"

	consulAPI "github.com/hashicorp/consul/api"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const (
	consulName = "consul"

	// optAddress is the string representing the key mapping to the value of the
	// address for Consul.
	optAddress         = "consul.address"
	consulOptionConfig = "consul.tlsconfig"

	// maxLockRetries is the number of retries attempted when acquiring a lock
	maxLockRetries = 10
)

type consulModule struct {
	opts   backendOptions
	config *consulAPI.Config
}

var (
	//consulDummyAddress can be overwritten from test invokers using ldflags
	consulDummyAddress = "https://127.0.0.1:8501"
	//consulDummyConfigFile can be overwritten from test invokers using ldflags
	consulDummyConfigFile = "/tmp/cilium-consul-certs/cilium-consul.yaml"

	module = newConsulModule()
)

func init() {
	// register consul module for use
	registerBackend(consulName, module)
}

func newConsulModule() backendModule {
	return &consulModule{
		opts: backendOptions{
			optAddress: &backendOption{
				description: "Addresses of consul cluster",
			},
			consulOptionConfig: &backendOption{
				description: "Path to consul tls configuration file",
			},
		},
	}
}

func (c *consulModule) createInstance() backendModule {
	return newConsulModule()
}

func (c *consulModule) getName() string {
	return consulName
}

func (c *consulModule) setConfigDummy() {
	c.config = consulAPI.DefaultConfig()
	c.config.Address = consulDummyAddress
	yc := consulAPI.TLSConfig{}
	b, err := ioutil.ReadFile(consulDummyConfigFile)
	if err != nil {
		log.WithError(err).Warnf("unable to read consul tls configuration file %s", consulDummyConfigFile)
	}

	err = yaml.Unmarshal(b, &yc)
	if err != nil {
		log.WithError(err).Warnf("invalid consul tls configuration in %s", consulDummyConfigFile)
	}

	c.config.TLSConfig = yc
}

func (c *consulModule) setConfig(opts map[string]string) error {
	return setOpts(opts, c.opts)
}

func (c *consulModule) setExtraConfig(opts *ExtraOptions) error {
	return nil
}

func (c *consulModule) getConfig() map[string]string {
	return getOpts(c.opts)
}

func (c *consulModule) newClient(opts *ExtraOptions) (BackendOperations, chan error) {
	errChan := make(chan error, 1)
	backend, err := c.connectConsulClient(opts)
	if err != nil {
		errChan <- err
	}
	close(errChan)
	return backend, errChan
}

func (c *consulModule) connectConsulClient(opts *ExtraOptions) (BackendOperations, error) {
	if c.config == nil {
		consulAddr, consulAddrSet := c.opts[optAddress]
		configPathOpt, configPathOptSet := c.opts[consulOptionConfig]
		if !consulAddrSet {
			return nil, fmt.Errorf("invalid consul configuration, please specify %s option", optAddress)
		}

		if consulAddr.value == "" {
			return nil, fmt.Errorf("invalid consul configuration, please specify %s option", optAddress)
		}

		addr := consulAddr.value
		c.config = consulAPI.DefaultConfig()
		if configPathOptSet && configPathOpt.value != "" {
			b, err := ioutil.ReadFile(configPathOpt.value)
			if err != nil {
				return nil, fmt.Errorf("unable to read consul tls configuration file %s: %s", configPathOpt.value, err)
			}
			yc := consulAPI.TLSConfig{}
			err = yaml.Unmarshal(b, &yc)
			if err != nil {
				return nil, fmt.Errorf("invalid consul tls configuration in %s: %s", configPathOpt.value, err)
			}
			c.config.TLSConfig = yc
		}

		c.config.Address = addr

	}
	client, err := newConsulClient(c.config, opts)
	if err != nil {
		return nil, err
	}

	return client, nil
}

var (
	maxRetries = 30
)

type consulClient struct {
	*consulAPI.Client
	lease        string
	controllers  *controller.Manager
	extraOptions *ExtraOptions
}

func newConsulClient(config *consulAPI.Config, opts *ExtraOptions) (BackendOperations, error) {
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

	boff := backoff.Exponential{Min: time.Duration(100) * time.Millisecond}
	log.Info("Waiting for consul to elect a leader")

	for i := 0; i < maxRetries; i++ {
		var leader string
		leader, err = c.Status().Leader()

		if err == nil {
			if leader != "" {
				// happy path
				break
			} else {
				err = errors.New("timeout while waiting for leader to be elected")
			}
		}
		boff.Wait(context.TODO())
	}

	if err != nil {
		log.WithError(err).Fatal("Unable to contact consul server")
	}

	entry := &consulAPI.SessionEntry{
		TTL:      fmt.Sprintf("%ds", int(LeaseTTL.Seconds())),
		Behavior: consulAPI.SessionBehaviorDelete,
	}

	lease, _, err := c.Session().Create(entry, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create default lease: %s", err)
	}

	client := &consulClient{
		Client:       c,
		lease:        lease,
		controllers:  controller.NewManager(),
		extraOptions: opts,
	}

	client.controllers.UpdateController(fmt.Sprintf("consul-lease-keepalive-%p", c),
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				_, _, err := c.Session().Renew(lease, nil)
				return err
			},
			RunInterval: KeepAliveInterval,
		},
	)

	return client, nil
}

func (c *consulClient) LockPath(ctx context.Context, path string) (kvLocker, error) {
	lockKey, err := c.LockOpts(&consulAPI.LockOptions{Key: getLockPath(path)})
	if err != nil {
		return nil, err
	}

	for retries := 0; retries < maxLockRetries; retries++ {
		ch, err := lockKey.Lock(nil)
		switch {
		case err != nil:
			return nil, err
		case ch == nil && err == nil:
			Trace("Acquiring lock timed out, retrying", nil, logrus.Fields{fieldKey: path, logfields.Attempt: retries})
		default:
			return lockKey, err
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("lock cancelled via context: %s", ctx.Err())
		default:
		}
	}

	return nil, fmt.Errorf("maximum retries (%d) reached", maxLockRetries)
}

// Watch starts watching for changes in a prefix
func (c *consulClient) Watch(w *Watcher) {
	// Last known state of all KVPairs matching the prefix
	localState := map[string]consulAPI.KVPair{}
	nextIndex := uint64(0)

	qo := consulAPI.QueryOptions{
		WaitTime: time.Second,
	}

	for {
		// Initialize sleep time to a millisecond as we don't
		// want to sleep in between successful watch cycles
		sleepTime := 1 * time.Millisecond

		qo.WaitIndex = nextIndex
		pairs, q, err := c.KV().List(w.prefix, &qo)
		if err != nil {
			sleepTime = 5 * time.Second
			Trace("List of Watch failed", err, logrus.Fields{fieldPrefix: w.prefix, fieldWatcher: w.name})
		}

		if q != nil {
			nextIndex = q.LastIndex
		}

		// timeout while watching for changes, re-schedule
		if qo.WaitIndex != 0 && (q == nil || q.LastIndex == qo.WaitIndex) {
			goto wait
		}

		for _, newPair := range pairs {
			oldPair, ok := localState[newPair.Key]

			// Keys reported for the first time must be new
			if !ok {
				if newPair.CreateIndex != newPair.ModifyIndex {
					log.Debugf("consul: Previously unknown key %s received with CreateIndex(%d) != ModifyIndex(%d)",
						newPair.Key, newPair.CreateIndex, newPair.ModifyIndex)
				}

				queueStart := spanstat.Start()
				w.Events <- KeyValueEvent{
					Typ:   EventTypeCreate,
					Key:   newPair.Key,
					Value: newPair.Value,
				}
				trackEventQueued(newPair.Key, EventTypeCreate, queueStart.End(true).Total())
			} else if oldPair.ModifyIndex != newPair.ModifyIndex {
				queueStart := spanstat.Start()
				w.Events <- KeyValueEvent{
					Typ:   EventTypeModify,
					Key:   newPair.Key,
					Value: newPair.Value,
				}
				trackEventQueued(newPair.Key, EventTypeModify, queueStart.End(true).Total())
			}

			// Everything left on localState will be assumed to
			// have been deleted, therefore remove all keys in
			// localState that still exist in the kvstore
			delete(localState, newPair.Key)
		}

		for k, deletedPair := range localState {
			queueStart := spanstat.Start()
			w.Events <- KeyValueEvent{
				Typ:   EventTypeDelete,
				Key:   deletedPair.Key,
				Value: deletedPair.Value,
			}
			trackEventQueued(deletedPair.Key, EventTypeDelete, queueStart.End(true).Total())
			delete(localState, k)
		}

		for _, newPair := range pairs {
			localState[newPair.Key] = *newPair

		}

		// Initial list operation has been completed, signal this
		if qo.WaitIndex == 0 {
			w.Events <- KeyValueEvent{Typ: EventTypeListDone}
		}

	wait:
		select {
		case <-time.After(sleepTime):
		case <-w.stopWatch:
			close(w.Events)
			w.stopWait.Done()
			return
		}
	}
}

func (c *consulClient) Connected() <-chan struct{} {
	return nil
}

func (c *consulClient) Disconnected() <-chan struct{} {
	return nil
}

func (c *consulClient) Status() (string, error) {
	leader, err := c.Client.Status().Leader()
	return "Consul: " + leader, err
}

func (c *consulClient) DeletePrefix(path string) error {
	duration := spanstat.Start()
	_, err := c.Client.KV().DeleteTree(path, nil)
	increaseMetric(path, metricDelete, "DeletePrefix", duration.EndError(err).Total(), err)
	return err
}

// Set sets value of key
func (c *consulClient) Set(key string, value []byte) error {
	duration := spanstat.Start()
	_, err := c.KV().Put(&consulAPI.KVPair{Key: key, Value: value}, nil)
	increaseMetric(key, metricSet, "Set", duration.EndError(err).Total(), err)
	return err
}

// Delete deletes a key
func (c *consulClient) Delete(key string) error {
	duration := spanstat.Start()
	_, err := c.KV().Delete(key, nil)
	increaseMetric(key, metricDelete, "Delete", duration.EndError(err).Total(), err)
	return err
}

// Get returns value of key
func (c *consulClient) Get(key string) ([]byte, error) {
	duration := spanstat.Start()
	pair, _, err := c.KV().Get(key, nil)
	increaseMetric(key, metricRead, "Get", duration.EndError(err).Total(), err)
	if err != nil {
		return nil, err
	}
	if pair == nil {
		return nil, nil
	}
	return pair.Value, nil
}

// GetPrefix returns the first key which matches the prefix
func (c *consulClient) GetPrefix(ctx context.Context, prefix string) ([]byte, error) {
	duration := spanstat.Start()
	opts := &consulAPI.QueryOptions{}
	pairs, _, err := c.KV().List(prefix, opts.WithContext(ctx))
	increaseMetric(prefix, metricRead, "GetPrefix", duration.EndError(err).Total(), err)
	if err != nil {
		return nil, err
	}

	if len(pairs) == 0 {
		return nil, nil
	}

	return pairs[0].Value, nil
}

// Update creates or updates a key with the value
func (c *consulClient) Update(ctx context.Context, key string, value []byte, lease bool) error {
	k := &consulAPI.KVPair{Key: key, Value: value}

	if lease {
		k.Session = c.lease
	}

	opts := &consulAPI.WriteOptions{}

	duration := spanstat.Start()
	_, err := c.KV().Put(k, opts.WithContext(ctx))
	increaseMetric(key, metricSet, "Update", duration.EndError(err).Total(), err)
	return err
}

// CreateOnly creates a key with the value and will fail if the key already exists
func (c *consulClient) CreateOnly(ctx context.Context, key string, value []byte, lease bool) error {
	k := &consulAPI.KVPair{
		Key:         key,
		Value:       value,
		CreateIndex: 0,
	}

	if lease {
		k.Session = c.lease
	}
	opts := &consulAPI.WriteOptions{}

	duration := spanstat.Start()
	success, _, err := c.KV().CAS(k, opts.WithContext(ctx))
	increaseMetric(key, metricSet, "CreateOnly", duration.EndError(err).Total(), err)
	if err != nil {
		return fmt.Errorf("unable to compare-and-swap: %s", err)
	}
	if !success {
		return fmt.Errorf("compare-and-swap unsuccessful")
	}

	return nil
}

// createIfExists creates a key with the value only if key condKey exists
func (c *consulClient) createIfExists(condKey, key string, value []byte, lease bool) error {
	// Consul does not support transactions which would allow to check for
	// the presence of a conditional key if the key is not the key being
	// manipulated
	//
	// Lock the conditional key to serialize all CreateIfExists() calls

	l, err := LockPath(context.Background(), condKey)
	if err != nil {
		return fmt.Errorf("unable to lock condKey for CreateIfExists: %s", err)
	}

	defer l.Unlock()

	// Create the key if it does not exist
	if err := c.CreateOnly(context.TODO(), key, value, lease); err != nil {
		return err
	}

	// Consul does not support transactions which would allow to check for
	// the presence of another key
	masterKey, err := c.Get(condKey)
	if err != nil || masterKey == nil {
		c.Delete(key)
		return fmt.Errorf("conditional key not present")
	}

	return nil
}

// CreateIfExists creates a key with the value only if key condKey exists
func (c *consulClient) CreateIfExists(condKey, key string, value []byte, lease bool) error {
	duration := spanstat.Start()
	err := c.createIfExists(condKey, key, value, lease)
	increaseMetric(key, metricSet, "CreateIfExists", duration.EndError(err).Total(), err)
	return err
}

// ListPrefix returns a map of matching keys
func (c *consulClient) ListPrefix(prefix string) (KeyValuePairs, error) {
	duration := spanstat.Start()
	pairs, _, err := c.KV().List(prefix, nil)
	increaseMetric(prefix, metricRead, "ListPrefix", duration.EndError(err).Total(), err)
	if err != nil {
		return nil, err
	}

	p := KeyValuePairs(make(map[string][]byte, len(pairs)))
	for i := 0; i < len(pairs); i++ {
		p[pairs[i].Key] = pairs[i].Value
	}

	return p, nil
}

// Close closes the consul session
func (c *consulClient) Close() {
	if c.controllers != nil {
		c.controllers.RemoveAll()
	}
	if c.lease != "" {
		c.Session().Destroy(c.lease, nil)
	}
}

// GetCapabilities returns the capabilities of the backend
func (c *consulClient) GetCapabilities() Capabilities {
	return Capabilities(0)
}

// Encode encodes a binary slice into a character set that the backend supports
func (c *consulClient) Encode(in []byte) string {
	return base64.URLEncoding.EncodeToString([]byte(in))
}

// Decode decodes a key previously encoded back into the original binary slice
func (c *consulClient) Decode(in string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(in)
}

// ListAndWatch implements the BackendOperations.ListAndWatch using consul
func (c *consulClient) ListAndWatch(name, prefix string, chanSize int) *Watcher {
	w := newWatcher(name, prefix, chanSize)

	log.WithField(fieldWatcher, w).Debug("Starting watcher...")

	go c.Watch(w)

	return w
}
