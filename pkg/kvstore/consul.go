// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	consulAPI "github.com/hashicorp/consul/api"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/time"
)

const (
	consulName = "consul"

	// ConsulAddrOption is the string representing the key mapping to the value of the
	// address for Consul.
	ConsulAddrOption   = "consul.address"
	ConsulOptionConfig = "consul.tlsconfig"

	// maxLockRetries is the number of retries attempted when acquiring a lock
	maxLockRetries = 10
)

type consulModule struct {
	opts   backendOptions
	config *consulAPI.Config
}

var (
	// consulDummyAddress can be overwritten from test invokers using ldflags
	consulDummyAddress = "https://127.0.0.1:8501"
	// consulDummyConfigFile can be overwritten from test invokers using ldflags
	consulDummyConfigFile = "/tmp/cilium-consul-certs/cilium-consul.yaml"

	module = newConsulModule()

	// ErrNotImplemented is the error which is returned when a functionality is not implemented.
	ErrNotImplemented = errors.New("not implemented")

	consulLeaseKeepaliveControllerGroup = controller.NewGroup("consul-lease-keepalive")
)

func init() {
	// register consul module for use
	registerBackend(consulName, module)
}

func newConsulModule() backendModule {
	return &consulModule{
		opts: backendOptions{
			ConsulAddrOption: &backendOption{
				description: "Addresses of consul cluster",
			},
			ConsulOptionConfig: &backendOption{
				description: "Path to consul tls configuration file",
			},
		},
	}
}

func ConsulDummyAddress() string {
	return consulDummyAddress
}

func ConsulDummyConfigFile() string {
	return consulDummyConfigFile
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
	b, err := os.ReadFile(consulDummyConfigFile)
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

func (c *consulModule) newClient(ctx context.Context, opts *ExtraOptions) (BackendOperations, chan error) {
	log.WithFields(logrus.Fields{
		logfields.URL: "https://slack.cilium.io",
	}).Warning("Support for Consul as a kvstore backend has been deprecated due to lack of maintainers. If you are interested in helping to maintain Consul support in Cilium, please reach out on GitHub or the official Cilium slack")

	errChan := make(chan error, 1)
	backend, err := c.connectConsulClient(ctx, opts)
	if err != nil {
		errChan <- err
	}
	close(errChan)
	return backend, errChan
}

func (c *consulModule) connectConsulClient(ctx context.Context, opts *ExtraOptions) (BackendOperations, error) {
	if c.config == nil {
		consulAddr, consulAddrSet := c.opts[ConsulAddrOption]
		configPathOpt, configPathOptSet := c.opts[ConsulOptionConfig]
		if !consulAddrSet {
			return nil, fmt.Errorf("invalid consul configuration, please specify %s option", ConsulAddrOption)
		}

		if consulAddr.value == "" {
			return nil, fmt.Errorf("invalid consul configuration, please specify %s option", ConsulAddrOption)
		}

		addr := consulAddr.value
		c.config = consulAPI.DefaultConfig()
		if configPathOptSet && configPathOpt.value != "" {
			b, err := os.ReadFile(configPathOpt.value)
			if err != nil {
				return nil, fmt.Errorf("unable to read consul tls configuration file %s: %w", configPathOpt.value, err)
			}
			yc := consulAPI.TLSConfig{}
			err = yaml.Unmarshal(b, &yc)
			if err != nil {
				return nil, fmt.Errorf("invalid consul tls configuration in %s: %w", configPathOpt.value, err)
			}
			c.config.TLSConfig = yc
		}

		c.config.Address = addr

	}
	client, err := newConsulClient(ctx, c.config, opts)
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
	lease             string
	controllers       *controller.Manager
	extraOptions      *ExtraOptions
	disconnectedMu    lock.RWMutex
	disconnected      chan struct{}
	statusCheckErrors chan error
}

func newConsulClient(ctx context.Context, config *consulAPI.Config, opts *ExtraOptions) (BackendOperations, error) {
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
		log.Info("Waiting for consul to elect a leader")
		boff.Wait(ctx)
	}

	if err != nil {
		log.WithError(err).Fatal("Unable to contact consul server")
	}

	entry := &consulAPI.SessionEntry{
		TTL:      fmt.Sprintf("%ds", int(option.Config.KVstoreLeaseTTL.Seconds())),
		Behavior: consulAPI.SessionBehaviorDelete,
	}

	wo := &consulAPI.WriteOptions{}
	lease, _, err := c.Session().Create(entry, wo.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("unable to create default lease: %w", err)
	}

	client := &consulClient{
		Client:            c,
		lease:             lease,
		controllers:       controller.NewManager(),
		extraOptions:      opts,
		disconnected:      make(chan struct{}),
		statusCheckErrors: make(chan error, 128),
	}

	client.controllers.UpdateController(
		fmt.Sprintf("consul-lease-keepalive-%p", c),
		controller.ControllerParams{
			Group: consulLeaseKeepaliveControllerGroup,
			DoFunc: func(ctx context.Context) error {
				wo := &consulAPI.WriteOptions{}
				_, _, err := c.Session().Renew(lease, wo.WithContext(ctx))
				if err != nil {
					// consider disconnected!
					client.disconnectedMu.Lock()
					close(client.disconnected)
					client.disconnected = make(chan struct{})
					client.disconnectedMu.Unlock()
				}
				return err
			},
			RunInterval: option.Config.KVstoreKeepAliveInterval,
		},
	)

	return client, nil
}

type ConsulLocker struct {
	*consulAPI.Lock
}

func (cl *ConsulLocker) Unlock(ctx context.Context) error {
	return cl.Lock.Unlock()
}

func (cl *ConsulLocker) Comparator() interface{} {
	return nil
}

func (c *consulClient) LockPath(ctx context.Context, path string) (KVLocker, error) {
	lockKey, err := c.LockOpts(&consulAPI.LockOptions{Key: getLockPath(path)})
	if err != nil {
		return nil, err
	}

	for retries := 0; retries < maxLockRetries; retries++ {
		ch, err := lockKey.Lock(nil)
		switch {
		case err != nil:
			return nil, err
		case ch == nil:
			Trace("Acquiring lock timed out, retrying", nil, logrus.Fields{fieldKey: path, logfields.Attempt: retries})
		default:
			return &ConsulLocker{Lock: lockKey}, err
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("lock cancelled via context: %w", ctx.Err())
		default:
		}
	}

	return nil, fmt.Errorf("maximum retries (%d) reached", maxLockRetries)
}

// watch starts watching for changes in a prefix
func (c *consulClient) watch(ctx context.Context, w *Watcher) {
	scope := GetScopeFromKey(strings.TrimRight(w.Prefix, "/"))
	// Last known state of all KVPairs matching the prefix
	localState := map[string]consulAPI.KVPair{}
	nextIndex := uint64(0)

	q := &consulAPI.QueryOptions{
		WaitTime: time.Second,
	}

	qo := q.WithContext(ctx)

	sleepTimer, sleepTimerDone := inctimer.New()
	defer sleepTimerDone()

	for {
		// Initialize sleep time to a millisecond as we don't
		// want to sleep in between successful watch cycles
		sleepTime := 1 * time.Millisecond

		qo.WaitIndex = nextIndex
		pairs, q, err := c.KV().List(w.Prefix, qo)
		if err != nil {
			sleepTime = 5 * time.Second
			Trace("List of Watch failed", err, logrus.Fields{fieldPrefix: w.Prefix})
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
				trackEventQueued(scope, EventTypeCreate, queueStart.End(true).Total())
			} else if oldPair.ModifyIndex != newPair.ModifyIndex {
				queueStart := spanstat.Start()
				w.Events <- KeyValueEvent{
					Typ:   EventTypeModify,
					Key:   newPair.Key,
					Value: newPair.Value,
				}
				trackEventQueued(scope, EventTypeModify, queueStart.End(true).Total())
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
			trackEventQueued(scope, EventTypeDelete, queueStart.End(true).Total())
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
		case <-sleepTimer.After(sleepTime):
		case <-w.stopWatch:
			close(w.Events)
			w.stopWait.Done()
			return
		}
	}
}

func (c *consulClient) waitForInitLock(ctx context.Context) <-chan struct{} {
	initLockSucceeded := make(chan struct{})

	go func() {
		for {
			locker, err := c.LockPath(ctx, InitLockPath)
			if err == nil {
				locker.Unlock(context.Background())
				close(initLockSucceeded)
				log.Info("Distributed lock successful, consul has quorum")
				return
			}

			time.Sleep(100 * time.Millisecond)
		}
	}()

	return initLockSucceeded
}

// Connected closes the returned channel when the consul client is connected.
func (c *consulClient) Connected(ctx context.Context) <-chan error {
	ch := make(chan error)
	go func() {
		for {
			qo := &consulAPI.QueryOptions{}
			// TODO find out if there's a better way to do this for consul
			_, _, err := c.Session().Info(c.lease, qo.WithContext(ctx))
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		<-c.waitForInitLock(ctx)
		close(ch)
	}()
	return ch
}

// Disconnected closes the returned channel when consul detects the client
// is disconnected from the server.
func (c *consulClient) Disconnected() <-chan struct{} {
	c.disconnectedMu.RLock()
	ch := c.disconnected
	c.disconnectedMu.RUnlock()
	return ch
}

func (c *consulClient) Status() (string, error) {
	leader, err := c.Client.Status().Leader()
	return "Consul: " + leader, err
}

func (c *consulClient) DeletePrefix(ctx context.Context, path string) (err error) {
	defer func() { Trace("DeletePrefix", err, logrus.Fields{fieldPrefix: path}) }()

	duration := spanstat.Start()
	wo := &consulAPI.WriteOptions{}
	_, err = c.Client.KV().DeleteTree(path, wo.WithContext(ctx))
	increaseMetric(path, metricDelete, "DeletePrefix", duration.EndError(err).Total(), err)
	return err
}

// DeleteIfLocked deletes a key if the client is still holding the given lock.
func (c *consulClient) DeleteIfLocked(ctx context.Context, key string, lock KVLocker) (err error) {
	defer func() { Trace("DeleteIfLocked", err, logrus.Fields{fieldKey: key}) }()
	return c.delete(ctx, key)
}

// Delete deletes a key
func (c *consulClient) Delete(ctx context.Context, key string) (err error) {
	defer func() { Trace("Delete", err, logrus.Fields{fieldKey: key}) }()
	return c.delete(ctx, key)
}

func (c *consulClient) delete(ctx context.Context, key string) error {
	duration := spanstat.Start()
	wo := &consulAPI.WriteOptions{}
	_, err := c.KV().Delete(key, wo.WithContext(ctx))
	increaseMetric(key, metricDelete, "Delete", duration.EndError(err).Total(), err)
	return err
}

// GetIfLocked returns value of key if the client is still holding the given lock.
func (c *consulClient) GetIfLocked(ctx context.Context, key string, lock KVLocker) (bv []byte, err error) {
	defer func() { Trace("GetIfLocked", err, logrus.Fields{fieldKey: key, fieldValue: string(bv)}) }()
	return c.Get(ctx, key)
}

// Get returns value of key
func (c *consulClient) Get(ctx context.Context, key string) (bv []byte, err error) {
	defer func() { Trace("Get", err, logrus.Fields{fieldKey: key, fieldValue: string(bv)}) }()

	duration := spanstat.Start()
	qo := &consulAPI.QueryOptions{}
	pair, _, err := c.KV().Get(key, qo.WithContext(ctx))
	increaseMetric(key, metricRead, "Get", duration.EndError(err).Total(), err)
	if err != nil {
		return nil, err
	}
	if pair == nil {
		return nil, nil
	}
	return pair.Value, nil
}

// UpdateIfLocked updates a key if the client is still holding the given lock.
func (c *consulClient) UpdateIfLocked(ctx context.Context, key string, value []byte, lease bool, lock KVLocker) error {
	return c.Update(ctx, key, value, lease)
}

// Update creates or updates a key with the value
func (c *consulClient) Update(ctx context.Context, key string, value []byte, lease bool) (err error) {
	defer func() {
		Trace("Update", err, logrus.Fields{fieldKey: key, fieldValue: string(value), fieldAttachLease: lease})
	}()

	k := &consulAPI.KVPair{Key: key, Value: value}

	if lease {
		k.Session = c.lease
	}

	opts := &consulAPI.WriteOptions{}

	duration := spanstat.Start()
	_, err = c.KV().Put(k, opts.WithContext(ctx))
	increaseMetric(key, metricSet, "Update", duration.EndError(err).Total(), err)
	return err
}

// UpdateIfDifferentIfLocked updates a key if the value is different and if the client is still holding the given lock.
func (c *consulClient) UpdateIfDifferentIfLocked(ctx context.Context, key string, value []byte, lease bool, lock KVLocker) (recreated bool, err error) {
	defer func() {
		Trace("UpdateIfDifferentIfLocked", err, logrus.Fields{fieldKey: key, fieldValue: value, fieldAttachLease: lease, "recreated": recreated})
	}()

	return c.updateIfDifferent(ctx, key, value, lease)
}

// UpdateIfDifferent updates a key if the value is different
func (c *consulClient) UpdateIfDifferent(ctx context.Context, key string, value []byte, lease bool) (recreated bool, err error) {
	defer func() {
		Trace("UpdateIfDifferent", err, logrus.Fields{fieldKey: key, fieldValue: value, fieldAttachLease: lease, "recreated": recreated})
	}()

	return c.updateIfDifferent(ctx, key, value, lease)
}

func (c *consulClient) updateIfDifferent(ctx context.Context, key string, value []byte, lease bool) (bool, error) {
	duration := spanstat.Start()
	qo := &consulAPI.QueryOptions{}
	getR, _, err := c.KV().Get(key, qo.WithContext(ctx))
	increaseMetric(key, metricRead, "Get", duration.EndError(err).Total(), err)
	// On error, attempt update blindly
	if err != nil || getR == nil {
		return true, c.Update(ctx, key, value, lease)
	}

	if lease && getR.Session != c.lease {
		return true, c.Update(ctx, key, value, lease)
	}

	// if lease is different and value is not equal then update.
	if !bytes.Equal(getR.Value, value) {
		return true, c.Update(ctx, key, value, lease)
	}

	return false, nil
}

// CreateOnlyIfLocked atomically creates a key if the client is still holding the given lock or fails if it already exists
func (c *consulClient) CreateOnlyIfLocked(ctx context.Context, key string, value []byte, lease bool, lock KVLocker) (success bool, err error) {
	defer func() {
		Trace("CreateOnlyIfLocked", err, logrus.Fields{fieldKey: key, fieldValue: value, fieldAttachLease: lease, "success": success})
	}()
	return c.createOnly(ctx, key, value, lease)
}

// CreateOnly creates a key with the value and will fail if the key already exists
func (c *consulClient) CreateOnly(ctx context.Context, key string, value []byte, lease bool) (success bool, err error) {
	defer func() {
		Trace("CreateOnly", err, logrus.Fields{fieldKey: key, fieldValue: value, fieldAttachLease: lease, "success": success})
	}()

	return c.createOnly(ctx, key, value, lease)
}

func (c *consulClient) createOnly(ctx context.Context, key string, value []byte, lease bool) (bool, error) {
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
		return false, fmt.Errorf("unable to compare-and-swap: %w", err)
	}
	return success, nil
}

// ListPrefixIfLocked returns a list of keys matching the prefix only if the client is still holding the given lock.
func (c *consulClient) ListPrefixIfLocked(ctx context.Context, prefix string, lock KVLocker) (v KeyValuePairs, err error) {
	defer func() { Trace("ListPrefixIfLocked", err, logrus.Fields{fieldPrefix: prefix, fieldNumEntries: len(v)}) }()
	return c.listPrefix(ctx, prefix)
}

// ListPrefix returns a map of matching keys
func (c *consulClient) ListPrefix(ctx context.Context, prefix string) (v KeyValuePairs, err error) {
	defer func() { Trace("ListPrefix", err, logrus.Fields{fieldPrefix: prefix, fieldNumEntries: len(v)}) }()
	return c.listPrefix(ctx, prefix)
}

func (c *consulClient) listPrefix(ctx context.Context, prefix string) (KeyValuePairs, error) {
	duration := spanstat.Start()
	qo := &consulAPI.QueryOptions{}
	pairs, _, err := c.KV().List(prefix, qo.WithContext(ctx))
	increaseMetric(prefix, metricRead, "ListPrefix", duration.EndError(err).Total(), err)
	if err != nil {
		return nil, err
	}

	p := KeyValuePairs(make(map[string]Value, len(pairs)))
	for i := 0; i < len(pairs); i++ {
		p[pairs[i].Key] = Value{
			Data:        pairs[i].Value,
			ModRevision: pairs[i].ModifyIndex,
			SessionID:   pairs[i].Session,
		}
	}

	return p, nil
}

// Close closes the consul session
func (c *consulClient) Close() {
	close(c.statusCheckErrors)
	if c.controllers != nil {
		c.controllers.RemoveAll()
	}
	if c.lease != "" {
		c.Session().Destroy(c.lease, nil)
	}
}

// Encode encodes a binary slice into a character set that the backend supports
func (c *consulClient) Encode(in []byte) (out string) {
	defer func() { Trace("Encode", nil, logrus.Fields{"in": in, "out": out}) }()
	return base64.URLEncoding.EncodeToString([]byte(in))
}

// Decode decodes a key previously encoded back into the original binary slice
func (c *consulClient) Decode(in string) (out []byte, err error) {
	defer func() { Trace("Decode", err, logrus.Fields{"in": in, "out": out}) }()
	return base64.URLEncoding.DecodeString(in)
}

// ListAndWatch implements the BackendOperations.ListAndWatch using consul
func (c *consulClient) ListAndWatch(ctx context.Context, prefix string, chanSize int) *Watcher {
	w := newWatcher(prefix, chanSize)

	log.WithField(fieldPrefix, prefix).Debug("Starting watcher...")

	go c.watch(ctx, w)

	return w
}

// StatusCheckErrors returns a channel which receives status check errors
func (c *consulClient) StatusCheckErrors() <-chan error {
	return c.statusCheckErrors
}

// RegisterLeaseExpiredObserver is not implemented for the consul backend
func (c *consulClient) RegisterLeaseExpiredObserver(prefix string, fn func(key string)) {}

// UserEnforcePresence is not implemented for the consul backend
func (c *consulClient) UserEnforcePresence(ctx context.Context, name string, roles []string) error {
	return ErrNotImplemented
}

// UserEnforceAbsence is not implemented for the consul backend
func (c *consulClient) UserEnforceAbsence(ctx context.Context, name string) error {
	return ErrNotImplemented
}
