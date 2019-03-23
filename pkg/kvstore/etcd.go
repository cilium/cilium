// Copyright 2016-2019 Authors of Cilium
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
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/spanstat"

	client "github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/clientv3/concurrency"
	clientyaml "github.com/coreos/etcd/clientv3/yaml"
	v3rpcErrors "github.com/coreos/etcd/etcdserver/api/v3rpc/rpctypes"
	"github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
	ctx "golang.org/x/net/context"
	"golang.org/x/time/rate"
)

const (
	// EtcdBackendName is the backend name fo etcd
	EtcdBackendName = "etcd"

	addrOption       = "etcd.address"
	EtcdOptionConfig = "etcd.config"

	// EtcdRateLimitOption specifies maximum kv operations per second
	EtcdRateLimitOption = "etcd.qps"
)

type etcdModule struct {
	opts   backendOptions
	config *client.Config
}

var (
	// versionCheckTimeout is the time we wait trying to verify the version
	// of an etcd endpoint. The timeout can be encountered on network
	// connectivity problems.
	versionCheckTimeout = 30 * time.Second

	// statusCheckTimeout is the timeout when performing status checks with
	// all etcd endpoints
	statusCheckTimeout = 5 * time.Second

	// initialConnectionTimeout  is the timeout for the initial connection to
	// the etcd server
	initialConnectionTimeout = 15 * time.Minute

	minRequiredVersion, _ = version.NewConstraint(">= 3.1.0")

	// etcdDummyAddress can be overwritten from test invokers using ldflags
	etcdDummyAddress = "http://127.0.0.1:4002"

	etcdInstance = newEtcdModule()
)

func EtcdDummyAddress() string {
	return etcdDummyAddress
}

func newEtcdModule() backendModule {
	return &etcdModule{
		opts: backendOptions{
			addrOption: &backendOption{
				description: "Addresses of etcd cluster",
			},
			EtcdOptionConfig: &backendOption{
				description: "Path to etcd configuration file",
			},
			EtcdRateLimitOption: &backendOption{
				description: "Rate limit in kv store operations per second",
				validate: func(v string) error {
					_, err := strconv.Atoi(v)
					return err
				},
			},
		},
	}
}

func (e *etcdModule) createInstance() backendModule {
	return newEtcdModule()
}

func (e *etcdModule) getName() string {
	return EtcdBackendName
}

func (e *etcdModule) setConfigDummy() {
	e.config = &client.Config{}
	e.config.Endpoints = []string{etcdDummyAddress}
}

func (e *etcdModule) setConfig(opts map[string]string) error {
	return setOpts(opts, e.opts)
}

func (e *etcdModule) setExtraConfig(opts *ExtraOptions) error {
	if opts != nil && len(opts.DialOption) != 0 {
		e.config = &client.Config{}
		e.config.DialOptions = append(e.config.DialOptions, opts.DialOption...)
	}
	return nil
}

func (e *etcdModule) getConfig() map[string]string {
	return getOpts(e.opts)
}

func (e *etcdModule) newClient(opts *ExtraOptions) (BackendOperations, chan error) {
	errChan := make(chan error, 10)

	endpointsOpt, endpointsSet := e.opts[addrOption]
	configPathOpt, configSet := e.opts[EtcdOptionConfig]

	rateLimitOpt, rateLimitSet := e.opts[EtcdRateLimitOption]

	rateLimit := defaults.KVstoreQPS
	if rateLimitSet {
		// error is discarded here because this option has validation
		rateLimit, _ = strconv.Atoi(rateLimitOpt.value)
	}

	var configPath string
	if configSet {
		configPath = configPathOpt.value
	}
	if e.config == nil {
		if !endpointsSet && !configSet {
			errChan <- fmt.Errorf("invalid etcd configuration, %s or %s must be specified", EtcdOptionConfig, addrOption)
			close(errChan)
			return nil, errChan
		}

		if endpointsOpt.value == "" && configPath == "" {
			errChan <- fmt.Errorf("invalid etcd configuration, %s or %s must be specified",
				EtcdOptionConfig, addrOption)
			close(errChan)
			return nil, errChan
		}

		e.config = &client.Config{}
	}

	if e.config.Endpoints == nil && endpointsSet {
		e.config.Endpoints = []string{endpointsOpt.value}
	}

	for {
		// connectEtcdClient will close errChan when the connection attempt has
		// been successful
		backend, err := connectEtcdClient(e.config, configPath, errChan, rateLimit, opts)
		switch {
		case os.IsNotExist(err):
			log.WithError(err).Info("Waiting for all etcd configuration files to be available")
			time.Sleep(5 * time.Second)
		case err != nil:
			errChan <- err
			close(errChan)
			return backend, errChan
		default:
			return backend, errChan
		}
	}
}

func init() {
	// register etcd module for use
	registerBackend(EtcdBackendName, etcdInstance)
}

// Hint tries to improve the error message displayed to te user.
func Hint(err error) error {
	switch err {
	case ctx.DeadlineExceeded:
		return fmt.Errorf("etcd client timeout exceeded")
	default:
		return err
	}
}

type etcdClient struct {
	// firstSession is a channel that will be closed once the first session
	// is set up in the etcd Client.
	firstSession chan struct{}

	// stopStatusChecker is closed when the status checker can be terminated
	stopStatusChecker chan struct{}

	client      *client.Client
	controllers *controller.Manager

	// config and configPath are initialized once and never written to again, they can be accessed without locking
	config     *client.Config
	configPath string

	// protects session from concurrent access
	lock.RWMutex
	session *concurrency.Session

	// statusLock protects latestStatusSnapshot and latestErrorStatus for
	// read/write access
	statusLock lock.RWMutex

	// latestStatusSnapshot is a snapshot of the latest etcd cluster status
	latestStatusSnapshot string

	// latestErrorStatus is the latest error condition of the etcd connection
	latestErrorStatus error

	extraOptions *ExtraOptions

	limiter *rate.Limiter
}

func (e *etcdClient) getLogger() *logrus.Entry {
	endpoints, path := []string{""}, ""
	if e != nil {
		if e.config != nil {
			endpoints = e.config.Endpoints
		}
		path = e.configPath
	}

	return log.WithFields(logrus.Fields{
		"endpoints": endpoints,
		"config":    path,
	})
}

type etcdMutex struct {
	mutex *concurrency.Mutex
}

func (e *etcdMutex) Unlock() error {
	return e.mutex.Unlock(ctx.TODO())
}

// GetLeaseID returns the current lease ID.
func (e *etcdClient) GetLeaseID() client.LeaseID {
	e.RWMutex.RLock()
	l := e.session.Lease()
	e.RWMutex.RUnlock()
	return l
}

// checkSession verifies if the lease is still valid from the return error of
// an etcd API call. If the error explicitly states that a lease was not found
// we mark the session has an orphan for this etcd client. If we would not mark
// it as an Orphan() the session would be considered expired after the leaseTTL
// By make it orphan we guarantee the session will be marked to be renewed.
func (e *etcdClient) checkSession(err error, leaseID client.LeaseID) {
	if err == v3rpcErrors.ErrLeaseNotFound {
		e.closeSession(leaseID)
	}
}

// closeSession closes the current session.
func (e *etcdClient) closeSession(leaseID client.LeaseID) {
	e.RWMutex.RLock()
	// only mark a session as orphan if the leaseID is the same as the
	// session ID to avoid making any other sessions as orphan.
	if e.session.Lease() == leaseID {
		e.session.Orphan()
	}
	e.RWMutex.RUnlock()
}

// Connected closes the returned channel when the etcd client is connected.
func (e *etcdClient) Connected() <-chan struct{} {
	select {
	case <-e.firstSession:
	getSession:
		e.RLock()
		ch := e.session.Done()
		e.RUnlock()
		select {
		case <-ch:
			// this case means we are disconnected as the e.session.Done() was
			// closed. We will pooling until we have a new etcd session and
			// we are connected to the kvstore.
			time.Sleep(100 * time.Millisecond)
			goto getSession
		default:
			out := make(chan struct{})
			close(out)
			return out
		}
	default:
		// We assume when the e.firstSession is closed that we have connectivity
		// with the kvstore as this channel is closed when we have the first
		// session.
		return e.firstSession
	}
}

// Disconnected closes the returned channel when the etcd client is
// disconnected after being reconnected. Blocks until the etcd client is first
// connected with the kvstore.
func (e *etcdClient) Disconnected() <-chan struct{} {
	select {
	case <-e.firstSession:
		e.RLock()
		ch := e.session.Done()
		e.RUnlock()
		return ch
	}
}

func (e *etcdClient) renewSession() error {
	<-e.firstSession
	<-e.session.Done()
	// This is an attempt to avoid concurrent access of a session that was
	// already expired. It's not perfect as there is still a period between the
	// e.session.Done() is closed and the e.Lock() is held where parallel go
	// routines can get a lease ID of an already expired lease.
	e.Lock()

	newSession, err := concurrency.NewSession(e.client, concurrency.WithTTL(int(LeaseTTL.Seconds())))
	if err != nil {
		e.UnlockIgnoreTime()
		return fmt.Errorf("Unable to renew etcd session: %s", err)
	}

	e.session = newSession
	e.UnlockIgnoreTime()

	e.getLogger().WithField(fieldSession, newSession).Debug("Renewing etcd session")

	if err := e.checkMinVersion(); err != nil {
		return err
	}

	return nil
}

func connectEtcdClient(config *client.Config, cfgPath string, errChan chan error, rateLimit int, opts *ExtraOptions) (BackendOperations, error) {
	if cfgPath != "" {
		cfg, err := clientyaml.NewConfig(cfgPath)
		if err != nil {
			return nil, err
		}
		cfg.DialOptions = append(cfg.DialOptions, config.DialOptions...)
		config = cfg
	}

	// Set DialTimeout to 0, otherwise the creation of a new client will
	// block until DialTimeout is reached or a connection to the server
	// is made.
	config.DialTimeout = 0
	c, err := client.New(*config)
	if err != nil {
		return nil, err
	}

	log.WithFields(logrus.Fields{
		"endpoints": config.Endpoints,
		"config":    cfgPath,
	}).Info("Connecting to etcd server...")

	var s concurrency.Session
	firstSession := make(chan struct{})
	sessionChan := make(chan *concurrency.Session)
	errorChan := make(chan error)

	// create session in parallel as this is a blocking operation
	go func() {
		session, err := concurrency.NewSession(c, concurrency.WithTTL(int(LeaseTTL.Seconds())))
		errorChan <- err
		sessionChan <- session
		close(sessionChan)
		close(errorChan)
	}()

	ec := &etcdClient{
		client:               c,
		config:               config,
		configPath:           cfgPath,
		session:              &s,
		firstSession:         firstSession,
		controllers:          controller.NewManager(),
		latestStatusSnapshot: "No connection to etcd",
		stopStatusChecker:    make(chan struct{}),
		extraOptions:         opts,
		limiter:              rate.NewLimiter(rate.Limit(rateLimit), rateLimit),
	}

	// wait for session to be created also in parallel
	go func() {
		defer close(errChan)

		var session concurrency.Session
		select {
		case err = <-errorChan:
			if err == nil {
				session = *<-sessionChan
			}
		case <-time.After(initialConnectionTimeout):
			err = fmt.Errorf("timed out while waiting for etcd session. Ensure that etcd is running on %s", config.Endpoints)
		}
		if err != nil {
			errChan <- err
			return
		}

		ec.getLogger().Debugf("Session received")
		s = session
		if err != nil {
			c.Close()
			errChan <- fmt.Errorf("unable to create default lease: %s", err)
			return
		}
		close(ec.firstSession)

		if err := ec.checkMinVersion(); err != nil {
			errChan <- fmt.Errorf("Unable to validate etcd version: %s", err)
		}
	}()

	go ec.statusChecker()

	ec.controllers.UpdateController("kvstore-etcd-session-renew",
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				return ec.renewSession()
			},
			RunInterval: time.Duration(10) * time.Millisecond,
		},
	)

	return ec, nil
}

func getEPVersion(c client.Maintenance, etcdEP string, timeout time.Duration) (*version.Version, error) {
	ctxTimeout, cancel := ctx.WithTimeout(ctx.TODO(), timeout)
	defer cancel()
	sr, err := c.Status(ctxTimeout, etcdEP)
	if err != nil {
		return nil, Hint(err)
	}
	v, err := version.NewVersion(sr.Version)
	if err != nil {
		return nil, fmt.Errorf("error parsing server version %q: %s", sr.Version, Hint(err))
	}
	return v, nil
}

// checkMinVersion checks the minimal version running on etcd cluster.  This
// function should be run whenever the etcd client is connected for the first
// time and whenever the session is renewed.
func (e *etcdClient) checkMinVersion() error {
	eps := e.client.Endpoints()

	for _, ep := range eps {
		v, err := getEPVersion(e.client.Maintenance, ep, versionCheckTimeout)
		if err != nil {
			e.getLogger().WithError(Hint(err)).WithField(fieldEtcdEndpoint, ep).
				Warn("Unable to verify version of etcd endpoint")
			continue
		}

		if !minRequiredVersion.Check(v) {
			return fmt.Errorf("Minimal etcd version not met in %q, required: %s, found: %s",
				ep, minRequiredVersion.String(), v.String())
		}

		e.getLogger().WithFields(logrus.Fields{
			fieldEtcdEndpoint: ep,
			"version":         v,
		}).Info("Successfully verified version of etcd endpoint")
	}

	if len(eps) == 0 {
		e.getLogger().Warn("Minimal etcd version unknown: No etcd endpoints available")
	}

	return nil
}

func (e *etcdClient) LockPath(ctx context.Context, path string) (kvLocker, error) {
	select {
	case <-e.firstSession:
	case <-ctx.Done():
		return nil, fmt.Errorf("lock cancelled via context: %s", ctx.Err())
	}

	e.RLock()
	mu := concurrency.NewMutex(e.session, path)
	e.RUnlock()

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	err := mu.Lock(ctx)
	if err != nil {
		return nil, Hint(err)
	}

	return &etcdMutex{mutex: mu}, nil
}

func (e *etcdClient) DeletePrefix(path string) error {
	duration := spanstat.Start()
	e.limiter.Wait(ctx.TODO())
	_, err := e.client.Delete(ctx.Background(), path, client.WithPrefix())
	increaseMetric(path, metricDelete, "DeletePrefix", duration.EndError(err).Total(), err)
	return Hint(err)
}

// Watch starts watching for changes in a prefix
func (e *etcdClient) Watch(w *Watcher) {
	localCache := watcherCache{}
	listSignalSent := false

	scopedLog := e.getLogger().WithFields(logrus.Fields{
		fieldWatcher: w,
		fieldPrefix:  w.prefix,
	})
	<-e.Connected()

reList:
	for {
		e.limiter.Wait(ctx.TODO())
		res, err := e.client.Get(ctx.Background(), w.prefix, client.WithPrefix(),
			client.WithSerializable())
		if err != nil {
			scopedLog.WithError(Hint(err)).Warn("Unable to list keys before starting watcher")
			continue
		}

		nextRev := res.Header.Revision + 1
		scopedLog.Debugf("List response from etcd len=%d: %+v", res.Count, res)

		if res.Count > 0 {
			for _, key := range res.Kvs {
				t := EventTypeCreate
				if localCache.Exists(key.Key) {
					t = EventTypeModify
				}

				localCache.MarkInUse(key.Key)
				scopedLog.Debugf("Emitting list result as %v event for %s=%v", t, key.Key, key.Value)

				queueStart := spanstat.Start()
				w.Events <- KeyValueEvent{
					Key:   string(key.Key),
					Value: key.Value,
					Typ:   t,
				}
				trackEventQueued(string(key.Key), t, queueStart.End(true).Total())
			}
		}

		// More keys to be read, call Get() again
		if res.More {
			continue
		}

		// Send out deletion events for all keys that were deleted
		// between our last known revision and the latest revision
		// received via Get
		localCache.RemoveDeleted(func(k string) {
			event := KeyValueEvent{
				Key: k,
				Typ: EventTypeDelete,
			}

			scopedLog.Debugf("Emitting EventTypeDelete event for %s", k)
			queueStart := spanstat.Start()
			w.Events <- event
			trackEventQueued(k, EventTypeDelete, queueStart.End(true).Total())
		})

		// Only send the list signal once
		if !listSignalSent {
			w.Events <- KeyValueEvent{Typ: EventTypeListDone}
			listSignalSent = true
		}

	recreateWatcher:
		scopedLog.WithField(fieldRev, nextRev).Debug("Starting to watch a prefix")

		e.limiter.Wait(ctx.TODO())
		etcdWatch := e.client.Watch(ctx.Background(), w.prefix,
			client.WithPrefix(), client.WithRev(nextRev))
		for {
			select {
			case <-w.stopWatch:
				close(w.Events)
				w.stopWait.Done()
				return

			case r, ok := <-etcdWatch:
				if !ok {
					time.Sleep(50 * time.Millisecond)
					goto recreateWatcher
				}

				scopedLog := scopedLog.WithField(fieldRev, r.Header.Revision)

				if err := r.Err(); err != nil {
					// We tried to watch on a compacted
					// revision that may no longer exist,
					// recreate the watcher and try to
					// watch on the next possible revision
					if err == v3rpcErrors.ErrCompacted {
						scopedLog.WithError(Hint(err)).Debug("Tried watching on compacted revision")
					}

					// mark all local keys in state for
					// deletion unless the upcoming GET
					// marks them alive
					localCache.MarkAllForDeletion()

					goto reList
				}

				nextRev = r.Header.Revision + 1
				scopedLog.Debugf("Received event from etcd: %+v", r)

				for _, ev := range r.Events {
					event := KeyValueEvent{
						Key:   string(ev.Kv.Key),
						Value: ev.Kv.Value,
					}

					switch {
					case ev.Type == client.EventTypeDelete:
						event.Typ = EventTypeDelete
						localCache.RemoveKey(ev.Kv.Key)
					case ev.IsCreate():
						event.Typ = EventTypeCreate
						localCache.MarkInUse(ev.Kv.Key)
					default:
						event.Typ = EventTypeModify
						localCache.MarkInUse(ev.Kv.Key)
					}

					scopedLog.Debugf("Emitting %v event for %s=%v", event.Typ, event.Key, event.Value)

					queueStart := spanstat.Start()
					w.Events <- event
					trackEventQueued(string(ev.Kv.Key), event.Typ, queueStart.End(true).Total())
				}
			}
		}
	}
}

func (e *etcdClient) determineEndpointStatus(endpointAddress string) (string, error) {
	ctxTimeout, cancel := ctx.WithTimeout(ctx.Background(), statusCheckTimeout)
	defer cancel()

	e.getLogger().Debugf("Checking status to etcd endpoint %s", endpointAddress)

	e.limiter.Wait(ctxTimeout)
	status, err := e.client.Status(ctxTimeout, endpointAddress)
	if err != nil {
		return fmt.Sprintf("%s - %s", endpointAddress, err), Hint(err)
	}

	str := fmt.Sprintf("%s - %s", endpointAddress, status.Version)
	if status.Header.MemberId == status.Leader {
		str += " (Leader)"
	}

	return str, nil
}

func (e *etcdClient) statusChecker() {
	for {
		newStatus := []string{}
		ok := 0

		endpoints := e.client.Endpoints()
		for _, ep := range endpoints {
			st, err := e.determineEndpointStatus(ep)
			if err == nil {
				ok++
			}

			newStatus = append(newStatus, st)
		}

		allConnected := len(endpoints) == ok

		e.statusLock.Lock()
		e.latestStatusSnapshot = fmt.Sprintf("etcd: %d/%d connected: %s", ok, len(endpoints), strings.Join(newStatus, "; "))

		// Only mark the etcd health as unstable if no etcd endpoints can be reached
		if len(endpoints) > 0 && ok == 0 {
			e.latestErrorStatus = fmt.Errorf("Not able to connect to any etcd endpoints")
		} else {
			e.latestErrorStatus = nil
		}

		e.statusLock.Unlock()

		select {
		case <-e.stopStatusChecker:
			return
		case <-time.After(e.extraOptions.StatusCheckInterval(allConnected)):
		}
	}
}

func (e *etcdClient) Status() (string, error) {
	e.statusLock.RLock()
	defer e.statusLock.RUnlock()

	return e.latestStatusSnapshot, Hint(e.latestErrorStatus)
}

// Get returns value of key
func (e *etcdClient) Get(key string) ([]byte, error) {
	duration := spanstat.Start()
	e.limiter.Wait(ctx.TODO())
	getR, err := e.client.Get(ctx.Background(), key)
	increaseMetric(key, metricRead, "Get", duration.EndError(err).Total(), err)
	if err != nil {
		return nil, Hint(err)
	}

	if getR.Count == 0 {
		return nil, nil
	}
	return getR.Kvs[0].Value, nil
}

// GetPrefix returns the first key which matches the prefix
func (e *etcdClient) GetPrefix(ctx context.Context, prefix string) ([]byte, error) {
	duration := spanstat.Start()
	e.limiter.Wait(ctx)
	getR, err := e.client.Get(ctx, prefix, client.WithPrefix())
	increaseMetric(prefix, metricRead, "GetPrefix", duration.EndError(err).Total(), err)
	if err != nil {
		return nil, Hint(err)
	}

	if getR.Count == 0 {
		return nil, nil
	}
	return getR.Kvs[0].Value, nil
}

// Set sets value of key
func (e *etcdClient) Set(key string, value []byte) error {
	duration := spanstat.Start()
	e.limiter.Wait(ctx.TODO())
	_, err := e.client.Put(ctx.Background(), key, string(value))
	increaseMetric(key, metricSet, "Set", duration.EndError(err).Total(), err)
	return Hint(err)
}

// Delete deletes a key
func (e *etcdClient) Delete(key string) error {
	duration := spanstat.Start()
	e.limiter.Wait(ctx.TODO())
	_, err := e.client.Delete(ctx.Background(), key)
	increaseMetric(key, metricDelete, "Delete", duration.EndError(err).Total(), err)
	return Hint(err)
}

func (e *etcdClient) createOpPut(key string, value []byte, leaseID client.LeaseID) *client.Op {
	if leaseID != 0 {
		op := client.OpPut(key, string(value), client.WithLease(leaseID))
		return &op
	}

	op := client.OpPut(key, string(value))
	return &op
}

// Update creates or updates a key
func (e *etcdClient) Update(ctx context.Context, key string, value []byte, lease bool) error {
	select {
	case <-e.firstSession:
	case <-ctx.Done():
		return fmt.Errorf("update cancelled via context: %s", ctx.Err())
	}

	if lease {
		duration := spanstat.Start()
		leaseID := e.GetLeaseID()
		e.limiter.Wait(ctx)
		_, err := e.client.Put(ctx, key, string(value), client.WithLease(leaseID))
		e.checkSession(err, leaseID)
		increaseMetric(key, metricSet, "Update", duration.EndError(err).Total(), err)
		return Hint(err)
	}

	duration := spanstat.Start()
	e.limiter.Wait(ctx)
	_, err := e.client.Put(ctx, key, string(value))
	increaseMetric(key, metricSet, "Update", duration.EndError(err).Total(), err)
	return Hint(err)
}

// CreateOnly creates a key with the value and will fail if the key already exists
func (e *etcdClient) CreateOnly(ctx context.Context, key string, value []byte, lease bool) error {
	duration := spanstat.Start()
	var leaseID client.LeaseID
	if lease {
		leaseID = e.GetLeaseID()
	}
	req := e.createOpPut(key, value, leaseID)
	cond := client.Compare(client.Version(key), "=", 0)

	e.limiter.Wait(ctx)
	txnresp, err := e.client.Txn(ctx).If(cond).Then(*req).Commit()
	increaseMetric(key, metricSet, "CreateOnly", duration.EndError(err).Total(), err)
	if err != nil {
		e.checkSession(err, leaseID)
		return Hint(err)
	}

	if txnresp.Succeeded == false {
		return fmt.Errorf("create was unsuccessful")
	}

	return nil
}

// CreateIfExists creates a key with the value only if key condKey exists
func (e *etcdClient) CreateIfExists(condKey, key string, value []byte, lease bool) error {
	duration := spanstat.Start()
	var leaseID client.LeaseID
	if lease {
		leaseID = e.GetLeaseID()
	}
	req := e.createOpPut(key, value, leaseID)
	cond := client.Compare(client.Version(condKey), "!=", 0)

	e.limiter.Wait(ctx.TODO())
	txnresp, err := e.client.Txn(ctx.TODO()).If(cond).Then(*req).Commit()
	increaseMetric(key, metricSet, "CreateIfExists", duration.EndError(err).Total(), err)
	if err != nil {
		e.checkSession(err, leaseID)
		return Hint(err)
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
	duration := spanstat.Start()

	e.limiter.Wait(ctx.TODO())
	getR, err := e.client.Get(ctx.Background(), prefix, client.WithPrefix())
	increaseMetric(prefix, metricRead, "ListPrefix", duration.EndError(err).Total(), err)
	if err != nil {
		return nil, Hint(err)
	}

	pairs := KeyValuePairs{}
	for i := int64(0); i < getR.Count; i++ {
		pairs[string(getR.Kvs[i].Key)] = getR.Kvs[i].Value

	}

	return pairs, nil
}

// Close closes the etcd session
func (e *etcdClient) Close() {
	close(e.stopStatusChecker)
	<-e.firstSession
	if e.controllers != nil {
		e.controllers.RemoveAll()
	}
	e.RLock()
	defer e.RUnlock()
	e.session.Close()
	e.client.Close()
}

// GetCapabilities returns the capabilities of the backend
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

// ListAndWatch implements the BackendOperations.ListAndWatch using etcd
func (e *etcdClient) ListAndWatch(name, prefix string, chanSize int) *Watcher {
	w := newWatcher(name, prefix, chanSize)

	e.getLogger().WithField(fieldWatcher, w).Debug("Starting watcher...")

	go e.Watch(w)

	return w
}

// IsEtcdOperator returns true if the configuration is setting up an
// etcd-operator and false otherwise.
func IsEtcdOperator(selectedBackend string, opts map[string]string, k8sNamespace string) bool {
	if selectedBackend != EtcdBackendName {
		return false
	}

	fqdnIsEtcdOperator := func(address string) bool {
		u, err := url.Parse(address)
		if err != nil {
			return false
		}
		// typical service name "cilium-etcd-client.kube-system.svc"
		names := strings.Split(u.Hostname(), ".")
		return len(names) >= 2 &&
			names[0] == "cilium-etcd-client" &&
			names[1] == k8sNamespace
	}

	fqdn := opts[addrOption]
	if len(fqdn) != 0 {
		return fqdnIsEtcdOperator(fqdn)
	}

	bm := newEtcdModule()
	err := bm.setConfig(opts)
	if err != nil {
		return false
	}
	etcdConfig := bm.getConfig()[EtcdOptionConfig]
	if len(etcdConfig) == 0 {
		return false
	}

	cfg, err := clientyaml.NewConfig(etcdConfig)
	if err != nil {
		log.WithError(err).Error("Unable to read etcd configuration.")
		return false
	}
	for _, endpoint := range cfg.Endpoints {
		if fqdnIsEtcdOperator(endpoint) {
			return true
		}
	}

	return false
}
