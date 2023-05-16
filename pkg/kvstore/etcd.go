// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blang/semver/v4"
	"github.com/sirupsen/logrus"
	"go.etcd.io/etcd/api/v3/mvccpb"
	v3rpcErrors "go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	"go.etcd.io/etcd/client/pkg/v3/tlsutil"
	client "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
	clientyaml "go.etcd.io/etcd/client/v3/yaml"
	"golang.org/x/time/rate"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/contexthelpers"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rand"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/versioncheck"
)

const (
	// EtcdBackendName is the backend name for etcd
	EtcdBackendName = "etcd"

	EtcdAddrOption               = "etcd.address"
	isEtcdOperatorOption         = "etcd.operator"
	EtcdOptionConfig             = "etcd.config"
	EtcdOptionKeepAliveHeartbeat = "etcd.keepaliveHeartbeat"
	EtcdOptionKeepAliveTimeout   = "etcd.keepaliveTimeout"

	// EtcdRateLimitOption specifies maximum kv operations per second
	EtcdRateLimitOption = "etcd.qps"

	// EtcdListLimitOption limits the number of results retrieved in one batch
	// by ListAndWatch operations. A 0 value equals to no limit.
	EtcdListLimitOption = "etcd.limit"

	minRequiredVersionStr = ">=3.1.0"

	etcdSessionRenewNamePrefix     = "kvstore-etcd-session-renew"
	etcdLockSessionRenewNamePrefix = "kvstore-etcd-lock-session-renew"
)

var (
	// ErrLockLeaseExpired is an error whenever the lease of the lock does not
	// exist or it was expired.
	ErrLockLeaseExpired = errors.New("transaction did not succeed: lock lease expired")

	randGen = rand.NewSafeRand(time.Now().UnixNano())
)

type etcdModule struct {
	opts   backendOptions
	config *client.Config
}

// versionCheckTimeout is the time we wait trying to verify the version
// of an etcd endpoint. The timeout can be encountered on network
// connectivity problems.
const versionCheckTimeout = 30 * time.Second

var (
	// statusCheckTimeout is the timeout when performing status checks with
	// all etcd endpoints
	statusCheckTimeout = 10 * time.Second

	// initialConnectionTimeout  is the timeout for the initial connection to
	// the etcd server
	initialConnectionTimeout = 15 * time.Minute

	minRequiredVersion = versioncheck.MustCompile(minRequiredVersionStr)

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
			isEtcdOperatorOption: &backendOption{
				description: "if the configuration is setting up an etcd-operator",
			},
			EtcdAddrOption: &backendOption{
				description: "Addresses of etcd cluster",
			},
			EtcdOptionConfig: &backendOption{
				description: "Path to etcd configuration file",
			},
			EtcdOptionKeepAliveTimeout: &backendOption{
				description: "Timeout after which an unanswered heartbeat triggers the connection to be closed",
				validate: func(v string) error {
					_, err := time.ParseDuration(v)
					return err
				},
			},
			EtcdOptionKeepAliveHeartbeat: &backendOption{
				description: "Heartbeat interval to keep gRPC connection alive",
				validate: func(v string) error {
					_, err := time.ParseDuration(v)
					return err
				},
			},
			EtcdRateLimitOption: &backendOption{
				description: "Rate limit in kv store operations per second",
				validate: func(v string) error {
					_, err := strconv.Atoi(v)
					return err
				},
			},
			EtcdListLimitOption: &backendOption{
				description: "Max number of results retrieved in one batch by ListAndWatch operations (0 = no limit)",
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

func shuffleEndpoints(endpoints []string) {
	randGen.Shuffle(len(endpoints), func(i, j int) {
		endpoints[i], endpoints[j] = endpoints[j], endpoints[i]
	})
}

type clientOptions struct {
	KeepAliveHeartbeat time.Duration
	KeepAliveTimeout   time.Duration
	RateLimit          int
	ListBatchSize      int
}

func (e *etcdModule) newClient(ctx context.Context, opts *ExtraOptions) (BackendOperations, chan error) {
	errChan := make(chan error, 10)

	clientOptions := clientOptions{
		KeepAliveHeartbeat: 15 * time.Second,
		KeepAliveTimeout:   25 * time.Second,
		RateLimit:          defaults.KVstoreQPS,
		ListBatchSize:      256,
	}

	if o, ok := e.opts[EtcdRateLimitOption]; ok && o.value != "" {
		clientOptions.RateLimit, _ = strconv.Atoi(o.value)
	}

	if o, ok := e.opts[EtcdListLimitOption]; ok && o.value != "" {
		clientOptions.ListBatchSize, _ = strconv.Atoi(o.value)
	}

	if o, ok := e.opts[EtcdOptionKeepAliveTimeout]; ok && o.value != "" {
		clientOptions.KeepAliveTimeout, _ = time.ParseDuration(o.value)
	}

	if o, ok := e.opts[EtcdOptionKeepAliveHeartbeat]; ok && o.value != "" {
		clientOptions.KeepAliveHeartbeat, _ = time.ParseDuration(o.value)
	}

	endpointsOpt, endpointsSet := e.opts[EtcdAddrOption]
	configPathOpt, configSet := e.opts[EtcdOptionConfig]

	var configPath string
	if configSet {
		configPath = configPathOpt.value
	}
	if e.config == nil {
		if !endpointsSet && !configSet {
			errChan <- fmt.Errorf("invalid etcd configuration, %s or %s must be specified", EtcdOptionConfig, EtcdAddrOption)
			close(errChan)
			return nil, errChan
		}

		if endpointsOpt.value == "" && configPath == "" {
			errChan <- fmt.Errorf("invalid etcd configuration, %s or %s must be specified",
				EtcdOptionConfig, EtcdAddrOption)
			close(errChan)
			return nil, errChan
		}

		e.config = &client.Config{}
	}

	if e.config.Endpoints == nil && endpointsSet {
		e.config.Endpoints = []string{endpointsOpt.value}
	}

	log.WithFields(logrus.Fields{
		"ConfigPath":         configPath,
		"KeepAliveHeartbeat": clientOptions.KeepAliveHeartbeat,
		"KeepAliveTimeout":   clientOptions.KeepAliveTimeout,
		"RateLimit":          clientOptions.RateLimit,
		"ListLimit":          clientOptions.ListBatchSize,
	}).Info("Creating etcd client")

	for {
		// connectEtcdClient will close errChan when the connection attempt has
		// been successful
		backend, err := connectEtcdClient(ctx, e.config, configPath, errChan, clientOptions, opts)
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

	if duration := os.Getenv("CILIUM_ETCD_STATUS_CHECK_INTERVAL"); duration != "" {
		timeout, err := time.ParseDuration(duration)
		if err == nil {
			statusCheckTimeout = timeout
		}
	}
}

// Hint tries to improve the error message displayed to te user.
func Hint(err error) error {
	switch err {
	case context.DeadlineExceeded:
		return fmt.Errorf("etcd client timeout exceeded")
	default:
		return err
	}
}

type etcdClient struct {
	// firstSession is a channel that will be closed once the first session
	// is set up in the etcd client. If an error occurred and the initial
	// session cannot be established, the error is provided via the
	// channel.
	firstSession chan struct{}

	// stopStatusChecker is closed when the status checker can be terminated
	stopStatusChecker chan struct{}

	client      *client.Client
	controllers *controller.Manager

	// config and configPath are initialized once and never written to again, they can be accessed without locking
	config     *client.Config
	configPath string

	// statusCheckErrors receives all errors reported by statusChecker()
	statusCheckErrors chan error

	// protects all sessions and sessionErr from concurrent access
	lock.RWMutex

	sessionErr    error
	session       *concurrency.Session
	sessionCancel context.CancelFunc

	lockSession       *concurrency.Session
	lockSessionCancel context.CancelFunc

	// statusLock protects latestStatusSnapshot and latestErrorStatus for
	// read/write access
	statusLock lock.RWMutex

	// latestStatusSnapshot is a snapshot of the latest etcd cluster status
	latestStatusSnapshot string

	// latestErrorStatus is the latest error condition of the etcd connection
	latestErrorStatus error

	extraOptions *ExtraOptions

	limiter       *rate.Limiter
	listBatchSize int

	lastHeartbeat time.Time
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

func (e *etcdMutex) Unlock(ctx context.Context) error {
	return e.mutex.Unlock(ctx)
}

func (e *etcdMutex) Comparator() interface{} {
	return e.mutex.IsOwner()
}

// GetSessionLeaseID returns the current lease ID.
func (e *etcdClient) GetSessionLeaseID() client.LeaseID {
	e.RWMutex.RLock()
	l := e.session.Lease()
	e.RWMutex.RUnlock()
	return l
}

// StatusCheckErrors returns a channel which receives status check errors
func (e *etcdClient) StatusCheckErrors() <-chan error {
	return e.statusCheckErrors
}

// GetLockSessionLeaseID returns the current lease ID for the lock session.
func (e *etcdClient) GetLockSessionLeaseID() client.LeaseID {
	e.RWMutex.RLock()
	l := e.lockSession.Lease()
	e.RWMutex.RUnlock()
	return l
}

// checkSession verifies if the lease is still valid from the return error of
// an etcd API call. If the error explicitly states that a lease was not found
// we mark the session has an orphan for this etcd client. If we would not mark
// it as an Orphan() the session would be considered expired after the leaseTTL
// By make it orphan we guarantee the session will be marked to be renewed.
func (e *etcdClient) checkSession(err error, leaseID client.LeaseID) {
	if errors.Is(err, v3rpcErrors.ErrLeaseNotFound) {
		e.closeSession(leaseID)
	}
}

// checkSession verifies if the lease is still valid from the return error of
// an etcd API call. If the error explicitly states that a lease was not found
// we mark the session has an orphan for this etcd client. If we would not mark
// it as an Orphan() the session would be considered expired after the leaseTTL
// By make it orphan we guarantee the session will be marked to be renewed.
func (e *etcdClient) checkLockSession(err error, leaseID client.LeaseID) {
	if errors.Is(err, v3rpcErrors.ErrLeaseNotFound) {
		e.closeLockSession(leaseID)
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

// closeSession closes the current session.
func (e *etcdClient) closeLockSession(leaseID client.LeaseID) {
	e.RWMutex.RLock()
	// only mark a session as orphan if the leaseID is the same as the
	// session ID to avoid making any other sessions as orphan.
	if e.lockSession.Lease() == leaseID {
		e.lockSession.Orphan()
	}
	e.RWMutex.RUnlock()
}

func (e *etcdClient) waitForInitLock(ctx context.Context) <-chan error {
	initLockSucceeded := make(chan error)

	go func() {
		for {
			select {
			case <-e.client.Ctx().Done():
				initLockSucceeded <- fmt.Errorf("client context ended: %w", e.client.Ctx().Err())
				close(initLockSucceeded)
				return
			case <-ctx.Done():
				initLockSucceeded <- fmt.Errorf("caller context ended: %w", ctx.Err())
				close(initLockSucceeded)
				return
			default:
			}

			if e.extraOptions != nil && e.extraOptions.NoLockQuorumCheck {
				close(initLockSucceeded)
				return
			}

			// Generate a random number so that we can acquire a lock even
			// if other agents are killed while locking this path.
			randNumber := strconv.FormatUint(randGen.Uint64(), 16)
			locker, err := e.LockPath(ctx, InitLockPath+"/"+randNumber)
			if err == nil {
				locker.Unlock(context.Background())
				close(initLockSucceeded)
				e.getLogger().Debug("Distributed lock successful, etcd has quorum")
				return
			}

			time.Sleep(100 * time.Millisecond)
		}
	}()

	return initLockSucceeded
}

func (e *etcdClient) isConnectedAndHasQuorum(ctx context.Context) error {
	ctxTimeout, cancel := context.WithTimeout(ctx, statusCheckTimeout)
	defer cancel()

	select {
	// Wait for the the initial connection to be established
	case <-e.firstSession:
		if err := e.sessionError(); err != nil {
			return err
		}
	// Client is closing
	case <-e.client.Ctx().Done():
		return fmt.Errorf("client is closing")
	// Timeout while waiting for initial connection, no success
	case <-ctxTimeout.Done():
		recordQuorumError("timeout")
		return fmt.Errorf("timeout while waiting for initial connection")
	}

	e.RLock()
	ch := e.session.Done()
	e.RUnlock()

	initLockSucceeded := e.waitForInitLock(ctxTimeout)
	select {
	// Catch disconnect event, no success
	case <-ch:
		recordQuorumError("session timeout")
		return fmt.Errorf("etcd session ended")
	// wait for initial lock to succeed
	case err := <-initLockSucceeded:
		if err != nil {
			recordQuorumError("lock timeout")
			return fmt.Errorf("unable to acquire lock: %w", err)
		}

		return nil
	}
}

// Connected closes the returned channel when the etcd client is connected. If
// the context is cancelled or if the etcd client is closed, an error is
// returned on the channel.
func (e *etcdClient) Connected(ctx context.Context) <-chan error {
	out := make(chan error)
	go func() {
		defer close(out)
		for {
			select {
			case <-e.client.Ctx().Done():
				out <- fmt.Errorf("etcd client context ended")
				return
			case <-ctx.Done():
				out <- ctx.Err()
				return
			default:
			}
			if e.isConnectedAndHasQuorum(ctx) == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	return out
}

// Disconnected closes the returned channel when the etcd client is
// disconnected after being reconnected. Blocks until the etcd client is first
// connected with the kvstore.
func (e *etcdClient) Disconnected() <-chan struct{} {
	<-e.firstSession
	e.RLock()
	ch := e.session.Done()
	e.RUnlock()
	return ch
}

func (e *etcdClient) renewSession(ctx context.Context) error {
	if err := e.waitForInitialSession(ctx); err != nil {
		return err
	}

	e.RLock()
	sessionChan := e.session.Done()
	e.RUnlock()

	select {
	// session has ended
	case <-sessionChan:
	// controller has stopped or etcd client is closing
	case <-ctx.Done():
		return nil
	}
	// This is an attempt to avoid concurrent access of a session that was
	// already expired. It's not perfect as there is still a period between the
	// e.session.Done() is closed and the e.Lock() is held where parallel go
	// routines can get a lease ID of an already expired lease.
	e.Lock()

	// Cancel any eventual old session context
	if e.sessionCancel != nil {
		e.sessionCancel()
		e.sessionCancel = nil
	}

	// Create a context representing the lifetime of the session. It will
	// timeout if the session creation does not succeed in time and then
	// persists until any of the below conditions are met:
	//  - The parent context is cancelled due to the etcd client closing or
	//    the controller being shut down
	//  - The above call to sessionCancel() cancels the session due to the
	//  session ending and requiring renewal.
	sessionContext, sessionCancel, sessionSuccess := contexthelpers.NewConditionalTimeoutContext(ctx, statusCheckTimeout)
	defer close(sessionSuccess)

	newSession, err := concurrency.NewSession(
		e.client,
		concurrency.WithTTL(int(option.Config.KVstoreLeaseTTL.Seconds())),
		concurrency.WithContext(sessionContext),
	)
	if err != nil {
		e.UnlockIgnoreTime()
		return fmt.Errorf("unable to renew etcd session: %s", err)
	}
	sessionSuccess <- true
	log.Infof("Got new lease ID %x and the session TTL is %s", newSession.Lease(), option.Config.KVstoreLeaseTTL)

	e.session = newSession
	e.sessionCancel = sessionCancel
	e.UnlockIgnoreTime()

	e.getLogger().WithField(fieldSession, newSession).Debug("Renewing etcd session")

	if err := e.checkMinVersion(ctx, versionCheckTimeout); err != nil {
		return err
	}

	return nil
}

func (e *etcdClient) renewLockSession(ctx context.Context) error {
	if err := e.waitForInitialSession(ctx); err != nil {
		return err
	}

	e.RWMutex.RLock()
	lockSessionChan := e.lockSession.Done()
	e.RWMutex.RUnlock()

	select {
	// session has ended
	case <-lockSessionChan:
	// controller has stopped or etcd client is closing
	case <-ctx.Done():
		return nil
	}
	// This is an attempt to avoid concurrent access of a session that was
	// already expired. It's not perfect as there is still a period between the
	// e.lockSession.Done() is closed and the e.Lock() is held where parallel go
	// routines can get a lease ID of an already expired lease.
	e.Lock()

	if e.lockSessionCancel != nil {
		e.lockSessionCancel()
		e.lockSessionCancel = nil
	}

	// Create a context representing the lifetime of the lock session. It
	// will timeout if the session creation does not succeed in time and
	// persists until any of the below conditions are met:
	//  - The parent context is cancelled due to the etcd client closing or
	//    the controller being shut down
	//  - The above call to sessionCancel() cancels the session due to the
	//  session ending and requiring renewal.
	sessionContext, sessionCancel, sessionSuccess := contexthelpers.NewConditionalTimeoutContext(ctx, statusCheckTimeout)
	defer close(sessionSuccess)

	newSession, err := concurrency.NewSession(
		e.client,
		concurrency.WithTTL(int(defaults.LockLeaseTTL.Seconds())),
		concurrency.WithContext(sessionContext),
	)
	if err != nil {
		e.UnlockIgnoreTime()
		return fmt.Errorf("unable to renew etcd lock session: %s", err)
	}
	sessionSuccess <- true
	log.Infof("Got new lock lease ID %x", newSession.Lease())

	e.lockSession = newSession
	e.lockSessionCancel = sessionCancel
	e.UnlockIgnoreTime()

	e.getLogger().WithField(fieldSession, newSession).Debug("Renewing etcd lock session")

	return nil
}

func connectEtcdClient(ctx context.Context, config *client.Config, cfgPath string, errChan chan error, clientOptions clientOptions, opts *ExtraOptions) (BackendOperations, error) {
	if cfgPath != "" {
		cfg, err := newConfig(cfgPath)
		if err != nil {
			return nil, err
		}
		if cfg.TLS != nil {
			cfg.TLS.GetClientCertificate, err = getClientCertificateReloader(cfgPath)
			if err != nil {
				return nil, err
			}
		}
		cfg.DialOptions = append(cfg.DialOptions, config.DialOptions...)
		config = cfg
	}

	// Shuffle the order of endpoints to avoid all agents connecting to the
	// same etcd endpoint and to work around etcd client library failover
	// bugs. (https://github.com/etcd-io/etcd/pull/9860)
	if config.Endpoints != nil {
		shuffleEndpoints(config.Endpoints)
	}

	// Set client context so that client can be cancelled from outside
	config.Context = ctx
	// Set DialTimeout to 0, otherwise the creation of a new client will
	// block until DialTimeout is reached or a connection to the server
	// is made.
	config.DialTimeout = 0
	// Ping the server to verify if the server connection is still valid
	config.DialKeepAliveTime = clientOptions.KeepAliveHeartbeat
	// Timeout if the server does not reply within 15 seconds and close the
	// connection. Ideally it should be lower than staleLockTimeout
	config.DialKeepAliveTimeout = clientOptions.KeepAliveTimeout
	c, err := client.New(*config)
	if err != nil {
		return nil, err
	}

	log.WithFields(logrus.Fields{
		"endpoints": config.Endpoints,
		"config":    cfgPath,
	}).Info("Connecting to etcd server...")

	var s, ls concurrency.Session
	errorChan := make(chan error)

	ec := &etcdClient{
		client:               c,
		config:               config,
		configPath:           cfgPath,
		session:              &s,
		lockSession:          &ls,
		firstSession:         make(chan struct{}),
		controllers:          controller.NewManager(),
		latestStatusSnapshot: "Waiting for initial connection to be established",
		stopStatusChecker:    make(chan struct{}),
		extraOptions:         opts,
		limiter:              rate.NewLimiter(rate.Limit(clientOptions.RateLimit), clientOptions.RateLimit),
		listBatchSize:        clientOptions.ListBatchSize,
		statusCheckErrors:    make(chan error, 128),
	}

	// create session in parallel as this is a blocking operation
	go func() {
		session, err := concurrency.NewSession(c, concurrency.WithTTL(int(option.Config.KVstoreLeaseTTL.Seconds())))
		if err != nil {
			errorChan <- err
			close(errorChan)
			return
		}
		lockSession, err := concurrency.NewSession(c, concurrency.WithTTL(int(defaults.LockLeaseTTL.Seconds())))
		if err != nil {
			errorChan <- err
			close(errorChan)
			return
		}

		ec.RWMutex.Lock()
		s = *session
		ls = *lockSession
		ec.RWMutex.Unlock()

		log.Infof("Got lease ID %x and the session TTL is %s", s.Lease(), option.Config.KVstoreLeaseTTL)
		log.Infof("Got lock lease ID %x", ls.Lease())
		close(errorChan)
	}()

	handleSessionError := func(err error) {
		ec.RWMutex.Lock()
		ec.sessionErr = err
		ec.RWMutex.Unlock()
		errChan <- err
	}

	// wait for session to be created also in parallel
	go func() {
		defer close(errChan)
		defer close(ec.firstSession)

		select {
		case err = <-errorChan:
			if err != nil {
				handleSessionError(err)
				return
			}
		case <-time.After(initialConnectionTimeout):
			handleSessionError(fmt.Errorf("timed out while waiting for etcd session. Ensure that etcd is running on %s", config.Endpoints))
			return
		}

		ec.getLogger().Info("Initial etcd session established")

		if err := ec.checkMinVersion(ctx, versionCheckTimeout); err != nil {
			handleSessionError(fmt.Errorf("unable to validate etcd version: %s", err))
		}
	}()

	go func() {
		watcher := ec.ListAndWatch(ctx, HeartbeatPath, HeartbeatPath, 128)

		for {
			select {
			case _, ok := <-watcher.Events:
				if !ok {
					log.Debug("Stopping heartbeat watcher")
					watcher.Stop()
					return
				}

				// It is tempting to compare against the
				// heartbeat value stored in the key. However,
				// this would require the time on all nodes to
				// be synchronized. Instead, assume current
				// time and print the heartbeat value in debug
				// messages for troubleshooting
				ec.RWMutex.Lock()
				ec.lastHeartbeat = time.Now()
				ec.RWMutex.Unlock()
				log.Debug("Received update notification of heartbeat")
			case <-ctx.Done():
				return
			}
		}
	}()

	go ec.statusChecker()

	ec.controllers.UpdateController(makeSessionName(etcdSessionRenewNamePrefix, opts),
		controller.ControllerParams{
			// Stop controller function when etcd client is terminating
			Context: ec.client.Ctx(),
			DoFunc: func(ctx context.Context) error {
				return ec.renewSession(ctx)
			},
			RunInterval: time.Duration(10) * time.Millisecond,
		},
	)

	ec.controllers.UpdateController(makeSessionName(etcdLockSessionRenewNamePrefix, opts),
		controller.ControllerParams{
			// Stop controller function when etcd client is terminating
			Context: ec.client.Ctx(),
			DoFunc: func(ctx context.Context) error {
				return ec.renewLockSession(ctx)
			},
			RunInterval: time.Duration(10) * time.Millisecond,
		},
	)

	return ec, nil
}

// makeSessionName builds up a session/locksession controller name
// clusterName is expected to be empty for main kvstore connection
func makeSessionName(sessionPrefix string, opts *ExtraOptions) string {
	if opts != nil && opts.ClusterName != "" {
		return fmt.Sprintf("%s-%s", sessionPrefix, opts.ClusterName)
	}
	return sessionPrefix
}

func getEPVersion(ctx context.Context, c client.Maintenance, etcdEP string, timeout time.Duration) (semver.Version, error) {
	ctxTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	sr, err := c.Status(ctxTimeout, etcdEP)
	if err != nil {
		return semver.Version{}, Hint(err)
	}
	v, err := versioncheck.Version(sr.Version)
	if err != nil {
		return semver.Version{}, fmt.Errorf("error parsing server version %q: %s", sr.Version, Hint(err))
	}
	return v, nil
}

func (e *etcdClient) sessionError() (err error) {
	e.RWMutex.RLock()
	err = e.sessionErr
	e.RWMutex.RUnlock()
	return
}

// checkMinVersion checks the minimal version running on etcd cluster.  This
// function should be run whenever the etcd client is connected for the first
// time and whenever the session is renewed.
func (e *etcdClient) checkMinVersion(ctx context.Context, timeout time.Duration) error {
	eps := e.client.Endpoints()

	for _, ep := range eps {
		v, err := getEPVersion(ctx, e.client.Maintenance, ep, timeout)
		if err != nil {
			e.getLogger().WithError(Hint(err)).WithField(fieldEtcdEndpoint, ep).
				Warn("Unable to verify version of etcd endpoint")
			continue
		}

		if !minRequiredVersion(v) {
			return fmt.Errorf("minimal etcd version not met in %q, required: %s, found: %s",
				ep, minRequiredVersionStr, v.String())
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

func (e *etcdClient) waitForInitialSession(ctx context.Context) error {
	select {
	case <-e.firstSession:
		if err := e.sessionError(); err != nil {
			return err
		}
	case <-ctx.Done():
		return fmt.Errorf("interrupt while waiting for initial session to be established: %w", ctx.Err())
	}

	return nil
}

func (e *etcdClient) LockPath(ctx context.Context, path string) (KVLocker, error) {
	if err := e.waitForInitialSession(ctx); err != nil {
		return nil, err
	}

	// Create the context first so that if a connectivity issue causes the
	// RLock acquisition below to block, this timeout will run concurrently
	// with the timeouts in renewSession() rather than running serially.
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	e.RLock()
	mu := concurrency.NewMutex(e.lockSession, path)
	leaseID := e.lockSession.Lease()
	e.RUnlock()

	err := mu.Lock(ctx)
	if err != nil {
		e.checkLockSession(err, leaseID)
		return nil, Hint(err)
	}

	return &etcdMutex{mutex: mu}, nil
}

func (e *etcdClient) DeletePrefix(ctx context.Context, path string) (err error) {
	defer func() { Trace("DeletePrefix", err, logrus.Fields{fieldPrefix: path}) }()

	duration := spanstat.Start()
	e.limiter.Wait(ctx)
	_, err = e.client.Delete(ctx, path, client.WithPrefix())
	increaseMetric(path, metricDelete, "DeletePrefix", duration.EndError(err).Total(), err)
	return Hint(err)
}

// Watch starts watching for changes in a prefix
func (e *etcdClient) Watch(ctx context.Context, w *Watcher) {
	localCache := watcherCache{}
	listSignalSent := false

	defer func() {
		close(w.Events)
		w.stopWait.Done()

		// The watch might be aborted by closing
		// the context instead of calling
		// w.Stop() from outside. In that case
		// we make sure to close everything and
		// as this uses sync.Once it can be
		// run multiple times (if that's the case).
		w.Stop()
	}()

	scopedLog := e.getLogger().WithFields(logrus.Fields{
		fieldWatcher: w,
		fieldPrefix:  w.Prefix,
	})

	err := <-e.Connected(ctx)
	if err != nil {
		// The context ended or the etcd client was closed
		// before connectivity was achieved
		return
	}

	// errLimiter is used to rate limit the retry of the first Get request in case an error
	// has occurred, to prevent overloading the etcd server due to the more aggressive
	// default rate limiter.
	errLimiter := backoff.Exponential{
		Name: "etcd-list-before-watch-error",
		Min:  50 * time.Millisecond,
		Max:  1 * time.Minute,
	}

	if e.extraOptions != nil {
		errLimiter.NodeManager = backoff.NewNodeManager(e.extraOptions.ClusterSizeDependantInterval)
	}

reList:
	for {
		select {
		case <-e.client.Ctx().Done():
			return
		case <-ctx.Done():
			return
		default:
		}

		e.limiter.Wait(ctx)
		kvs, revision, err := e.paginatedList(ctx, scopedLog, w.Prefix)
		if err != nil {
			scopedLog.WithError(Hint(err)).Warn("Unable to list keys before starting watcher")
			errLimiter.Wait(ctx)
			continue
		}
		errLimiter.Reset()

		for _, key := range kvs {
			t := EventTypeCreate
			if localCache.Exists(key.Key) {
				t = EventTypeModify
			}

			localCache.MarkInUse(key.Key)
			scopedLog.Debugf("Emitting list result as %s event for %s=%s", t, key.Key, key.Value)

			queueStart := spanstat.Start()
			w.Events <- KeyValueEvent{
				Key:   string(key.Key),
				Value: key.Value,
				Typ:   t,
			}
			trackEventQueued(string(key.Key), t, queueStart.End(true).Total())
		}

		nextRev := revision + 1

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

		e.limiter.Wait(ctx)
		etcdWatch := e.client.Watch(client.WithRequireLeader(ctx), w.Prefix,
			client.WithPrefix(), client.WithRev(nextRev))
		for {
			select {
			case <-e.client.Ctx().Done():
				return
			case <-ctx.Done():
				return
			case <-w.stopWatch:
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
					if errors.Is(err, v3rpcErrors.ErrCompacted) {
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

					scopedLog.Debugf("Emitting %s event for %s=%s", event.Typ, event.Key, event.Value)

					queueStart := spanstat.Start()
					w.Events <- event
					trackEventQueued(string(ev.Kv.Key), event.Typ, queueStart.End(true).Total())
				}
			}
		}
	}
}

func (e *etcdClient) paginatedList(ctx context.Context, log *logrus.Entry, prefix string) (kvs []*mvccpb.KeyValue, revision int64, err error) {
	start, end := prefix, client.GetPrefixRangeEnd(prefix)

	for {
		res, err := e.client.Get(ctx, start, client.WithRange(end),
			client.WithSort(client.SortByKey, client.SortAscend),
			client.WithRev(revision), client.WithSerializable(),
			client.WithLimit(int64(e.listBatchSize)),
		)
		if err != nil {
			return nil, 0, err
		}

		log.WithFields(logrus.Fields{
			fieldNumEntries:       len(res.Kvs),
			fieldRemainingEntries: res.Count - int64(len(res.Kvs)),
		}).Debug("Received list response from etcd")

		if kvs == nil {
			kvs = make([]*mvccpb.KeyValue, 0, res.Count)
		}

		kvs = append(kvs, res.Kvs...)

		revision = res.Header.Revision
		if !res.More || len(res.Kvs) == 0 {
			return kvs, revision, nil
		}

		start = string(res.Kvs[len(res.Kvs)-1].Key) + "\x00"
	}
}

func (e *etcdClient) determineEndpointStatus(ctx context.Context, endpointAddress string) (string, error) {
	ctxTimeout, cancel := context.WithTimeout(ctx, statusCheckTimeout)
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
	ctx := context.Background()

	consecutiveQuorumErrors := 0

	statusTimer, statusTimerDone := inctimer.New()
	defer statusTimerDone()

	for {
		newStatus := []string{}
		ok := 0

		quorumError := e.isConnectedAndHasQuorum(ctx)

		endpoints := e.client.Endpoints()
		for _, ep := range endpoints {
			st, err := e.determineEndpointStatus(ctx, ep)
			if err == nil {
				ok++
			}

			newStatus = append(newStatus, st)
		}

		allConnected := len(endpoints) == ok

		e.RWMutex.RLock()
		sessionLeaseID := e.session.Lease()
		lockSessionLeaseID := e.lockSession.Lease()
		lastHeartbeat := e.lastHeartbeat
		e.RWMutex.RUnlock()

		if heartbeatDelta := time.Since(lastHeartbeat); !lastHeartbeat.IsZero() && heartbeatDelta > 2*HeartbeatWriteInterval {
			recordQuorumError("no event received")
			quorumError = fmt.Errorf("%s since last heartbeat update has been received", heartbeatDelta)
		}

		quorumString := "true"
		if quorumError != nil {
			quorumString = quorumError.Error()
			consecutiveQuorumErrors++
			quorumString += fmt.Sprintf(", consecutive-errors=%d", consecutiveQuorumErrors)
		} else {
			consecutiveQuorumErrors = 0
		}

		e.statusLock.Lock()

		switch {
		case consecutiveQuorumErrors > option.Config.KVstoreMaxConsecutiveQuorumErrors:
			e.latestErrorStatus = fmt.Errorf("quorum check failed %d times in a row: %s",
				consecutiveQuorumErrors, quorumError)
			e.latestStatusSnapshot = e.latestErrorStatus.Error()
		case len(endpoints) > 0 && ok == 0:
			e.latestErrorStatus = fmt.Errorf("not able to connect to any etcd endpoints")
			e.latestStatusSnapshot = e.latestErrorStatus.Error()
		default:
			e.latestErrorStatus = nil
			e.latestStatusSnapshot = fmt.Sprintf("etcd: %d/%d connected, lease-ID=%x, lock lease-ID=%x, has-quorum=%s: %s",
				ok, len(endpoints), sessionLeaseID, lockSessionLeaseID, quorumString, strings.Join(newStatus, "; "))
		}

		e.statusLock.Unlock()
		if e.latestErrorStatus != nil {
			select {
			case e.statusCheckErrors <- e.latestErrorStatus:
			default:
				// Channel's buffer is full, skip sending errors to the channel but log warnings instead
				log.WithError(e.latestErrorStatus).
					Warning("Status check error channel is full, dropping this error")
			}
		}

		select {
		case <-e.stopStatusChecker:
			close(e.statusCheckErrors)
			return
		case <-statusTimer.After(e.extraOptions.StatusCheckInterval(allConnected)):
		}
	}
}

func (e *etcdClient) Status() (string, error) {
	e.statusLock.RLock()
	defer e.statusLock.RUnlock()

	return e.latestStatusSnapshot, Hint(e.latestErrorStatus)
}

// GetIfLocked returns value of key if the client is still holding the given lock.
func (e *etcdClient) GetIfLocked(ctx context.Context, key string, lock KVLocker) (bv []byte, err error) {
	defer func() { Trace("GetIfLocked", err, logrus.Fields{fieldKey: key, fieldValue: string(bv)}) }()

	duration := spanstat.Start()
	e.limiter.Wait(ctx)
	opGet := client.OpGet(key)
	cmp := lock.Comparator().(client.Cmp)
	txnReply, err := e.client.Txn(ctx).If(cmp).Then(opGet).Commit()
	if err == nil && !txnReply.Succeeded {
		err = ErrLockLeaseExpired
	}
	increaseMetric(key, metricRead, "GetLocked", duration.EndError(err).Total(), err)
	if err != nil {
		return nil, Hint(err)
	}

	getR := txnReply.Responses[0].GetResponseRange()
	// RangeResponse
	if getR.Count == 0 {
		return nil, nil
	}
	return getR.Kvs[0].Value, nil
}

// Get returns value of key
func (e *etcdClient) Get(ctx context.Context, key string) (bv []byte, err error) {
	defer func() { Trace("Get", err, logrus.Fields{fieldKey: key, fieldValue: string(bv)}) }()

	duration := spanstat.Start()
	e.limiter.Wait(ctx)
	getR, err := e.client.Get(ctx, key)
	increaseMetric(key, metricRead, "Get", duration.EndError(err).Total(), err)
	if err != nil {
		return nil, Hint(err)
	}

	if getR.Count == 0 {
		return nil, nil
	}
	return getR.Kvs[0].Value, nil
}

// GetPrefixIfLocked returns the first key which matches the prefix and its value if the client is still holding the given lock.
func (e *etcdClient) GetPrefixIfLocked(ctx context.Context, prefix string, lock KVLocker) (k string, bv []byte, err error) {
	defer func() {
		Trace("GetPrefixIfLocked", err, logrus.Fields{fieldPrefix: prefix, fieldKey: k, fieldValue: string(bv)})
	}()

	duration := spanstat.Start()
	e.limiter.Wait(ctx)
	opGet := client.OpGet(prefix, client.WithPrefix(), client.WithLimit(1))
	cmp := lock.Comparator().(client.Cmp)
	txnReply, err := e.client.Txn(ctx).If(cmp).Then(opGet).Commit()
	if err == nil && !txnReply.Succeeded {
		err = ErrLockLeaseExpired
	}
	increaseMetric(prefix, metricRead, "GetPrefixLocked", duration.EndError(err).Total(), err)
	if err != nil {
		return "", nil, Hint(err)
	}
	getR := txnReply.Responses[0].GetResponseRange()

	if getR.Count == 0 {
		return "", nil, nil
	}
	return string(getR.Kvs[0].Key), getR.Kvs[0].Value, nil
}

// GetPrefix returns the first key which matches the prefix and its value
func (e *etcdClient) GetPrefix(ctx context.Context, prefix string) (k string, bv []byte, err error) {
	defer func() {
		Trace("GetPrefix", err, logrus.Fields{fieldPrefix: prefix, fieldKey: k, fieldValue: string(bv)})
	}()

	duration := spanstat.Start()
	e.limiter.Wait(ctx)
	getR, err := e.client.Get(ctx, prefix, client.WithPrefix(), client.WithLimit(1))
	increaseMetric(prefix, metricRead, "GetPrefix", duration.EndError(err).Total(), err)
	if err != nil {
		return "", nil, Hint(err)
	}

	if getR.Count == 0 {
		return "", nil, nil
	}
	return string(getR.Kvs[0].Key), getR.Kvs[0].Value, nil
}

// Set sets value of key
func (e *etcdClient) Set(ctx context.Context, key string, value []byte) (err error) {
	defer func() { Trace("Set", err, logrus.Fields{fieldKey: key, fieldValue: string(value)}) }()

	duration := spanstat.Start()
	e.limiter.Wait(ctx)
	_, err = e.client.Put(ctx, key, string(value))
	increaseMetric(key, metricSet, "Set", duration.EndError(err).Total(), err)
	return Hint(err)
}

// DeleteIfLocked deletes a key if the client is still holding the given lock.
func (e *etcdClient) DeleteIfLocked(ctx context.Context, key string, lock KVLocker) (err error) {
	defer func() { Trace("DeleteIfLocked", err, logrus.Fields{fieldKey: key}) }()

	duration := spanstat.Start()
	e.limiter.Wait(ctx)
	opDel := client.OpDelete(key)
	cmp := lock.Comparator().(client.Cmp)
	txnReply, err := e.client.Txn(ctx).If(cmp).Then(opDel).Commit()
	if err == nil && !txnReply.Succeeded {
		err = ErrLockLeaseExpired
	}
	increaseMetric(key, metricDelete, "DeleteLocked", duration.EndError(err).Total(), err)
	return Hint(err)
}

// Delete deletes a key
func (e *etcdClient) Delete(ctx context.Context, key string) (err error) {
	defer func() { Trace("Delete", err, logrus.Fields{fieldKey: key}) }()

	duration := spanstat.Start()
	e.limiter.Wait(ctx)
	_, err = e.client.Delete(ctx, key)
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

// UpdateIfLocked updates a key if the client is still holding the given lock.
func (e *etcdClient) UpdateIfLocked(ctx context.Context, key string, value []byte, lease bool, lock KVLocker) error {
	if err := e.waitForInitialSession(ctx); err != nil {
		return err
	}

	var (
		txnReply *client.TxnResponse
		err      error
	)

	duration := spanstat.Start()
	e.limiter.Wait(ctx)
	if lease {
		leaseID := e.GetSessionLeaseID()
		opPut := client.OpPut(key, string(value), client.WithLease(leaseID))
		cmp := lock.Comparator().(client.Cmp)
		txnReply, err = e.client.Txn(ctx).If(cmp).Then(opPut).Commit()
		e.checkSession(err, leaseID)
	} else {
		opPut := client.OpPut(key, string(value))
		cmp := lock.Comparator().(client.Cmp)
		txnReply, err = e.client.Txn(ctx).If(cmp).Then(opPut).Commit()
	}
	if err == nil && !txnReply.Succeeded {
		err = ErrLockLeaseExpired
	}
	increaseMetric(key, metricSet, "UpdateIfLocked", duration.EndError(err).Total(), err)
	return Hint(err)
}

// Update creates or updates a key
func (e *etcdClient) Update(ctx context.Context, key string, value []byte, lease bool) (err error) {
	defer Trace("Update", err, logrus.Fields{fieldKey: key, fieldValue: string(value), fieldAttachLease: lease})

	if err = e.waitForInitialSession(ctx); err != nil {
		return
	}

	if lease {
		duration := spanstat.Start()
		leaseID := e.GetSessionLeaseID()
		e.limiter.Wait(ctx)
		_, err := e.client.Put(ctx, key, string(value), client.WithLease(leaseID))
		e.checkSession(err, leaseID)
		increaseMetric(key, metricSet, "Update", duration.EndError(err).Total(), err)
		return Hint(err)
	}

	duration := spanstat.Start()
	e.limiter.Wait(ctx)
	_, err = e.client.Put(ctx, key, string(value))
	increaseMetric(key, metricSet, "Update", duration.EndError(err).Total(), err)
	return Hint(err)
}

// UpdateIfDifferentIfLocked updates a key if the value is different and if the client is still holding the given lock.
func (e *etcdClient) UpdateIfDifferentIfLocked(ctx context.Context, key string, value []byte, lease bool, lock KVLocker) (recreated bool, err error) {
	defer func() {
		Trace("UpdateIfDifferentIfLocked", err, logrus.Fields{fieldKey: key, fieldValue: value, fieldAttachLease: lease, "recreated": recreated})
	}()

	if err = e.waitForInitialSession(ctx); err != nil {
		return false, err
	}

	duration := spanstat.Start()
	e.limiter.Wait(ctx)
	cnds := lock.Comparator().(client.Cmp)
	txnresp, err := e.client.Txn(ctx).If(cnds).Then(client.OpGet(key)).Commit()

	increaseMetric(key, metricRead, "Get", duration.EndError(err).Total(), err)

	// On error, attempt update blindly
	if err != nil {
		return true, e.UpdateIfLocked(ctx, key, value, lease, lock)
	}

	if !txnresp.Succeeded {
		return false, ErrLockLeaseExpired
	}

	getR := txnresp.Responses[0].GetResponseRange()
	if getR.Count == 0 {
		return true, e.UpdateIfLocked(ctx, key, value, lease, lock)
	}

	if lease {
		leaseID := e.GetSessionLeaseID()
		if getR.Kvs[0].Lease != int64(leaseID) {
			return true, e.UpdateIfLocked(ctx, key, value, lease, lock)
		}
	}
	// if value is not equal then update.
	if !bytes.Equal(getR.Kvs[0].Value, value) {
		return true, e.UpdateIfLocked(ctx, key, value, lease, lock)
	}

	return false, nil
}

// UpdateIfDifferent updates a key if the value is different
func (e *etcdClient) UpdateIfDifferent(ctx context.Context, key string, value []byte, lease bool) (recreated bool, err error) {
	defer func() {
		Trace("UpdateIfDifferent", err, logrus.Fields{fieldKey: key, fieldValue: value, fieldAttachLease: lease, "recreated": recreated})
	}()

	if err = e.waitForInitialSession(ctx); err != nil {
		return false, err
	}

	duration := spanstat.Start()
	e.limiter.Wait(ctx)
	getR, err := e.client.Get(ctx, key)
	increaseMetric(key, metricRead, "Get", duration.EndError(err).Total(), err)
	// On error, attempt update blindly
	if err != nil || getR.Count == 0 {
		return true, e.Update(ctx, key, value, lease)
	}
	if lease {
		leaseID := e.GetSessionLeaseID()
		if getR.Kvs[0].Lease != int64(leaseID) {
			return true, e.Update(ctx, key, value, lease)
		}
	}
	// if value is not equal then update.
	if !bytes.Equal(getR.Kvs[0].Value, value) {
		return true, e.Update(ctx, key, value, lease)
	}

	return false, nil
}

// CreateOnlyIfLocked atomically creates a key if the client is still holding the given lock or fails if it already exists
func (e *etcdClient) CreateOnlyIfLocked(ctx context.Context, key string, value []byte, lease bool, lock KVLocker) (success bool, err error) {
	defer func() {
		Trace("CreateOnlyIfLocked", err, logrus.Fields{fieldKey: key, fieldValue: value, fieldAttachLease: lease, "success": success})
	}()

	duration := spanstat.Start()
	var leaseID client.LeaseID
	if lease {
		leaseID = e.GetSessionLeaseID()
	}
	req := e.createOpPut(key, value, leaseID)
	cnds := []client.Cmp{
		client.Compare(client.Version(key), "=", 0),
		lock.Comparator().(client.Cmp),
	}

	// We need to do a get in the else of the txn to detect if the lock is still
	// valid or not.
	opGets := []client.Op{
		client.OpGet(key),
	}

	e.limiter.Wait(ctx)
	txnresp, err := e.client.Txn(ctx).If(cnds...).Then(*req).Else(opGets...).Commit()
	increaseMetric(key, metricSet, "CreateOnlyLocked", duration.EndError(err).Total(), err)
	if err != nil {
		e.checkSession(err, leaseID)
		return false, Hint(err)
	}

	// The txn can failed for the following reasons:
	//  - Key version is not zero;
	//  - Lock does not exist or is expired.
	// For both of those cases, the key that we are comparing might or not
	// exist, so we have:
	//  A - Key does not exist and lock does not exist => ErrLockLeaseExpired
	//  B - Key does not exist and lock exist => txn should succeed
	//  C - Key does exist, version is == 0 and lock does not exist => ErrLockLeaseExpired
	//  D - Key does exist, version is != 0 and lock does not exist => ErrLockLeaseExpired
	//  E - Key does exist, version is == 0 and lock does exist => txn should succeed
	//  F - Key does exist, version is != 0 and lock does exist => txn fails but returned is nil!

	if !txnresp.Succeeded {
		// case F
		if len(txnresp.Responses[0].GetResponseRange().Kvs) != 0 &&
			txnresp.Responses[0].GetResponseRange().Kvs[0].Version != 0 {
			return false, nil
		}

		// case A, C and D
		return false, ErrLockLeaseExpired
	}

	// case B and E
	return true, nil
}

// CreateOnly creates a key with the value and will fail if the key already exists
func (e *etcdClient) CreateOnly(ctx context.Context, key string, value []byte, lease bool) (success bool, err error) {
	defer func() {
		Trace("CreateOnly", err, logrus.Fields{fieldKey: key, fieldValue: value, fieldAttachLease: lease, "success": success})
	}()

	duration := spanstat.Start()
	var leaseID client.LeaseID
	if lease {
		leaseID = e.GetSessionLeaseID()
	}
	req := e.createOpPut(key, value, leaseID)
	cond := client.Compare(client.Version(key), "=", 0)

	e.limiter.Wait(ctx)
	txnresp, err := e.client.Txn(ctx).If(cond).Then(*req).Commit()
	increaseMetric(key, metricSet, "CreateOnly", duration.EndError(err).Total(), err)
	if err != nil {
		e.checkSession(err, leaseID)
		return false, Hint(err)
	}

	return txnresp.Succeeded, nil
}

// CreateIfExists creates a key with the value only if key condKey exists
func (e *etcdClient) CreateIfExists(ctx context.Context, condKey, key string, value []byte, lease bool) (err error) {
	defer func() {
		Trace("CreateIfExists", err, logrus.Fields{fieldKey: key, fieldValue: string(value), fieldCondition: condKey, fieldAttachLease: lease})
	}()

	duration := spanstat.Start()
	var leaseID client.LeaseID
	if lease {
		leaseID = e.GetSessionLeaseID()
	}
	req := e.createOpPut(key, value, leaseID)
	cond := client.Compare(client.Version(condKey), "!=", 0)

	e.limiter.Wait(ctx)
	txnresp, err := e.client.Txn(ctx).If(cond).Then(*req).Commit()
	increaseMetric(key, metricSet, "CreateIfExists", duration.EndError(err).Total(), err)
	if err != nil {
		e.checkSession(err, leaseID)
		return Hint(err)
	}

	if !txnresp.Succeeded {
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

// ListPrefixIfLocked returns a list of keys matching the prefix only if the client is still holding the given lock.
func (e *etcdClient) ListPrefixIfLocked(ctx context.Context, prefix string, lock KVLocker) (v KeyValuePairs, err error) {
	defer func() { Trace("ListPrefixIfLocked", err, logrus.Fields{fieldPrefix: prefix, fieldNumEntries: len(v)}) }()

	duration := spanstat.Start()
	e.limiter.Wait(ctx)
	opGet := client.OpGet(prefix, client.WithPrefix())
	cmp := lock.Comparator().(client.Cmp)
	txnReply, err := e.client.Txn(ctx).If(cmp).Then(opGet).Commit()
	if err == nil && !txnReply.Succeeded {
		err = ErrLockLeaseExpired
	}
	increaseMetric(prefix, metricRead, "ListPrefixLocked", duration.EndError(err).Total(), err)
	if err != nil {
		return nil, Hint(err)
	}
	getR := txnReply.Responses[0].GetResponseRange()

	pairs := KeyValuePairs(make(map[string]Value, getR.Count))
	for i := int64(0); i < getR.Count; i++ {
		pairs[string(getR.Kvs[i].Key)] = Value{
			Data:        getR.Kvs[i].Value,
			ModRevision: uint64(getR.Kvs[i].ModRevision),
		}

	}

	return pairs, nil
}

// ListPrefix returns a map of matching keys
func (e *etcdClient) ListPrefix(ctx context.Context, prefix string) (v KeyValuePairs, err error) {
	defer func() { Trace("ListPrefix", err, logrus.Fields{fieldPrefix: prefix, fieldNumEntries: len(v)}) }()

	duration := spanstat.Start()

	e.limiter.Wait(ctx)
	getR, err := e.client.Get(ctx, prefix, client.WithPrefix())
	increaseMetric(prefix, metricRead, "ListPrefix", duration.EndError(err).Total(), err)
	if err != nil {
		return nil, Hint(err)
	}

	pairs := KeyValuePairs(make(map[string]Value, getR.Count))
	for i := int64(0); i < getR.Count; i++ {
		pairs[string(getR.Kvs[i].Key)] = Value{
			Data:        getR.Kvs[i].Value,
			ModRevision: uint64(getR.Kvs[i].ModRevision),
			LeaseID:     getR.Kvs[i].Lease,
		}

	}

	return pairs, nil
}

// Close closes the etcd session
func (e *etcdClient) Close(ctx context.Context) {
	close(e.stopStatusChecker)
	sessionErr := e.waitForInitialSession(ctx)
	if e.controllers != nil {
		e.controllers.RemoveAll()
	}
	e.RLock()
	defer e.RUnlock()
	// Only close e.lockSession if the initial session was successful
	if sessionErr == nil {
		if err := e.lockSession.Close(); err != nil {
			e.getLogger().WithError(err).Warning("Failed to revoke lock session while closing etcd client")
		}
	}
	// Only close e.session if the initial session was successful
	if sessionErr == nil {
		if err := e.session.Close(); err != nil {
			e.getLogger().WithError(err).Warning("Failed to revoke main session while closing etcd client")
		}
	}
	if e.client != nil {
		if err := e.client.Close(); err != nil {
			e.getLogger().WithError(err).Warning("Failed to close etcd client")
		}
	}
}

// GetCapabilities returns the capabilities of the backend
func (e *etcdClient) GetCapabilities() Capabilities {
	return Capabilities(CapabilityCreateIfExists)
}

// Encode encodes a binary slice into a character set that the backend supports
func (e *etcdClient) Encode(in []byte) (out string) {
	defer func() { Trace("Encode", nil, logrus.Fields{"in": in, "out": out}) }()
	return string(in)
}

// Decode decodes a key previously encoded back into the original binary slice
func (e *etcdClient) Decode(in string) (out []byte, err error) {
	defer func() { Trace("Decode", err, logrus.Fields{"in": in, "out": out}) }()
	return []byte(in), nil
}

// ListAndWatch implements the BackendOperations.ListAndWatch using etcd
func (e *etcdClient) ListAndWatch(ctx context.Context, name, prefix string, chanSize int) *Watcher {
	w := newWatcher(name, prefix, chanSize)

	e.getLogger().WithField(fieldWatcher, w).Debug("Starting watcher...")

	go e.Watch(ctx, w)

	return w
}

// UserEnforcePresence creates a user in etcd if not already present, and grants the specified roles.
func (e *etcdClient) UserEnforcePresence(ctx context.Context, name string, roles []string) error {
	scopedLog := e.getLogger().WithField(FieldUser, name)

	scopedLog.Debug("Creating user")
	_, err := e.client.Auth.UserAddWithOptions(ctx, name, "", &client.UserAddOptions{NoPassword: true})
	if err != nil {
		if errors.Is(err, v3rpcErrors.ErrUserAlreadyExist) {
			scopedLog.Debug("User already exists")
		} else {
			return err
		}
	}

	for _, role := range roles {
		scopedLog.WithField(FieldRole, role).Debug("Granting role to user")

		_, err := e.client.Auth.UserGrantRole(ctx, name, role)
		if err != nil {
			return err
		}
	}

	return nil
}

// UserEnforcePresence deletes a user from etcd, if present.
func (e *etcdClient) UserEnforceAbsence(ctx context.Context, name string) error {
	scopedLog := e.getLogger().WithField(FieldUser, name)

	scopedLog.Debug("Deleting user")
	_, err := e.client.Auth.UserDelete(ctx, name)
	if err != nil {
		if errors.Is(err, v3rpcErrors.ErrUserNotFound) {
			scopedLog.Debug("User not found")
		} else {
			return err
		}
	}

	return nil
}

// SplitK8sServiceURL returns the service name and namespace for the given address.
// If the given address is not parseable or it is not the format
// '<protocol>://><name>.<namespace>[optional]', returns an error.
func SplitK8sServiceURL(address string) (string, string, error) {
	u, err := url.Parse(address)
	if err != nil {
		return "", "", err
	}
	// typical service name "cilium-etcd-client.kube-system.svc"
	names := strings.Split(u.Hostname(), ".")
	if len(names) >= 2 {
		return names[0], names[1], nil
	}
	return "", "",
		fmt.Errorf("invalid service name. expecting <protocol://><name>.<namespace>[optional], got: %s", address)
}

// IsEtcdOperator returns the service name if the configuration is setting up an
// etcd-operator. If the configuration explicitly states it is configured
// to connect to an etcd operator, e.g. with etcd.operator=true, the returned
// service name is the first found within the configuration specified.
func IsEtcdOperator(selectedBackend string, opts map[string]string, k8sNamespace string) (string, bool) {
	if selectedBackend != EtcdBackendName {
		return "", false
	}

	isEtcdOperator := strings.ToLower(opts[isEtcdOperatorOption]) == "true"

	fqdnIsEtcdOperator := func(address string) bool {
		svcName, ns, err := SplitK8sServiceURL(address)
		return err == nil &&
			svcName == "cilium-etcd-client" &&
			ns == k8sNamespace
	}

	fqdn := opts[EtcdAddrOption]
	if len(fqdn) != 0 {
		if fqdnIsEtcdOperator(fqdn) || isEtcdOperator {
			return fqdn, true
		}
		return "", false
	}

	bm := newEtcdModule()
	err := bm.setConfig(opts)
	if err != nil {
		return "", false
	}
	etcdConfig := bm.getConfig()[EtcdOptionConfig]
	if len(etcdConfig) == 0 {
		return "", false
	}

	cfg, err := newConfig(etcdConfig)
	if err != nil {
		log.WithError(err).Error("Unable to read etcd configuration.")
		return "", false
	}
	for _, endpoint := range cfg.Endpoints {
		if fqdnIsEtcdOperator(endpoint) || isEtcdOperator {
			return endpoint, true
		}
	}

	return "", false
}

// newConfig is a wrapper of clientyaml.NewConfig. Since etcd has deprecated
// the `ca-file` field from yamlConfig in v3.4, the clientyaml.NewConfig won't
// read that field from the etcd configuration file making Cilium fail to
// connect to a TLS-enabled etcd server. Since we should have deprecated the
// usage of this field a long time ago, in this galaxy, we will have this
// wrapper function as a workaround which will still use the `ca-file` field to
// avoid users breaking their connectivity to etcd when upgrading Cilium.
// TODO remove this wrapper in cilium >= 1.8
func newConfig(fpath string) (*client.Config, error) {
	cfg, err := clientyaml.NewConfig(fpath)
	if err != nil {
		return nil, err
	}
	if cfg.TLS == nil || cfg.TLS.RootCAs != nil {
		return cfg, nil
	}

	yc := &yamlConfig{}
	b, err := os.ReadFile(fpath)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(b, yc)
	if err != nil {
		return nil, err
	}
	if yc.InsecureTransport {
		return cfg, nil
	}

	if yc.CAfile != "" {
		cp, err := tlsutil.NewCertPool([]string{yc.CAfile})
		if err != nil {
			return nil, err
		}
		cfg.TLS.RootCAs = cp
	}
	return cfg, nil
}

// reload on-disk certificate and key when needed
func getClientCertificateReloader(fpath string) (func(*tls.CertificateRequestInfo) (*tls.Certificate, error), error) {
	yc := &yamlKeyPairConfig{}
	b, err := os.ReadFile(fpath)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(b, yc)
	if err != nil {
		return nil, err
	}
	if yc.Certfile == "" || yc.Keyfile == "" {
		return nil, nil
	}
	reloader := func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		cer, err := tls.LoadX509KeyPair(yc.Certfile, yc.Keyfile)
		return &cer, err
	}
	return reloader, nil
}

// copy of relevant internal structure fields in go.etcd.io/etcd/clientv3/yaml
// needed to implement certificates reload, not depending on the deprecated
// newconfig/yamlConfig.
type yamlKeyPairConfig struct {
	Certfile string `json:"cert-file"`
	Keyfile  string `json:"key-file"`
}

// copy of the internal structure in github.com/etcd-io/etcd/clientv3/yaml so we
// can still use the `ca-file` field for one more release.
type yamlConfig struct {
	client.Config

	InsecureTransport     bool   `json:"insecure-transport"`
	InsecureSkipTLSVerify bool   `json:"insecure-skip-tls-verify"`
	Certfile              string `json:"cert-file"`
	Keyfile               string `json:"key-file"`
	TrustedCAfile         string `json:"trusted-ca-file"`

	// CAfile is being deprecated. Use 'TrustedCAfile' instead.
	// TODO: deprecate this in v4
	CAfile string `json:"ca-file"`
}
