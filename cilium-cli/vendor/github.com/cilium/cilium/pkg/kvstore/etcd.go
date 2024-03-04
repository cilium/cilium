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

	"github.com/sirupsen/logrus"
	"go.etcd.io/etcd/api/v3/mvccpb"
	v3rpcErrors "go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	"go.etcd.io/etcd/client/pkg/v3/logutil"
	"go.etcd.io/etcd/client/pkg/v3/tlsutil"
	client "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
	clientyaml "go.etcd.io/etcd/client/v3/yaml"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/time/rate"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rand"
	ciliumrate "github.com/cilium/cilium/pkg/rate"
	ciliumratemetrics "github.com/cilium/cilium/pkg/rate/metrics"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/time"
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

	// EtcdMaxInflightOption specifies maximum inflight concurrent kv store operations
	EtcdMaxInflightOption = "etcd.maxInflight"

	// EtcdListLimitOption limits the number of results retrieved in one batch
	// by ListAndWatch operations. A 0 value equals to no limit.
	EtcdListLimitOption = "etcd.limit"

	// etcdMaxKeysPerLease is the maximum number of keys that can be attached to a lease
	etcdMaxKeysPerLease = 1000
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

var (
	// statusCheckTimeout is the timeout when performing status checks with
	// all etcd endpoints
	statusCheckTimeout = 10 * time.Second

	// initialConnectionTimeout  is the timeout for the initial connection to
	// the etcd server
	initialConnectionTimeout = 15 * time.Minute

	// etcdDummyAddress can be overwritten from test invokers using ldflags
	etcdDummyAddress = "http://127.0.0.1:4002"

	etcdInstance = newEtcdModule()

	// etcd3ClientLogger is the logger used for the underlying etcd clients. We
	// explicitly initialize a logger and propagate it to prevent each client from
	// automatically creating a new one, which comes with a significant memory cost.
	etcd3ClientLogger *zap.Logger
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
			EtcdMaxInflightOption: &backendOption{
				description: "Maximum inflight concurrent kv store operations; defaults to etcd.qps if unset",
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
	MaxInflight        int
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

	if o, ok := e.opts[EtcdMaxInflightOption]; ok && o.value != "" {
		clientOptions.MaxInflight, _ = strconv.Atoi(o.value)
	}

	if clientOptions.MaxInflight == 0 {
		clientOptions.MaxInflight = clientOptions.RateLimit
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
		"MaxInflight":        clientOptions.MaxInflight,
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

	// Initialize the etcd client logger.
	l, err := logutil.CreateDefaultZapLogger(etcdClientDebugLevel())
	if err != nil {
		log.WithError(err).Warning("Failed to initialize etcd client logger")
		l = zap.NewNop()
	}
	etcd3ClientLogger = l.Named("etcd-client")
}

// etcdClientDebugLevel translates ETCD_CLIENT_DEBUG into zap log level.
// This is a copy of a private etcd client function:
// https://github.com/etcd-io/etcd/blob/v3.5.9/client/v3/logger.go#L47-L59
func etcdClientDebugLevel() zapcore.Level {
	envLevel := os.Getenv("ETCD_CLIENT_DEBUG")
	if envLevel == "" || envLevel == "true" {
		return zapcore.InfoLevel
	}
	var l zapcore.Level
	if err := l.Set(envLevel); err != nil {
		log.Warning("Invalid value for environment variable 'ETCD_CLIENT_DEBUG'. Using default level: 'info'")
		return zapcore.InfoLevel
	}
	return l
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

	client *client.Client

	// config and configPath are initialized once and never written to again, they can be accessed without locking
	config     *client.Config
	configPath string

	// statusCheckErrors receives all errors reported by statusChecker()
	statusCheckErrors chan error

	// protects all sessions and sessionErr from concurrent access
	lock.RWMutex

	sessionErr error

	// leaseManager manages the acquisition of etcd leases for generic purposes
	leaseManager *etcdLeaseManager
	// lockLeaseManager manages the acquisition of etcd leases for locking
	// purposes, associated with a shorter TTL
	lockLeaseManager *etcdLeaseManager

	// statusLock protects latestStatusSnapshot and latestErrorStatus for
	// read/write access
	statusLock lock.RWMutex

	// latestStatusSnapshot is a snapshot of the latest etcd cluster status
	latestStatusSnapshot string

	// latestErrorStatus is the latest error condition of the etcd connection
	latestErrorStatus error

	extraOptions *ExtraOptions

	limiter       *ciliumrate.APILimiter
	listBatchSize int

	lastHeartbeat time.Time

	leaseExpiredObservers lock.Map[string, func(string)]

	// logger is the scoped logger associated with this client
	logger logrus.FieldLogger
}

type etcdMutex struct {
	mutex    *concurrency.Mutex
	onUnlock func()
}

func (e *etcdMutex) Unlock(ctx context.Context) error {
	e.onUnlock()
	return e.mutex.Unlock(ctx)
}

func (e *etcdMutex) Comparator() interface{} {
	return e.mutex.IsOwner()
}

// StatusCheckErrors returns a channel which receives status check errors
func (e *etcdClient) StatusCheckErrors() <-chan error {
	return e.statusCheckErrors
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
				e.logger.Debug("Distributed lock successful, etcd has quorum")
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

	initLockSucceeded := e.waitForInitLock(ctxTimeout)
	if err := <-initLockSucceeded; err != nil {
		recordQuorumError("lock timeout")
		return fmt.Errorf("unable to acquire lock: %w", err)
	}

	return nil
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

	for {
		session, err := e.lockLeaseManager.GetSession(context.Background(), InitLockPath)
		if err == nil {
			return session.Done()
		}

		e.logger.WithError(err).Warning("Failed to acquire lock session")
		time.Sleep(100 * time.Millisecond)
	}
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

	// Use the shared etcd client logger to prevent unnecessary allocations.
	config.Logger = etcd3ClientLogger

	c, err := client.New(*config)
	if err != nil {
		return nil, err
	}

	errorChan := make(chan error)

	limiter := ciliumrate.NewAPILimiter(makeSessionName("etcd", opts), ciliumrate.APILimiterParameters{
		RateLimit:        rate.Limit(clientOptions.RateLimit),
		RateBurst:        clientOptions.RateLimit,
		ParallelRequests: clientOptions.MaxInflight,
	}, ciliumratemetrics.APILimiterObserver())

	ec := &etcdClient{
		client:               c,
		config:               config,
		configPath:           cfgPath,
		firstSession:         make(chan struct{}),
		latestStatusSnapshot: "Waiting for initial connection to be established",
		stopStatusChecker:    make(chan struct{}),
		extraOptions:         opts,
		limiter:              limiter,
		listBatchSize:        clientOptions.ListBatchSize,
		statusCheckErrors:    make(chan error, 128),
		logger: log.WithFields(logrus.Fields{
			"endpoints": config.Endpoints,
			"config":    cfgPath,
		}),
	}

	ec.logger.Info("Connecting to etcd server...")

	leaseTTL := option.Config.KVstoreLeaseTTL
	if option.Config.KVstoreLeaseTTL == 0 {
		leaseTTL = defaults.KVstoreLeaseTTL
	}

	ec.leaseManager = newEtcdLeaseManager(c, leaseTTL, etcdMaxKeysPerLease, ec.expiredLeaseObserver, ec.logger)
	ec.lockLeaseManager = newEtcdLeaseManager(c, defaults.LockLeaseTTL, etcdMaxKeysPerLease, nil, ec.logger)

	// create session in parallel as this is a blocking operation
	go func() {
		ls, err := ec.lockLeaseManager.GetSession(ctx, InitLockPath)
		if err != nil {
			errorChan <- err
			close(errorChan)
			return
		}

		log.Infof("Got lock lease ID %x", ls.Lease())
		close(errorChan)
	}()

	handleSessionError := func(err error) {
		ec.RWMutex.Lock()
		ec.sessionErr = err
		ec.RWMutex.Unlock()

		ec.statusLock.Lock()
		ec.latestStatusSnapshot = "Failed to establish initial connection"
		ec.latestErrorStatus = err
		ec.statusLock.Unlock()

		errChan <- err
		ec.statusCheckErrors <- err
	}

	// wait for session to be created also in parallel
	go func() {
		err := func() (err error) {
			select {
			case err = <-errorChan:
				if err != nil {
					return err
				}
			case <-time.After(initialConnectionTimeout):
				return fmt.Errorf("timed out while waiting for etcd session. Ensure that etcd is running on %s", config.Endpoints)
			}

			ec.logger.Info("Initial etcd session established")

			return nil
		}()

		if err != nil {
			handleSessionError(err)
			close(errChan)
			close(ec.firstSession)
			close(ec.statusCheckErrors)
			return
		}

		close(errChan)
		close(ec.firstSession)

		go ec.statusChecker()

		watcher := ec.ListAndWatch(ctx, HeartbeatPath, 128)

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

	return ec, nil
}

// makeSessionName builds up a session/locksession controller name
// clusterName is expected to be empty for main kvstore connection
func makeSessionName(sessionPrefix string, opts *ExtraOptions) string {
	if opts != nil && opts.ClusterName != "" {
		return sessionPrefix + "-" + opts.ClusterName
	}
	return sessionPrefix
}

func (e *etcdClient) sessionError() (err error) {
	e.RWMutex.RLock()
	err = e.sessionErr
	e.RWMutex.RUnlock()
	return
}

func (e *etcdClient) LockPath(ctx context.Context, path string) (KVLocker, error) {
	// Create the context first, so that the timeout also accounts for the time
	// possibly required to acquire a new session (if not already established).
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	session, err := e.lockLeaseManager.GetSession(ctx, path)
	if err != nil {
		return nil, Hint(err)
	}

	mu := concurrency.NewMutex(session, path)
	err = mu.Lock(ctx)
	if err != nil {
		e.lockLeaseManager.CancelIfExpired(err, session.Lease())
		return nil, Hint(err)
	}

	release := func() { e.lockLeaseManager.Release(path) }
	return &etcdMutex{mutex: mu, onUnlock: release}, nil
}

func (e *etcdClient) DeletePrefix(ctx context.Context, path string) (err error) {
	defer func() {
		Trace("DeletePrefix", err, logrus.Fields{fieldPrefix: path})
	}()
	lr, err := e.limiter.Wait(ctx)
	if err != nil {
		return Hint(err)
	}

	defer func(duration *spanstat.SpanStat) {
		increaseMetric(path, metricDelete, "DeletePrefix", duration.EndError(err).Total(), err)
	}(spanstat.Start())

	_, err = e.client.Delete(ctx, path, client.WithPrefix())
	// Using lr.Error for convenience, as it matches lr.Done() when err is nil
	lr.Error(err)

	if err == nil {
		e.leaseManager.ReleasePrefix(path)
	}

	return Hint(err)
}

// watch starts watching for changes in a prefix
func (e *etcdClient) watch(ctx context.Context, w *Watcher) {
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

	scopedLog := e.logger.WithField(fieldPrefix, w.Prefix)
	scopedLog.Debug("Starting watcher...")

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

		lr, err := e.limiter.Wait(ctx)
		if err != nil {
			continue
		}
		kvs, revision, err := e.paginatedList(ctx, scopedLog, w.Prefix)
		if err != nil {
			lr.Error(err)
			scopedLog.WithError(Hint(err)).Warn("Unable to list keys before starting watcher")
			errLimiter.Wait(ctx)
			continue
		}
		lr.Done()
		errLimiter.Reset()

		for _, key := range kvs {
			t := EventTypeCreate
			if localCache.Exists(key.Key) {
				t = EventTypeModify
			}

			localCache.MarkInUse(key.Key)

			if traceEnabled {
				scopedLog.Debugf("Emitting list result as %s event for %s=%s", t, key.Key, key.Value)
			}

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

			if traceEnabled {
				scopedLog.Debugf("Emitting EventTypeDelete event for %s", k)
			}

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

		lr, err = e.limiter.Wait(ctx)
		if err != nil {
			select {
			case <-e.client.Ctx().Done():
				return
			case <-ctx.Done():
				return
			default:
				goto recreateWatcher
			}
		}

		etcdWatch := e.client.Watch(client.WithRequireLeader(ctx), w.Prefix,
			client.WithPrefix(), client.WithRev(nextRev))
		lr.Done()

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
				if traceEnabled {
					scopedLog.Debugf("Received event from etcd: %+v", r)
				}

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

					if traceEnabled {
						scopedLog.Debugf("Emitting %s event for %s=%s", event.Typ, event.Key, event.Value)
					}

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

	e.logger.Debugf("Checking status to etcd endpoint %s", endpointAddress)

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
			e.latestStatusSnapshot = fmt.Sprintf("etcd: %d/%d connected, leases=%d, lock leases=%d, has-quorum=%s: %s",
				ok, len(endpoints), e.leaseManager.TotalLeases(), e.leaseManager.TotalLeases(), quorumString, strings.Join(newStatus, "; "))
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
	defer func() {
		Trace("GetIfLocked", err, logrus.Fields{fieldKey: key, fieldValue: string(bv)})
	}()
	lr, err := e.limiter.Wait(ctx)
	if err != nil {
		return nil, Hint(err)
	}
	defer func(duration *spanstat.SpanStat) {
		increaseMetric(key, metricRead, "GetLocked", duration.EndError(err).Total(), err)
	}(spanstat.Start())

	opGet := client.OpGet(key)
	cmp := lock.Comparator().(client.Cmp)
	txnReply, err := e.client.Txn(ctx).If(cmp).Then(opGet).Commit()
	if err == nil && !txnReply.Succeeded {
		err = ErrLockLeaseExpired
	}

	if err != nil {
		lr.Error(err)
		return nil, Hint(err)
	}

	lr.Done()
	getR := txnReply.Responses[0].GetResponseRange()
	// RangeResponse
	if getR.Count == 0 {
		return nil, nil
	}
	return getR.Kvs[0].Value, nil
}

// Get returns value of key
func (e *etcdClient) Get(ctx context.Context, key string) (bv []byte, err error) {
	defer func() {
		Trace("Get", err, logrus.Fields{fieldKey: key, fieldValue: string(bv)})
	}()
	lr, err := e.limiter.Wait(ctx)
	if err != nil {
		return nil, Hint(err)
	}
	defer func(duration *spanstat.SpanStat) {
		increaseMetric(key, metricRead, "Get", duration.EndError(err).Total(), err)
	}(spanstat.Start())

	getR, err := e.client.Get(ctx, key)
	if err != nil {
		lr.Error(err)
		return nil, Hint(err)
	}
	lr.Done()

	if getR.Count == 0 {
		return nil, nil
	}
	return getR.Kvs[0].Value, nil
}

// DeleteIfLocked deletes a key if the client is still holding the given lock.
func (e *etcdClient) DeleteIfLocked(ctx context.Context, key string, lock KVLocker) (err error) {
	defer func() {
		Trace("DeleteIfLocked", err, logrus.Fields{fieldKey: key})
	}()
	lr, err := e.limiter.Wait(ctx)
	if err != nil {
		return Hint(err)
	}
	defer func(duration *spanstat.SpanStat) {
		increaseMetric(key, metricDelete, "DeleteLocked", duration.EndError(err).Total(), err)
	}(spanstat.Start())

	opDel := client.OpDelete(key)
	cmp := lock.Comparator().(client.Cmp)
	txnReply, err := e.client.Txn(ctx).If(cmp).Then(opDel).Commit()
	if err == nil && !txnReply.Succeeded {
		err = ErrLockLeaseExpired
	}
	if err == nil {
		e.leaseManager.Release(key)
	}

	// Using lr.Error for convenience, as it matches lr.Done() when err is nil
	lr.Error(err)
	return Hint(err)
}

// Delete deletes a key
func (e *etcdClient) Delete(ctx context.Context, key string) (err error) {
	defer func() {
		Trace("Delete", err, logrus.Fields{fieldKey: key})
	}()
	lr, err := e.limiter.Wait(ctx)
	if err != nil {
		return Hint(err)
	}
	defer func(duration *spanstat.SpanStat) {
		increaseMetric(key, metricDelete, "Delete", duration.EndError(err).Total(), err)
	}(spanstat.Start())

	_, err = e.client.Delete(ctx, key)
	// Using lr.Error for convenience, as it matches lr.Done() when err is nil
	lr.Error(err)

	if err == nil {
		e.leaseManager.Release(key)
	}

	return Hint(err)
}

// UpdateIfLocked updates a key if the client is still holding the given lock.
func (e *etcdClient) UpdateIfLocked(ctx context.Context, key string, value []byte, lease bool, lock KVLocker) (err error) {
	defer func() {
		Trace("UpdateIfLocked", err, logrus.Fields{fieldKey: key, fieldValue: string(value), fieldAttachLease: lease})
	}()
	var leaseID client.LeaseID
	if lease {
		leaseID, err = e.leaseManager.GetLeaseID(ctx, key)
		if err != nil {
			return Hint(err)
		}
	}
	lr, err := e.limiter.Wait(ctx)
	if err != nil {
		return Hint(err)
	}
	defer func(duration *spanstat.SpanStat) {
		increaseMetric(key, metricSet, "UpdateIfLocked", duration.EndError(err).Total(), err)
	}(spanstat.Start())

	var txnReply *client.TxnResponse
	opPut := client.OpPut(key, string(value), client.WithLease(leaseID))
	cmp := lock.Comparator().(client.Cmp)
	txnReply, err = e.client.Txn(ctx).If(cmp).Then(opPut).Commit()
	e.leaseManager.CancelIfExpired(err, leaseID)

	if err == nil && !txnReply.Succeeded {
		err = ErrLockLeaseExpired
	}

	// Using lr.Error for convenience, as it matches lr.Done() when err is nil
	lr.Error(err)
	return Hint(err)
}

// Update creates or updates a key
func (e *etcdClient) Update(ctx context.Context, key string, value []byte, lease bool) (err error) {
	defer func() {
		Trace("Update", err, logrus.Fields{fieldKey: key, fieldValue: string(value), fieldAttachLease: lease})
	}()
	var leaseID client.LeaseID
	if lease {
		leaseID, err = e.leaseManager.GetLeaseID(ctx, key)
		if err != nil {
			return Hint(err)
		}
	}
	lr, err := e.limiter.Wait(ctx)
	if err != nil {
		return Hint(err)
	}
	defer func(duration *spanstat.SpanStat) {
		increaseMetric(key, metricSet, "Update", duration.EndError(err).Total(), err)
	}(spanstat.Start())

	_, err = e.client.Put(ctx, key, string(value), client.WithLease(leaseID))
	e.leaseManager.CancelIfExpired(err, leaseID)

	// Using lr.Error for convenience, as it matches lr.Done() when err is nil
	lr.Error(err)
	return Hint(err)
}

// UpdateIfDifferentIfLocked updates a key if the value is different and if the client is still holding the given lock.
func (e *etcdClient) UpdateIfDifferentIfLocked(ctx context.Context, key string, value []byte, lease bool, lock KVLocker) (recreated bool, err error) {
	defer func() {
		Trace("UpdateIfDifferentIfLocked", err, logrus.Fields{fieldKey: key, fieldValue: value, fieldAttachLease: lease, "recreated": recreated})
	}()
	lr, err := e.limiter.Wait(ctx)
	if err != nil {
		return false, Hint(err)
	}
	duration := spanstat.Start()

	cnds := lock.Comparator().(client.Cmp)
	txnresp, err := e.client.Txn(ctx).If(cnds).Then(client.OpGet(key)).Commit()
	// Using lr.Error for convenience, as it matches lr.Done() when err is nil
	lr.Error(err)
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

	if lease && !e.leaseManager.KeyHasLease(key, client.LeaseID(getR.Kvs[0].Lease)) {
		return true, e.UpdateIfLocked(ctx, key, value, lease, lock)
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
	lr, err := e.limiter.Wait(ctx)
	if err != nil {
		return false, Hint(err)
	}
	duration := spanstat.Start()

	getR, err := e.client.Get(ctx, key)
	// Using lr.Error for convenience, as it matches lr.Done() when err is nil
	lr.Error(err)
	increaseMetric(key, metricRead, "Get", duration.EndError(err).Total(), err)
	// On error, attempt update blindly
	if err != nil || getR.Count == 0 {
		return true, e.Update(ctx, key, value, lease)
	}
	if lease && !e.leaseManager.KeyHasLease(key, client.LeaseID(getR.Kvs[0].Lease)) {
		return true, e.Update(ctx, key, value, lease)
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
	var leaseID client.LeaseID
	if lease {
		leaseID, err = e.leaseManager.GetLeaseID(ctx, key)
		if err != nil {
			return false, Hint(err)
		}
	}
	lr, err := e.limiter.Wait(ctx)
	if err != nil {
		return false, Hint(err)
	}
	duration := spanstat.Start()

	req := client.OpPut(key, string(value), client.WithLease(leaseID))
	cnds := []client.Cmp{
		client.Compare(client.Version(key), "=", 0),
		lock.Comparator().(client.Cmp),
	}

	// We need to do a get in the else of the txn to detect if the lock is still
	// valid or not.
	opGets := []client.Op{
		client.OpGet(key),
	}
	txnresp, err := e.client.Txn(ctx).If(cnds...).Then(req).Else(opGets...).Commit()
	increaseMetric(key, metricSet, "CreateOnlyLocked", duration.EndError(err).Total(), err)
	if err != nil {
		lr.Error(err)
		e.leaseManager.CancelIfExpired(err, leaseID)
		return false, Hint(err)
	}
	lr.Done()

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
	var leaseID client.LeaseID
	if lease {
		leaseID, err = e.leaseManager.GetLeaseID(ctx, key)
		if err != nil {
			return false, Hint(err)
		}
	}
	lr, err := e.limiter.Wait(ctx)
	if err != nil {
		return false, Hint(err)
	}
	defer func(duration *spanstat.SpanStat) {
		increaseMetric(key, metricSet, "CreateOnly", duration.EndError(err).Total(), err)
	}(spanstat.Start())

	req := client.OpPut(key, string(value), client.WithLease(leaseID))
	cond := client.Compare(client.Version(key), "=", 0)

	txnresp, err := e.client.Txn(ctx).If(cond).Then(req).Commit()

	if err != nil {
		lr.Error(err)
		e.leaseManager.CancelIfExpired(err, leaseID)
		return false, Hint(err)
	}

	lr.Done()
	return txnresp.Succeeded, nil
}

// ListPrefixIfLocked returns a list of keys matching the prefix only if the client is still holding the given lock.
func (e *etcdClient) ListPrefixIfLocked(ctx context.Context, prefix string, lock KVLocker) (v KeyValuePairs, err error) {
	defer func() {
		Trace("ListPrefixIfLocked", err, logrus.Fields{fieldPrefix: prefix, fieldNumEntries: len(v)})
	}()
	lr, err := e.limiter.Wait(ctx)
	if err != nil {
		return nil, Hint(err)
	}
	defer func(duration *spanstat.SpanStat) {
		increaseMetric(prefix, metricRead, "ListPrefixLocked", duration.EndError(err).Total(), err)
	}(spanstat.Start())

	opGet := client.OpGet(prefix, client.WithPrefix())
	cmp := lock.Comparator().(client.Cmp)
	txnReply, err := e.client.Txn(ctx).If(cmp).Then(opGet).Commit()
	if err == nil && !txnReply.Succeeded {
		err = ErrLockLeaseExpired
	}
	if err != nil {
		lr.Error(err)
		return nil, Hint(err)
	}
	lr.Done()
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
	defer func() {
		Trace("ListPrefix", err, logrus.Fields{fieldPrefix: prefix, fieldNumEntries: len(v)})
	}()
	lr, err := e.limiter.Wait(ctx)
	if err != nil {
		return nil, Hint(err)
	}
	defer func(duration *spanstat.SpanStat) {
		increaseMetric(prefix, metricRead, "ListPrefix", duration.EndError(err).Total(), err)
	}(spanstat.Start())

	getR, err := e.client.Get(ctx, prefix, client.WithPrefix())
	if err != nil {
		lr.Error(err)
		return nil, Hint(err)
	}
	lr.Done()

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

	if err := e.client.Close(); err != nil {
		e.logger.WithError(err).Warning("Failed to close etcd client")
	}

	// Wait until all child goroutines spawned by the lease managers have terminated.
	e.leaseManager.Wait()
	e.lockLeaseManager.Wait()
}

// Encode encodes a binary slice into a character set that the backend supports
func (e *etcdClient) Encode(in []byte) (out string) {
	return string(in)
}

// Decode decodes a key previously encoded back into the original binary slice
func (e *etcdClient) Decode(in string) (out []byte, err error) {
	return []byte(in), nil
}

// ListAndWatch implements the BackendOperations.ListAndWatch using etcd
func (e *etcdClient) ListAndWatch(ctx context.Context, prefix string, chanSize int) *Watcher {
	w := newWatcher(prefix, chanSize)

	go e.watch(ctx, w)

	return w
}

// RegisterLeaseExpiredObserver registers a function which is executed when
// the lease associated with a key having the given prefix is detected as expired.
// If the function is nil, the previous observer (if any) is unregistered.
func (e *etcdClient) RegisterLeaseExpiredObserver(prefix string, fn func(key string)) {
	if fn == nil {
		e.leaseExpiredObservers.Delete(prefix)
	} else {
		e.leaseExpiredObservers.Store(prefix, fn)
	}
}

func (e *etcdClient) expiredLeaseObserver(key string) {
	e.leaseExpiredObservers.Range(func(prefix string, fn func(string)) bool {
		if strings.HasPrefix(key, prefix) {
			fn(key)
		}
		return true
	})
}

// UserEnforcePresence creates a user in etcd if not already present, and grants the specified roles.
func (e *etcdClient) UserEnforcePresence(ctx context.Context, name string, roles []string) error {
	scopedLog := e.logger.WithField(FieldUser, name)

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
	scopedLog := e.logger.WithField(FieldUser, name)

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
