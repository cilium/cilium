// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	cmutils "github.com/cilium/cilium/pkg/clustermesh/utils"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

var (
	remoteConnectionControllerGroup = controller.NewGroup("clustermesh-remote-cluster")
	clusterConfigControllerGroup    = controller.NewGroup("clustermesh-cluster-config")
)

type RemoteCluster interface {
	// Run implements the actual business logic once the connection to the remote cluster has been established.
	// The ready channel shall be closed when the initialization tasks completed, possibly returning an error.
	Run(ctx context.Context, backend kvstore.BackendOperations, config types.CiliumClusterConfig, ready chan<- error)

	Stop()
	Remove(ctx context.Context)
}

// backendFactoryFn is the type of the function to create the etcd client.
type backendFactoryFn func(ctx context.Context, backend string, opts map[string]string,
	options *kvstore.ExtraOptions) (kvstore.BackendOperations, chan error)

// remoteCluster represents another cluster other than the cluster the agent is
// running in
type remoteCluster struct {
	RemoteCluster

	// name is the name of the cluster
	name string

	// configPath is the path to the etcd configuration to be used to
	// connect to the etcd cluster of the remote cluster
	configPath string

	// clusterSizeDependantInterval allows to calculate intervals based on cluster size.
	clusterSizeDependantInterval kvstore.ClusterSizeDependantIntervalFunc

	// resolvers are the set of resolvers used to create the custom dialer.
	resolvers []dial.Resolver

	controllers *controller.Manager

	// wg is used to wait for the termination of the goroutines spawned by the
	// controller upon reconnection for long running background tasks.
	wg sync.WaitGroup

	// remoteConnectionControllerName is the name of the backing controller
	// that maintains the remote connection
	remoteConnectionControllerName string

	// mutex protects the following variables
	// - backend
	// - config
	// - etcdClusterID
	// - failures
	// - lastFailure
	mutex lock.RWMutex

	// backend is the kvstore backend being used
	backend kvstore.BackendOperations

	// config contains the information about the cluster config for status reporting
	config *models.RemoteClusterConfig

	// etcdClusterID contains the information about the etcd cluster ID for status
	// reporting. It is used to distinguish which instance of the clustermesh-apiserver
	// we are connected to when running in HA mode.
	etcdClusterID string

	// failures is the number of observed failures
	failures int

	// lastFailure is the timestamp of the last failure
	lastFailure time.Time

	logger logrus.FieldLogger

	// backendFactory allows to override the function to create the etcd client
	// for testing purposes.
	backendFactory backendFactoryFn
	// clusterLockFactory allows to override the function to create the clusterLock
	// for testing purposes.
	clusterLockFactory func() *clusterLock

	metricLastFailureTimestamp prometheus.Gauge
	metricReadinessStatus      prometheus.Gauge
	metricTotalFailures        prometheus.Gauge
}

// releaseOldConnection releases the etcd connection to a remote cluster
func (rc *remoteCluster) releaseOldConnection() {
	rc.metricReadinessStatus.Set(metrics.BoolToFloat64(false))

	// Make sure that all child goroutines terminated before performing cleanup.
	rc.wg.Wait()

	rc.mutex.Lock()
	backend := rc.backend
	rc.backend = nil
	rc.config = nil
	rc.etcdClusterID = ""
	rc.mutex.Unlock()

	if backend != nil {
		backend.Close()
	}
}

func (rc *remoteCluster) restartRemoteConnection() {
	rc.controllers.UpdateController(
		rc.remoteConnectionControllerName,
		controller.ControllerParams{
			Group: remoteConnectionControllerGroup,
			DoFunc: func(ctx context.Context) error {
				rc.releaseOldConnection()

				clusterLock := rc.clusterLockFactory()
				extraOpts := rc.makeExtraOpts(clusterLock)
				backend, errChan := rc.backendFactory(ctx, kvstore.EtcdBackendName, rc.makeEtcdOpts(), &extraOpts)

				// Block until either an error is returned or
				// the channel is closed due to success of the
				// connection
				rc.logger.Debugf("Waiting for connection to be established")

				var err error
				select {
				case err = <-errChan:
				case err = <-clusterLock.errors:
				}

				if err != nil {
					if backend != nil {
						backend.Close()
					}
					rc.logger.WithError(err).Warning("Unable to establish etcd connection to remote cluster")
					return err
				}

				etcdClusterID := fmt.Sprintf("%x", clusterLock.etcdClusterID.Load())

				rc.mutex.Lock()
				rc.backend = backend
				rc.etcdClusterID = etcdClusterID
				rc.mutex.Unlock()

				ctx, cancel := context.WithCancel(ctx)
				rc.wg.Add(1)
				go func() {
					rc.watchdog(ctx, backend, clusterLock)
					cancel()
					rc.wg.Done()
				}()

				rc.logger.WithField(logfields.EtcdClusterID, etcdClusterID).Info("Connection to remote cluster established")

				config, err := rc.getClusterConfig(ctx, backend)
				if err != nil {
					lgr := rc.logger
					if errors.Is(err, cmutils.ErrClusterConfigNotFound) {
						lgr = lgr.WithField(logfields.Hint,
							"If KVStoreMesh is enabled, check whether it is connected to the target cluster."+
								" Additionally, ensure that the cluster name is correct.")
					}

					lgr.WithError(err).Warning("Unable to get remote cluster configuration")
					cancel()
					return err
				}
				rc.logger.Info("Found remote cluster configuration")

				ready := make(chan error)

				// Let's execute the long running logic in background. This allows
				// to return early from the controller body, so that the statistics
				// are updated correctly. Instead, blocking until rc.Run terminates
				// would prevent a previous failure from being cleared out.
				rc.wg.Add(1)
				go func() {
					rc.Run(ctx, backend, config, ready)
					cancel()
					rc.wg.Done()
				}()

				if err := <-ready; err != nil {
					rc.logger.WithError(err).Warning("Connection to remote cluster failed")
					return err
				}

				rc.metricReadinessStatus.Set(metrics.BoolToFloat64(true))
				return nil
			},
			StopFunc: func(ctx context.Context) error {
				rc.releaseOldConnection()
				rc.logger.Info("Connection to remote cluster stopped")
				return nil
			},
			CancelDoFuncOnUpdate: true,
		},
	)
}

func (rc *remoteCluster) watchdog(ctx context.Context, backend kvstore.BackendOperations, clusterLock *clusterLock) {
	handleErr := func(err error) {
		rc.logger.WithError(err).Warning("Error observed on etcd connection, reconnecting etcd")
		rc.mutex.Lock()
		rc.failures++
		rc.lastFailure = time.Now()
		rc.metricLastFailureTimestamp.SetToCurrentTime()
		rc.metricTotalFailures.Set(float64(rc.failures))
		rc.metricReadinessStatus.Set(metrics.BoolToFloat64(rc.isReadyLocked()))
		rc.mutex.Unlock()

		rc.restartRemoteConnection()
	}

	select {
	case err, ok := <-backend.StatusCheckErrors():
		if ok && err != nil {
			handleErr(err)
		}
	case err, ok := <-clusterLock.errors:
		if ok && err != nil {
			handleErr(err)
		}
	case <-ctx.Done():
		return
	}
}

func (rc *remoteCluster) getClusterConfig(ctx context.Context, backend kvstore.BackendOperations) (types.CiliumClusterConfig, error) {
	var (
		clusterConfigRetrievalTimeout = 3 * time.Minute
		lastError                     = context.Canceled
		lastErrorLock                 lock.Mutex
	)

	ctx, cancel := context.WithTimeout(ctx, clusterConfigRetrievalTimeout)
	defer cancel()

	rc.mutex.Lock()
	rc.config = &models.RemoteClusterConfig{Required: true}
	rc.mutex.Unlock()

	cfgch := make(chan types.CiliumClusterConfig, 1)
	defer close(cfgch)

	// We retry here rather than simply returning an error and relying on the external
	// controller backoff period to avoid recreating every time a new connection to the remote
	// kvstore, which would introduce an unnecessary overhead. Still, we do return in case of
	// consecutive failures, to ensure that we do not retry forever if something strange happened.
	ctrlname := rc.remoteConnectionControllerName + "-cluster-config"
	defer rc.controllers.RemoveControllerAndWait(ctrlname)
	rc.controllers.UpdateController(ctrlname, controller.ControllerParams{
		Group: clusterConfigControllerGroup,
		DoFunc: func(ctx context.Context) error {
			rc.logger.Debug("Retrieving cluster configuration from remote kvstore")
			config, err := cmutils.GetClusterConfig(ctx, rc.name, backend)
			if err != nil {
				lastErrorLock.Lock()
				lastError = err
				lastErrorLock.Unlock()
				return err
			}

			cfgch <- config
			return nil
		},
		Context:          ctx,
		MaxRetryInterval: 30 * time.Second,
	})

	// Wait until either the configuration is retrieved, or the context expires
	select {
	case config := <-cfgch:
		rc.mutex.Lock()
		rc.config.Retrieved = true
		rc.config.ClusterID = int64(config.ID)
		rc.config.Kvstoremesh = config.Capabilities.Cached
		rc.config.SyncCanaries = config.Capabilities.SyncedCanaries
		rc.config.ServiceExportsEnabled = config.Capabilities.ServiceExportsEnabled
		rc.mutex.Unlock()

		return config, nil
	case <-ctx.Done():
		lastErrorLock.Lock()
		defer lastErrorLock.Unlock()
		return types.CiliumClusterConfig{}, fmt.Errorf("failed to retrieve cluster configuration: %w", lastError)
	}
}

func (rc *remoteCluster) makeEtcdOpts() map[string]string {
	opts := map[string]string{
		kvstore.EtcdOptionConfig: rc.configPath,
	}

	for key, value := range option.Config.KVStoreOpt {
		switch key {
		case kvstore.EtcdRateLimitOption, kvstore.EtcdMaxInflightOption, kvstore.EtcdListLimitOption,
			kvstore.EtcdOptionKeepAliveHeartbeat, kvstore.EtcdOptionKeepAliveTimeout:
			opts[key] = value
		}
	}

	return opts
}

func (rc *remoteCluster) makeExtraOpts(clusterLock *clusterLock) kvstore.ExtraOptions {
	var dialOpts []grpc.DialOption

	dialOpts = append(dialOpts, grpc.WithStreamInterceptor(newStreamInterceptor(clusterLock)), grpc.WithUnaryInterceptor(newUnaryInterceptor(clusterLock)))

	// Allow to resolve service names without depending on the DNS. This prevents the need
	// for setting the DNSPolicy to ClusterFirstWithHostNet when running in host network.
	dialOpts = append(dialOpts, grpc.WithContextDialer(dial.NewContextDialer(rc.logger, rc.resolvers...)))

	return kvstore.ExtraOptions{
		NoLockQuorumCheck:            true,
		ClusterName:                  rc.name,
		ClusterSizeDependantInterval: rc.clusterSizeDependantInterval,
		DialOption:                   dialOpts,
		NoEndpointStatusChecks:       true,
	}
}

func (rc *remoteCluster) connect() {
	rc.logger.Info("Connecting to remote cluster")
	rc.restartRemoteConnection()
}

// onStop is executed when the clustermesh subsystem is being stopped.
// In this case, we don't want to drain the known entries, otherwise
// we would break existing connections when the agent gets restarted.
func (rc *remoteCluster) onStop() {
	_ = rc.controllers.RemoveControllerAndWait(rc.remoteConnectionControllerName)
	rc.Stop()
}

// onRemove is executed when a remote cluster is explicitly disconnected
// (i.e., its configuration is removed). In this case, we need to drain
// all known entries, to properly cleanup the status without requiring to
// restart the agent.
func (rc *remoteCluster) onRemove(ctx context.Context) {
	rc.onStop()
	rc.Remove(ctx)

	rc.logger.Info("Remote cluster disconnected")
}

func (rc *remoteCluster) isReady() bool {
	rc.mutex.RLock()
	defer rc.mutex.RUnlock()

	return rc.isReadyLocked()
}

func (rc *remoteCluster) isReadyLocked() bool {
	return rc.backend != nil && rc.config != nil && (!rc.config.Required || rc.config.Retrieved)
}

func (rc *remoteCluster) status() *models.RemoteCluster {
	rc.mutex.RLock()
	defer rc.mutex.RUnlock()

	// This can happen when the controller in restartRemoteConnection is waiting
	// for the first connection to succeed.
	var backendStatus = "Waiting for initial connection to be established"
	if rc.backend != nil {
		var backendError error
		backendStatus, backendError = rc.backend.Status()
		if backendError != nil {
			backendStatus = backendError.Error()
		}

		if rc.etcdClusterID != "" {
			backendStatus += ", ID: " + rc.etcdClusterID
		}
	}

	status := &models.RemoteCluster{
		Name:        rc.name,
		Ready:       rc.isReadyLocked(),
		Connected:   rc.backend != nil,
		Status:      backendStatus,
		Config:      rc.config,
		NumFailures: int64(rc.failures),
		LastFailure: strfmt.DateTime(rc.lastFailure),
	}

	return status
}
