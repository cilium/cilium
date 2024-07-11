// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package internal

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
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	cmutils "github.com/cilium/cilium/pkg/clustermesh/utils"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

type RemoteCluster interface {
	// Run implements the actual business logic once the connection to the remote cluster has been established.
	// The ready channel shall be closed when the initialization tasks completed, possibly returning an error.
	Run(ctx context.Context, backend kvstore.BackendOperations, config *types.CiliumClusterConfig, ready chan<- error)

	Stop()
	Remove()
}

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

	// serviceIPGetter, if not nil, is used to create a custom dialer for service resolution.
	serviceIPGetter k8s.ServiceIPGetter

	// changed receives an event when the remote cluster configuration has
	// changed and is closed when the configuration file was removed
	changed chan bool

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
	// - failures
	// - lastFailure
	mutex lock.RWMutex

	// backend is the kvstore backend being used
	backend kvstore.BackendOperations

	// config contains the information about the cluster config for status reporting
	config *models.RemoteClusterConfig

	// failures is the number of observed failures
	failures int

	// lastFailure is the timestamp of the last failure
	lastFailure time.Time

	metricLastFailureTimestamp prometheus.Gauge
	metricReadinessStatus      prometheus.Gauge
	metricTotalFailures        prometheus.Gauge
}

var (
	// skipKvstoreConnection skips the etcd connection, used for testing
	skipKvstoreConnection bool
)

func (rc *remoteCluster) getLogger() *logrus.Entry {
	var (
		status string
		err    error
	)

	if rc.backend != nil {
		status, err = rc.backend.Status()
	}

	return log.WithFields(logrus.Fields{
		fieldClusterName:   rc.name,
		fieldConfig:        rc.configPath,
		fieldKVStoreStatus: status,
		fieldKVStoreErr:    err,
	})
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
	rc.mutex.Unlock()

	// Release resources asynchronously in the background. Many of these
	// operations may time out if the connection was closed due to an error
	// condition.
	go func() {
		if backend != nil {
			backend.Close(context.Background())
		}
	}()
}

func (rc *remoteCluster) restartRemoteConnection() {
	rc.controllers.UpdateController(rc.remoteConnectionControllerName,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				rc.releaseOldConnection()

				extraOpts := rc.makeExtraOpts()

				backend, errChan := kvstore.NewClient(ctx, kvstore.EtcdBackendName,
					rc.makeEtcdOpts(), &extraOpts)

				// Block until either an error is returned or
				// the channel is closed due to success of the
				// connection
				rc.getLogger().Debugf("Waiting for connection to be established")
				err, isErr := <-errChan
				if isErr {
					if backend != nil {
						backend.Close(ctx)
					}
					rc.getLogger().WithError(err).Warning("Unable to establish etcd connection to remote cluster")
					return err
				}

				rc.mutex.Lock()
				rc.backend = backend
				rc.mutex.Unlock()

				rc.getLogger().Info("Connection to remote cluster established")

				config, err := rc.getClusterConfig(ctx, backend, false)
				if err == nil && config == nil {
					rc.getLogger().Warning("Remote cluster doesn't have cluster configuration, falling back to the old behavior. This is expected when connecting to the old cluster running Cilium without cluster configuration feature.")
				} else if err == nil {
					rc.getLogger().Info("Found remote cluster configuration")
				} else {
					rc.getLogger().WithError(err).Warning("Unable to get remote cluster configuration")
					return err
				}

				ctx, cancel := context.WithCancel(ctx)
				rc.wg.Add(1)
				go func() {
					rc.watchdog(ctx, backend)
					rc.wg.Done()
				}()

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
					rc.getLogger().WithError(err).Warning("Connection to remote cluster failed")
					return err
				}

				rc.metricReadinessStatus.Set(metrics.BoolToFloat64(true))
				return nil
			},
			StopFunc: func(ctx context.Context) error {
				rc.releaseOldConnection()
				rc.getLogger().Info("Connection to remote cluster stopped")
				return nil
			},
			CancelDoFuncOnUpdate: true,
		},
	)
}

func (rc *remoteCluster) watchdog(ctx context.Context, backend kvstore.BackendOperations) {
	select {
	case err, ok := <-backend.StatusCheckErrors():
		if ok && err != nil {
			rc.getLogger().WithError(err).Warning("Error observed on etcd connection, reconnecting etcd")
			rc.mutex.Lock()
			rc.failures++
			rc.lastFailure = time.Now()
			rc.metricLastFailureTimestamp.SetToCurrentTime()
			rc.metricTotalFailures.Set(float64(rc.failures))
			rc.metricReadinessStatus.Set(metrics.BoolToFloat64(rc.isReadyLocked()))
			rc.mutex.Unlock()

			rc.restartRemoteConnection()
		}

	case <-ctx.Done():
		return
	}
}

func (rc *remoteCluster) getClusterConfig(ctx context.Context, backend kvstore.BackendOperations, forceRequired bool) (*cmtypes.CiliumClusterConfig, error) {
	var (
		err                           error
		requireConfig                 = forceRequired
		clusterConfigRetrievalTimeout = 3 * time.Minute
	)

	ctx, cancel := context.WithTimeout(ctx, clusterConfigRetrievalTimeout)
	defer cancel()

	if !requireConfig {
		// Let's check whether the kvstore states that the cluster configuration should be always present.
		requireConfig, err = cmutils.IsClusterConfigRequired(ctx, backend)
		if err != nil {
			return nil, fmt.Errorf("failed to detect whether the cluster configuration is required: %w", err)
		}
	}

	rc.mutex.Lock()
	rc.config = &models.RemoteClusterConfig{Required: requireConfig}
	rc.mutex.Unlock()

	cfgch := make(chan *types.CiliumClusterConfig, 1)
	defer close(cfgch)

	// We retry here rather than simply returning an error and relying on the external
	// controller backoff period to avoid recreating every time a new connection to the remote
	// kvstore, which would introduce an unnecessary overhead. Still, we do return in case of
	// consecutive failures, to ensure that we do not retry forever if something strange happened.
	ctrlname := rc.remoteConnectionControllerName + "-cluster-config"
	defer rc.controllers.RemoveControllerAndWait(ctrlname)
	rc.controllers.UpdateController(ctrlname, controller.ControllerParams{
		DoFunc: func(ctx context.Context) error {
			rc.getLogger().Debug("Retrieving cluster configuration from remote kvstore")
			config, err := cmutils.GetClusterConfig(ctx, rc.name, backend)
			if err != nil {
				return err
			}

			if config == nil && requireConfig {
				return errors.New("cluster configuration expected to be present but not found")
			}

			// We should stop retrying in case we either successfully retrieved the cluster
			// configuration, or we are not required to wait for it.
			cfgch <- config
			return nil
		},
		Context:          ctx,
		MaxRetryInterval: 30 * time.Second,
	})

	// Wait until either the configuration is retrieved, or the context expires
	select {
	case config := <-cfgch:
		if config != nil {
			rc.mutex.Lock()
			rc.config.Retrieved = true
			rc.config.ClusterID = int64(config.ID)
			rc.config.Kvstoremesh = config.Capabilities.Cached
			rc.config.SyncCanaries = config.Capabilities.SyncedCanaries
			rc.mutex.Unlock()
		}

		return config, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("failed to retrieve cluster configuration")
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

func (rc *remoteCluster) makeExtraOpts() kvstore.ExtraOptions {
	var dialOpts []grpc.DialOption
	if rc.serviceIPGetter != nil {
		// Allow to resolve service names without depending on the DNS. This prevents the need
		// for setting the DNSPolicy to ClusterFirstWithHostNet when running in host network.
		logger := log.WithField(fieldClusterName, rc.name)
		dialOpts = append(dialOpts, grpc.WithContextDialer(k8s.CreateCustomDialer(rc.serviceIPGetter, logger, false)))
	}

	return kvstore.ExtraOptions{
		NoLockQuorumCheck:            true,
		ClusterName:                  rc.name,
		ClusterSizeDependantInterval: rc.clusterSizeDependantInterval,
		DialOption:                   dialOpts,
	}
}

func (rc *remoteCluster) onInsert() {
	rc.getLogger().Info("New remote cluster configuration")

	if skipKvstoreConnection {
		return
	}

	rc.remoteConnectionControllerName = fmt.Sprintf("remote-etcd-%s", rc.name)
	rc.restartRemoteConnection()

	go func() {
		for {
			val := <-rc.changed
			if val {
				rc.getLogger().Info("etcd configuration has changed, re-creating connection")
				rc.restartRemoteConnection()
			} else {
				rc.getLogger().Info("Closing connection to remote etcd")
				return
			}
		}
	}()
}

// onStop is executed when the clustermesh subsystem is being stopped.
// In this case, we don't want to drain the known entries, otherwise
// we would break existing connections when the agent gets restarted.
func (rc *remoteCluster) onStop() {
	_ = rc.controllers.RemoveControllerAndWait(rc.remoteConnectionControllerName)
	close(rc.changed)
	rc.Stop()
}

// onRemove is executed when a remote cluster is explicitly disconnected
// (i.e., its configuration is removed). In this case, we need to drain
// all known entries, to properly cleanup the status without requiring to
// restart the agent.
func (rc *remoteCluster) onRemove() {
	rc.onStop()
	rc.Remove()

	rc.getLogger().Info("Remote cluster disconnected")
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
