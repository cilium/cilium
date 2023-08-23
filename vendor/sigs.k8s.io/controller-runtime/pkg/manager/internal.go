/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package manager

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"

	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/internal/httpserver"
	intrec "sigs.k8s.io/controller-runtime/pkg/internal/recorder"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

const (
	// Values taken from: https://github.com/kubernetes/component-base/blob/master/config/v1alpha1/defaults.go
	defaultLeaseDuration          = 15 * time.Second
	defaultRenewDeadline          = 10 * time.Second
	defaultRetryPeriod            = 2 * time.Second
	defaultGracefulShutdownPeriod = 30 * time.Second

	defaultReadinessEndpoint = "/readyz"
	defaultLivenessEndpoint  = "/healthz"
)

var _ Runnable = &controllerManager{}

type controllerManager struct {
	sync.Mutex
	started bool

	stopProcedureEngaged *int64
	errChan              chan error
	runnables            *runnables

	// cluster holds a variety of methods to interact with a cluster. Required.
	cluster cluster.Cluster

	// recorderProvider is used to generate event recorders that will be injected into Controllers
	// (and EventHandlers, Sources and Predicates).
	recorderProvider *intrec.Provider

	// resourceLock forms the basis for leader election
	resourceLock resourcelock.Interface

	// leaderElectionReleaseOnCancel defines if the manager should step back from the leader lease
	// on shutdown
	leaderElectionReleaseOnCancel bool

	// metricsServer is used to serve prometheus metrics
	metricsServer metricsserver.Server

	// healthProbeListener is used to serve liveness probe
	healthProbeListener net.Listener

	// Readiness probe endpoint name
	readinessEndpointName string

	// Liveness probe endpoint name
	livenessEndpointName string

	// Readyz probe handler
	readyzHandler *healthz.Handler

	// Healthz probe handler
	healthzHandler *healthz.Handler

	// pprofListener is used to serve pprof
	pprofListener net.Listener

	// controllerConfig are the global controller options.
	controllerConfig config.Controller

	// Logger is the logger that should be used by this manager.
	// If none is set, it defaults to log.Log global logger.
	logger logr.Logger

	// leaderElectionStopped is an internal channel used to signal the stopping procedure that the
	// LeaderElection.Run(...) function has returned and the shutdown can proceed.
	leaderElectionStopped chan struct{}

	// leaderElectionCancel is used to cancel the leader election. It is distinct from internalStopper,
	// because for safety reasons we need to os.Exit() when we lose the leader election, meaning that
	// it must be deferred until after gracefulShutdown is done.
	leaderElectionCancel context.CancelFunc

	// elected is closed when this manager becomes the leader of a group of
	// managers, either because it won a leader election or because no leader
	// election was configured.
	elected chan struct{}

	webhookServer webhook.Server
	// webhookServerOnce will be called in GetWebhookServer() to optionally initialize
	// webhookServer if unset, and Add() it to controllerManager.
	webhookServerOnce sync.Once

	// leaderElectionID is the name of the resource that leader election
	// will use for holding the leader lock.
	leaderElectionID string
	// leaseDuration is the duration that non-leader candidates will
	// wait to force acquire leadership.
	leaseDuration time.Duration
	// renewDeadline is the duration that the acting controlplane will retry
	// refreshing leadership before giving up.
	renewDeadline time.Duration
	// retryPeriod is the duration the LeaderElector clients should wait
	// between tries of actions.
	retryPeriod time.Duration

	// gracefulShutdownTimeout is the duration given to runnable to stop
	// before the manager actually returns on stop.
	gracefulShutdownTimeout time.Duration

	// onStoppedLeading is callled when the leader election lease is lost.
	// It can be overridden for tests.
	onStoppedLeading func()

	// shutdownCtx is the context that can be used during shutdown. It will be cancelled
	// after the gracefulShutdownTimeout ended. It must not be accessed before internalStop
	// is closed because it will be nil.
	shutdownCtx context.Context

	internalCtx    context.Context
	internalCancel context.CancelFunc

	// internalProceduresStop channel is used internally to the manager when coordinating
	// the proper shutdown of servers. This channel is also used for dependency injection.
	internalProceduresStop chan struct{}
}

type hasCache interface {
	Runnable
	GetCache() cache.Cache
}

// Add sets dependencies on i, and adds it to the list of Runnables to start.
func (cm *controllerManager) Add(r Runnable) error {
	cm.Lock()
	defer cm.Unlock()
	return cm.add(r)
}

func (cm *controllerManager) add(r Runnable) error {
	return cm.runnables.Add(r)
}

// AddHealthzCheck allows you to add Healthz checker.
func (cm *controllerManager) AddHealthzCheck(name string, check healthz.Checker) error {
	cm.Lock()
	defer cm.Unlock()

	if cm.started {
		return fmt.Errorf("unable to add new checker because healthz endpoint has already been created")
	}

	if cm.healthzHandler == nil {
		cm.healthzHandler = &healthz.Handler{Checks: map[string]healthz.Checker{}}
	}

	cm.healthzHandler.Checks[name] = check
	return nil
}

// AddReadyzCheck allows you to add Readyz checker.
func (cm *controllerManager) AddReadyzCheck(name string, check healthz.Checker) error {
	cm.Lock()
	defer cm.Unlock()

	if cm.started {
		return fmt.Errorf("unable to add new checker because healthz endpoint has already been created")
	}

	if cm.readyzHandler == nil {
		cm.readyzHandler = &healthz.Handler{Checks: map[string]healthz.Checker{}}
	}

	cm.readyzHandler.Checks[name] = check
	return nil
}

func (cm *controllerManager) GetHTTPClient() *http.Client {
	return cm.cluster.GetHTTPClient()
}

func (cm *controllerManager) GetConfig() *rest.Config {
	return cm.cluster.GetConfig()
}

func (cm *controllerManager) GetClient() client.Client {
	return cm.cluster.GetClient()
}

func (cm *controllerManager) GetScheme() *runtime.Scheme {
	return cm.cluster.GetScheme()
}

func (cm *controllerManager) GetFieldIndexer() client.FieldIndexer {
	return cm.cluster.GetFieldIndexer()
}

func (cm *controllerManager) GetCache() cache.Cache {
	return cm.cluster.GetCache()
}

func (cm *controllerManager) GetEventRecorderFor(name string) record.EventRecorder {
	return cm.cluster.GetEventRecorderFor(name)
}

func (cm *controllerManager) GetRESTMapper() meta.RESTMapper {
	return cm.cluster.GetRESTMapper()
}

func (cm *controllerManager) GetAPIReader() client.Reader {
	return cm.cluster.GetAPIReader()
}

func (cm *controllerManager) GetWebhookServer() webhook.Server {
	cm.webhookServerOnce.Do(func() {
		if cm.webhookServer == nil {
			panic("webhook should not be nil")
		}
		if err := cm.Add(cm.webhookServer); err != nil {
			panic(fmt.Sprintf("unable to add webhook server to the controller manager: %s", err))
		}
	})
	return cm.webhookServer
}

func (cm *controllerManager) GetLogger() logr.Logger {
	return cm.logger
}

func (cm *controllerManager) GetControllerOptions() config.Controller {
	return cm.controllerConfig
}

func (cm *controllerManager) addHealthProbeServer() error {
	mux := http.NewServeMux()
	srv := httpserver.New(mux)

	if cm.readyzHandler != nil {
		mux.Handle(cm.readinessEndpointName, http.StripPrefix(cm.readinessEndpointName, cm.readyzHandler))
		// Append '/' suffix to handle subpaths
		mux.Handle(cm.readinessEndpointName+"/", http.StripPrefix(cm.readinessEndpointName, cm.readyzHandler))
	}
	if cm.healthzHandler != nil {
		mux.Handle(cm.livenessEndpointName, http.StripPrefix(cm.livenessEndpointName, cm.healthzHandler))
		// Append '/' suffix to handle subpaths
		mux.Handle(cm.livenessEndpointName+"/", http.StripPrefix(cm.livenessEndpointName, cm.healthzHandler))
	}

	return cm.add(&server{
		Kind:     "health probe",
		Log:      cm.logger,
		Server:   srv,
		Listener: cm.healthProbeListener,
	})
}

func (cm *controllerManager) addPprofServer() error {
	mux := http.NewServeMux()
	srv := httpserver.New(mux)

	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	return cm.add(&server{
		Kind:     "pprof",
		Log:      cm.logger,
		Server:   srv,
		Listener: cm.pprofListener,
	})
}

// Start starts the manager and waits indefinitely.
// There is only two ways to have start return:
// An error has occurred during in one of the internal operations,
// such as leader election, cache start, webhooks, and so on.
// Or, the context is cancelled.
func (cm *controllerManager) Start(ctx context.Context) (err error) {
	cm.Lock()
	if cm.started {
		cm.Unlock()
		return errors.New("manager already started")
	}
	cm.started = true

	var ready bool
	defer func() {
		// Only unlock the manager if we haven't reached
		// the internal readiness condition.
		if !ready {
			cm.Unlock()
		}
	}()

	// Initialize the internal context.
	cm.internalCtx, cm.internalCancel = context.WithCancel(ctx)

	// This chan indicates that stop is complete, in other words all runnables have returned or timeout on stop request
	stopComplete := make(chan struct{})
	defer close(stopComplete)
	// This must be deferred after closing stopComplete, otherwise we deadlock.
	defer func() {
		// https://hips.hearstapps.com/hmg-prod.s3.amazonaws.com/images/gettyimages-459889618-1533579787.jpg
		stopErr := cm.engageStopProcedure(stopComplete)
		if stopErr != nil {
			if err != nil {
				// Utilerrors.Aggregate allows to use errors.Is for all contained errors
				// whereas fmt.Errorf allows wrapping at most one error which means the
				// other one can not be found anymore.
				err = kerrors.NewAggregate([]error{err, stopErr})
			} else {
				err = stopErr
			}
		}
	}()

	// Add the cluster runnable.
	if err := cm.add(cm.cluster); err != nil {
		return fmt.Errorf("failed to add cluster to runnables: %w", err)
	}

	// Metrics should be served whether the controller is leader or not.
	// (If we don't serve metrics for non-leaders, prometheus will still scrape
	// the pod but will get a connection refused).
	if cm.metricsServer != nil {
		// Note: We are adding the metrics server directly to HTTPServers here as matching on the
		// metricsserver.Server interface in cm.runnables.Add would be very brittle.
		if err := cm.runnables.HTTPServers.Add(cm.metricsServer, nil); err != nil {
			return fmt.Errorf("failed to add metrics server: %w", err)
		}
	}

	// Serve health probes.
	if cm.healthProbeListener != nil {
		if err := cm.addHealthProbeServer(); err != nil {
			return fmt.Errorf("failed to add health probe server: %w", err)
		}
	}

	// Add pprof server
	if cm.pprofListener != nil {
		if err := cm.addPprofServer(); err != nil {
			return fmt.Errorf("failed to add pprof server: %w", err)
		}
	}

	// First start any internal HTTP servers, which includes health probes, metrics and profiling if enabled.
	//
	// WARNING: Internal HTTP servers MUST start before any cache is populated, otherwise it would block
	// conversion webhooks to be ready for serving which make the cache never get ready.
	if err := cm.runnables.HTTPServers.Start(cm.internalCtx); err != nil {
		if err != nil {
			return fmt.Errorf("failed to start HTTP servers: %w", err)
		}
	}

	// Start any webhook servers, which includes conversion, validation, and defaulting
	// webhooks that are registered.
	//
	// WARNING: Webhooks MUST start before any cache is populated, otherwise there is a race condition
	// between conversion webhooks and the cache sync (usually initial list) which causes the webhooks
	// to never start because no cache can be populated.
	if err := cm.runnables.Webhooks.Start(cm.internalCtx); err != nil {
		if err != nil {
			return fmt.Errorf("failed to start webhooks: %w", err)
		}
	}

	// Start and wait for caches.
	if err := cm.runnables.Caches.Start(cm.internalCtx); err != nil {
		if err != nil {
			return fmt.Errorf("failed to start caches: %w", err)
		}
	}

	// Start the non-leaderelection Runnables after the cache has synced.
	if err := cm.runnables.Others.Start(cm.internalCtx); err != nil {
		if err != nil {
			return fmt.Errorf("failed to start other runnables: %w", err)
		}
	}

	// Start the leader election and all required runnables.
	{
		ctx, cancel := context.WithCancel(context.Background())
		cm.leaderElectionCancel = cancel
		go func() {
			if cm.resourceLock != nil {
				if err := cm.startLeaderElection(ctx); err != nil {
					cm.errChan <- err
				}
			} else {
				// Treat not having leader election enabled the same as being elected.
				if err := cm.startLeaderElectionRunnables(); err != nil {
					cm.errChan <- err
				}
				close(cm.elected)
			}
		}()
	}

	ready = true
	cm.Unlock()
	select {
	case <-ctx.Done():
		// We are done
		return nil
	case err := <-cm.errChan:
		// Error starting or running a runnable
		return err
	}
}

// engageStopProcedure signals all runnables to stop, reads potential errors
// from the errChan and waits for them to end. It must not be called more than once.
func (cm *controllerManager) engageStopProcedure(stopComplete <-chan struct{}) error {
	if !atomic.CompareAndSwapInt64(cm.stopProcedureEngaged, 0, 1) {
		return errors.New("stop procedure already engaged")
	}

	// Populate the shutdown context, this operation MUST be done before
	// closing the internalProceduresStop channel.
	//
	// The shutdown context immediately expires if the gracefulShutdownTimeout is not set.
	var shutdownCancel context.CancelFunc
	if cm.gracefulShutdownTimeout < 0 {
		// We want to wait forever for the runnables to stop.
		cm.shutdownCtx, shutdownCancel = context.WithCancel(context.Background())
	} else {
		cm.shutdownCtx, shutdownCancel = context.WithTimeout(context.Background(), cm.gracefulShutdownTimeout)
	}
	defer shutdownCancel()

	// Start draining the errors before acquiring the lock to make sure we don't deadlock
	// if something that has the lock is blocked on trying to write into the unbuffered
	// channel after something else already wrote into it.
	var closeOnce sync.Once
	go func() {
		for {
			// Closing in the for loop is required to avoid race conditions between
			// the closure of all internal procedures and making sure to have a reader off the error channel.
			closeOnce.Do(func() {
				// Cancel the internal stop channel and wait for the procedures to stop and complete.
				close(cm.internalProceduresStop)
				cm.internalCancel()
			})
			select {
			case err, ok := <-cm.errChan:
				if ok {
					cm.logger.Error(err, "error received after stop sequence was engaged")
				}
			case <-stopComplete:
				return
			}
		}
	}()

	// We want to close this after the other runnables stop, because we don't
	// want things like leader election to try and emit events on a closed
	// channel
	defer cm.recorderProvider.Stop(cm.shutdownCtx)
	defer func() {
		// Cancel leader election only after we waited. It will os.Exit() the app for safety.
		if cm.resourceLock != nil {
			// After asking the context to be cancelled, make sure
			// we wait for the leader stopped channel to be closed, otherwise
			// we might encounter race conditions between this code
			// and the event recorder, which is used within leader election code.
			cm.leaderElectionCancel()
			<-cm.leaderElectionStopped
		}
	}()

	go func() {
		// First stop the non-leader election runnables.
		cm.logger.Info("Stopping and waiting for non leader election runnables")
		cm.runnables.Others.StopAndWait(cm.shutdownCtx)

		// Stop all the leader election runnables, which includes reconcilers.
		cm.logger.Info("Stopping and waiting for leader election runnables")
		cm.runnables.LeaderElection.StopAndWait(cm.shutdownCtx)

		// Stop the caches before the leader election runnables, this is an important
		// step to make sure that we don't race with the reconcilers by receiving more events
		// from the API servers and enqueueing them.
		cm.logger.Info("Stopping and waiting for caches")
		cm.runnables.Caches.StopAndWait(cm.shutdownCtx)

		// Webhooks and internal HTTP servers should come last, as they might be still serving some requests.
		cm.logger.Info("Stopping and waiting for webhooks")
		cm.runnables.Webhooks.StopAndWait(cm.shutdownCtx)

		cm.logger.Info("Stopping and waiting for HTTP servers")
		cm.runnables.HTTPServers.StopAndWait(cm.shutdownCtx)

		// Proceed to close the manager and overall shutdown context.
		cm.logger.Info("Wait completed, proceeding to shutdown the manager")
		shutdownCancel()
	}()

	<-cm.shutdownCtx.Done()
	if err := cm.shutdownCtx.Err(); err != nil && !errors.Is(err, context.Canceled) {
		if errors.Is(err, context.DeadlineExceeded) {
			if cm.gracefulShutdownTimeout > 0 {
				return fmt.Errorf("failed waiting for all runnables to end within grace period of %s: %w", cm.gracefulShutdownTimeout, err)
			}
			return nil
		}
		// For any other error, return the error.
		return err
	}

	return nil
}

func (cm *controllerManager) startLeaderElectionRunnables() error {
	return cm.runnables.LeaderElection.Start(cm.internalCtx)
}

func (cm *controllerManager) startLeaderElection(ctx context.Context) (err error) {
	l, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:          cm.resourceLock,
		LeaseDuration: cm.leaseDuration,
		RenewDeadline: cm.renewDeadline,
		RetryPeriod:   cm.retryPeriod,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(_ context.Context) {
				if err := cm.startLeaderElectionRunnables(); err != nil {
					cm.errChan <- err
					return
				}
				close(cm.elected)
			},
			OnStoppedLeading: func() {
				if cm.onStoppedLeading != nil {
					cm.onStoppedLeading()
				}
				// Make sure graceful shutdown is skipped if we lost the leader lock without
				// intending to.
				cm.gracefulShutdownTimeout = time.Duration(0)
				// Most implementations of leader election log.Fatal() here.
				// Since Start is wrapped in log.Fatal when called, we can just return
				// an error here which will cause the program to exit.
				cm.errChan <- errors.New("leader election lost")
			},
		},
		ReleaseOnCancel: cm.leaderElectionReleaseOnCancel,
		Name:            cm.leaderElectionID,
	})
	if err != nil {
		return err
	}

	// Start the leader elector process
	go func() {
		l.Run(ctx)
		<-ctx.Done()
		close(cm.leaderElectionStopped)
	}()
	return nil
}

func (cm *controllerManager) Elected() <-chan struct{} {
	return cm.elected
}
