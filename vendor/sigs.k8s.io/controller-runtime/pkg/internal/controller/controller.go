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

package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/client-go/util/workqueue"

	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/internal/controller/metrics"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// Controller implements controller.Controller.
type Controller[request comparable] struct {
	// Name is used to uniquely identify a Controller in tracing, logging and monitoring.  Name is required.
	Name string

	// MaxConcurrentReconciles is the maximum number of concurrent Reconciles which can be run. Defaults to 1.
	MaxConcurrentReconciles int

	// Reconciler is a function that can be called at any time with the Name / Namespace of an object and
	// ensures that the state of the system matches the state specified in the object.
	// Defaults to the DefaultReconcileFunc.
	Do reconcile.TypedReconciler[request]

	// RateLimiter is used to limit how frequently requests may be queued into the work queue.
	RateLimiter workqueue.TypedRateLimiter[request]

	// NewQueue constructs the queue for this controller once the controller is ready to start.
	// This is a func because the standard Kubernetes work queues start themselves immediately, which
	// leads to goroutine leaks if something calls controller.New repeatedly.
	NewQueue func(controllerName string, rateLimiter workqueue.TypedRateLimiter[request]) workqueue.TypedRateLimitingInterface[request]

	// Queue is an listeningQueue that listens for events from Informers and adds object keys to
	// the Queue for processing
	Queue workqueue.TypedRateLimitingInterface[request]

	// mu is used to synchronize Controller setup
	mu sync.Mutex

	// Started is true if the Controller has been Started
	Started bool

	// ctx is the context that was passed to Start() and used when starting watches.
	//
	// According to the docs, contexts should not be stored in a struct: https://golang.org/pkg/context,
	// while we usually always strive to follow best practices, we consider this a legacy case and it should
	// undergo a major refactoring and redesign to allow for context to not be stored in a struct.
	ctx context.Context

	// CacheSyncTimeout refers to the time limit set on waiting for cache to sync
	// Defaults to 2 minutes if not set.
	CacheSyncTimeout time.Duration

	// startWatches maintains a list of sources, handlers, and predicates to start when the controller is started.
	startWatches []source.TypedSource[request]

	// LogConstructor is used to construct a logger to then log messages to users during reconciliation,
	// or for example when a watch is started.
	// Note: LogConstructor has to be able to handle nil requests as we are also using it
	// outside the context of a reconciliation.
	LogConstructor func(request *request) logr.Logger

	// RecoverPanic indicates whether the panic caused by reconcile should be recovered.
	// Defaults to true.
	RecoverPanic *bool

	// LeaderElected indicates whether the controller is leader elected or always running.
	LeaderElected *bool
}

// Reconcile implements reconcile.Reconciler.
func (c *Controller[request]) Reconcile(ctx context.Context, req request) (_ reconcile.Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			ctrlmetrics.ReconcilePanics.WithLabelValues(c.Name).Inc()

			if c.RecoverPanic == nil || *c.RecoverPanic {
				for _, fn := range utilruntime.PanicHandlers {
					fn(ctx, r)
				}
				err = fmt.Errorf("panic: %v [recovered]", r)
				return
			}

			log := logf.FromContext(ctx)
			log.Info(fmt.Sprintf("Observed a panic in reconciler: %v", r))
			panic(r)
		}
	}()
	return c.Do.Reconcile(ctx, req)
}

// Watch implements controller.Controller.
func (c *Controller[request]) Watch(src source.TypedSource[request]) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Controller hasn't started yet, store the watches locally and return.
	//
	// These watches are going to be held on the controller struct until the manager or user calls Start(...).
	if !c.Started {
		c.startWatches = append(c.startWatches, src)
		return nil
	}

	c.LogConstructor(nil).Info("Starting EventSource", "source", src)
	return src.Start(c.ctx, c.Queue)
}

// NeedLeaderElection implements the manager.LeaderElectionRunnable interface.
func (c *Controller[request]) NeedLeaderElection() bool {
	if c.LeaderElected == nil {
		return true
	}
	return *c.LeaderElected
}

// Start implements controller.Controller.
func (c *Controller[request]) Start(ctx context.Context) error {
	// use an IIFE to get proper lock handling
	// but lock outside to get proper handling of the queue shutdown
	c.mu.Lock()
	if c.Started {
		return errors.New("controller was started more than once. This is likely to be caused by being added to a manager multiple times")
	}

	c.initMetrics()

	// Set the internal context.
	c.ctx = ctx

	c.Queue = c.NewQueue(c.Name, c.RateLimiter)
	go func() {
		<-ctx.Done()
		c.Queue.ShutDown()
	}()

	wg := &sync.WaitGroup{}
	err := func() error {
		defer c.mu.Unlock()

		// TODO(pwittrock): Reconsider HandleCrash
		defer utilruntime.HandleCrash()

		// NB(directxman12): launch the sources *before* trying to wait for the
		// caches to sync so that they have a chance to register their intendeded
		// caches.
		for _, watch := range c.startWatches {
			c.LogConstructor(nil).Info("Starting EventSource", "source", fmt.Sprintf("%s", watch))

			if err := watch.Start(ctx, c.Queue); err != nil {
				return err
			}
		}

		// Start the SharedIndexInformer factories to begin populating the SharedIndexInformer caches
		c.LogConstructor(nil).Info("Starting Controller")

		for _, watch := range c.startWatches {
			syncingSource, ok := watch.(source.SyncingSource)
			if !ok {
				continue
			}

			if err := func() error {
				// use a context with timeout for launching sources and syncing caches.
				sourceStartCtx, cancel := context.WithTimeout(ctx, c.CacheSyncTimeout)
				defer cancel()

				// WaitForSync waits for a definitive timeout, and returns if there
				// is an error or a timeout
				if err := syncingSource.WaitForSync(sourceStartCtx); err != nil {
					err := fmt.Errorf("failed to wait for %s caches to sync: %w", c.Name, err)
					c.LogConstructor(nil).Error(err, "Could not wait for Cache to sync")
					return err
				}

				return nil
			}(); err != nil {
				return err
			}
		}

		// All the watches have been started, we can reset the local slice.
		//
		// We should never hold watches more than necessary, each watch source can hold a backing cache,
		// which won't be garbage collected if we hold a reference to it.
		c.startWatches = nil

		// Launch workers to process resources
		c.LogConstructor(nil).Info("Starting workers", "worker count", c.MaxConcurrentReconciles)
		wg.Add(c.MaxConcurrentReconciles)
		for i := 0; i < c.MaxConcurrentReconciles; i++ {
			go func() {
				defer wg.Done()
				// Run a worker thread that just dequeues items, processes them, and marks them done.
				// It enforces that the reconcileHandler is never invoked concurrently with the same object.
				for c.processNextWorkItem(ctx) {
				}
			}()
		}

		c.Started = true
		return nil
	}()
	if err != nil {
		return err
	}

	<-ctx.Done()
	c.LogConstructor(nil).Info("Shutdown signal received, waiting for all workers to finish")
	wg.Wait()
	c.LogConstructor(nil).Info("All workers finished")
	return nil
}

// processNextWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the reconcileHandler.
func (c *Controller[request]) processNextWorkItem(ctx context.Context) bool {
	obj, shutdown := c.Queue.Get()
	if shutdown {
		// Stop working
		return false
	}

	// We call Done here so the workqueue knows we have finished
	// processing this item. We also must remember to call Forget if we
	// do not want this work item being re-queued. For example, we do
	// not call Forget if a transient error occurs, instead the item is
	// put back on the workqueue and attempted again after a back-off
	// period.
	defer c.Queue.Done(obj)

	ctrlmetrics.ActiveWorkers.WithLabelValues(c.Name).Add(1)
	defer ctrlmetrics.ActiveWorkers.WithLabelValues(c.Name).Add(-1)

	c.reconcileHandler(ctx, obj)
	return true
}

const (
	labelError        = "error"
	labelRequeueAfter = "requeue_after"
	labelRequeue      = "requeue"
	labelSuccess      = "success"
)

func (c *Controller[request]) initMetrics() {
	ctrlmetrics.ReconcileTotal.WithLabelValues(c.Name, labelError).Add(0)
	ctrlmetrics.ReconcileTotal.WithLabelValues(c.Name, labelRequeueAfter).Add(0)
	ctrlmetrics.ReconcileTotal.WithLabelValues(c.Name, labelRequeue).Add(0)
	ctrlmetrics.ReconcileTotal.WithLabelValues(c.Name, labelSuccess).Add(0)
	ctrlmetrics.ReconcileErrors.WithLabelValues(c.Name).Add(0)
	ctrlmetrics.TerminalReconcileErrors.WithLabelValues(c.Name).Add(0)
	ctrlmetrics.ReconcilePanics.WithLabelValues(c.Name).Add(0)
	ctrlmetrics.WorkerCount.WithLabelValues(c.Name).Set(float64(c.MaxConcurrentReconciles))
	ctrlmetrics.ActiveWorkers.WithLabelValues(c.Name).Set(0)
}

func (c *Controller[request]) reconcileHandler(ctx context.Context, req request) {
	// Update metrics after processing each item
	reconcileStartTS := time.Now()
	defer func() {
		c.updateMetrics(time.Since(reconcileStartTS))
	}()

	log := c.LogConstructor(&req)
	reconcileID := uuid.NewUUID()

	log = log.WithValues("reconcileID", reconcileID)
	ctx = logf.IntoContext(ctx, log)
	ctx = addReconcileID(ctx, reconcileID)

	// RunInformersAndControllers the syncHandler, passing it the Namespace/Name string of the
	// resource to be synced.
	log.V(5).Info("Reconciling")
	result, err := c.Reconcile(ctx, req)
	switch {
	case err != nil:
		if errors.Is(err, reconcile.TerminalError(nil)) {
			ctrlmetrics.TerminalReconcileErrors.WithLabelValues(c.Name).Inc()
		} else {
			c.Queue.AddRateLimited(req)
		}
		ctrlmetrics.ReconcileErrors.WithLabelValues(c.Name).Inc()
		ctrlmetrics.ReconcileTotal.WithLabelValues(c.Name, labelError).Inc()
		if !result.IsZero() {
			log.Info("Warning: Reconciler returned both a non-zero result and a non-nil error. The result will always be ignored if the error is non-nil and the non-nil error causes reqeueuing with exponential backoff. For more details, see: https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/reconcile#Reconciler")
		}
		log.Error(err, "Reconciler error")
	case result.RequeueAfter > 0:
		log.V(5).Info(fmt.Sprintf("Reconcile done, requeueing after %s", result.RequeueAfter))
		// The result.RequeueAfter request will be lost, if it is returned
		// along with a non-nil error. But this is intended as
		// We need to drive to stable reconcile loops before queuing due
		// to result.RequestAfter
		c.Queue.Forget(req)
		c.Queue.AddAfter(req, result.RequeueAfter)
		ctrlmetrics.ReconcileTotal.WithLabelValues(c.Name, labelRequeueAfter).Inc()
	case result.Requeue:
		log.V(5).Info("Reconcile done, requeueing")
		c.Queue.AddRateLimited(req)
		ctrlmetrics.ReconcileTotal.WithLabelValues(c.Name, labelRequeue).Inc()
	default:
		log.V(5).Info("Reconcile successful")
		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
		c.Queue.Forget(req)
		ctrlmetrics.ReconcileTotal.WithLabelValues(c.Name, labelSuccess).Inc()
	}
}

// GetLogger returns this controller's logger.
func (c *Controller[request]) GetLogger() logr.Logger {
	return c.LogConstructor(nil)
}

// updateMetrics updates prometheus metrics within the controller.
func (c *Controller[request]) updateMetrics(reconcileTime time.Duration) {
	ctrlmetrics.ReconcileTime.WithLabelValues(c.Name).Observe(reconcileTime.Seconds())
}

// ReconcileIDFromContext gets the reconcileID from the current context.
func ReconcileIDFromContext(ctx context.Context) types.UID {
	r, ok := ctx.Value(reconcileIDKey{}).(types.UID)
	if !ok {
		return ""
	}

	return r
}

// reconcileIDKey is a context.Context Value key. Its associated value should
// be a types.UID.
type reconcileIDKey struct{}

func addReconcileID(ctx context.Context, reconcileID types.UID) context.Context {
	return context.WithValue(ctx, reconcileIDKey{}, reconcileID)
}
