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
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"sigs.k8s.io/controller-runtime/pkg/internal/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/ratelimiter"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// Options are the arguments for creating a new Controller.
type Options struct {
	// MaxConcurrentReconciles is the maximum number of concurrent Reconciles which can be run. Defaults to 1.
	MaxConcurrentReconciles int

	// CacheSyncTimeout refers to the time limit set to wait for syncing caches.
	// Defaults to 2 minutes if not set.
	CacheSyncTimeout time.Duration

	// RecoverPanic indicates whether the panic caused by reconcile should be recovered.
	// Defaults to the Controller.RecoverPanic setting from the Manager if unset.
	RecoverPanic *bool

	// NeedLeaderElection indicates whether the controller needs to use leader election.
	// Defaults to true, which means the controller will use leader election.
	NeedLeaderElection *bool

	// Reconciler reconciles an object
	Reconciler reconcile.Reconciler

	// RateLimiter is used to limit how frequently requests may be queued.
	// Defaults to MaxOfRateLimiter which has both overall and per-item rate limiting.
	// The overall is a token bucket and the per-item is exponential.
	RateLimiter ratelimiter.RateLimiter

	// NewQueue constructs the queue for this controller once the controller is ready to start.
	// With NewQueue a custom queue implementation can be used, e.g. a priority queue to prioritize with which
	// priority/order objects are reconciled (e.g. to reconcile objects with changes first).
	// This is a func because the standard Kubernetes work queues start themselves immediately, which
	// leads to goroutine leaks if something calls controller.New repeatedly.
	// The NewQueue func gets the controller name and the RateLimiter option (defaulted if necessary) passed in.
	// NewQueue defaults to NewRateLimitingQueueWithConfig.
	//
	// NOTE: LOW LEVEL PRIMITIVE!
	// Only use a custom NewQueue if you know what you are doing.
	NewQueue func(controllerName string, rateLimiter ratelimiter.RateLimiter) workqueue.RateLimitingInterface

	// LogConstructor is used to construct a logger used for this controller and passed
	// to each reconciliation via the context field.
	LogConstructor func(request *reconcile.Request) logr.Logger
}

// Controller implements a Kubernetes API.  A Controller manages a work queue fed reconcile.Requests
// from source.Sources.  Work is performed through the reconcile.Reconciler for each enqueued item.
// Work typically is reads and writes Kubernetes objects to make the system state match the state specified
// in the object Spec.
type Controller interface {
	// Reconciler is called to reconcile an object by Namespace/Name
	reconcile.Reconciler

	// Watch watches the provided Source.
	Watch(src source.Source) error

	// Start starts the controller.  Start blocks until the context is closed or a
	// controller has an error starting.
	Start(ctx context.Context) error

	// GetLogger returns this controller logger prefilled with basic information.
	GetLogger() logr.Logger
}

// New returns a new Controller registered with the Manager.  The Manager will ensure that shared Caches have
// been synced before the Controller is Started.
func New(name string, mgr manager.Manager, options Options) (Controller, error) {
	c, err := NewUnmanaged(name, mgr, options)
	if err != nil {
		return nil, err
	}

	// Add the controller as a Manager components
	return c, mgr.Add(c)
}

// NewUnmanaged returns a new controller without adding it to the manager. The
// caller is responsible for starting the returned controller.
func NewUnmanaged(name string, mgr manager.Manager, options Options) (Controller, error) {
	if options.Reconciler == nil {
		return nil, fmt.Errorf("must specify Reconciler")
	}

	if len(name) == 0 {
		return nil, fmt.Errorf("must specify Name for Controller")
	}

	if options.LogConstructor == nil {
		log := mgr.GetLogger().WithValues(
			"controller", name,
		)
		options.LogConstructor = func(req *reconcile.Request) logr.Logger {
			log := log
			if req != nil {
				log = log.WithValues(
					"object", klog.KRef(req.Namespace, req.Name),
					"namespace", req.Namespace, "name", req.Name,
				)
			}
			return log
		}
	}

	if options.MaxConcurrentReconciles <= 0 {
		if mgr.GetControllerOptions().MaxConcurrentReconciles > 0 {
			options.MaxConcurrentReconciles = mgr.GetControllerOptions().MaxConcurrentReconciles
		} else {
			options.MaxConcurrentReconciles = 1
		}
	}

	if options.CacheSyncTimeout == 0 {
		if mgr.GetControllerOptions().CacheSyncTimeout != 0 {
			options.CacheSyncTimeout = mgr.GetControllerOptions().CacheSyncTimeout
		} else {
			options.CacheSyncTimeout = 2 * time.Minute
		}
	}

	if options.RateLimiter == nil {
		options.RateLimiter = workqueue.DefaultControllerRateLimiter()
	}

	if options.NewQueue == nil {
		options.NewQueue = func(controllerName string, rateLimiter ratelimiter.RateLimiter) workqueue.RateLimitingInterface {
			return workqueue.NewRateLimitingQueueWithConfig(rateLimiter, workqueue.RateLimitingQueueConfig{
				Name: controllerName,
			})
		}
	}

	if options.RecoverPanic == nil {
		options.RecoverPanic = mgr.GetControllerOptions().RecoverPanic
	}

	if options.NeedLeaderElection == nil {
		options.NeedLeaderElection = mgr.GetControllerOptions().NeedLeaderElection
	}

	// Create controller with dependencies set
	return &controller.Controller{
		Do:                      options.Reconciler,
		RateLimiter:             options.RateLimiter,
		NewQueue:                options.NewQueue,
		MaxConcurrentReconciles: options.MaxConcurrentReconciles,
		CacheSyncTimeout:        options.CacheSyncTimeout,
		Name:                    name,
		LogConstructor:          options.LogConstructor,
		RecoverPanic:            options.RecoverPanic,
		LeaderElected:           options.NeedLeaderElection,
	}, nil
}

// ReconcileIDFromContext gets the reconcileID from the current context.
var ReconcileIDFromContext = controller.ReconcileIDFromContext
