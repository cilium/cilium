/*
Copyright 2023 The Kubernetes Authors.

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

package config

import (
	"time"

	"github.com/go-logr/logr"
)

// Controller contains configuration options for controllers. It only includes options
// that makes sense for a set of controllers and is used for defaulting the options
// of multiple controllers.
type Controller struct {
	// SkipNameValidation allows skipping the name validation that ensures that every controller name is unique.
	// Unique controller names are important to get unique metrics and logs for a controller.
	// Can be overwritten for a controller via the SkipNameValidation setting on the controller.
	// Defaults to false if SkipNameValidation setting on controller and Manager are unset.
	SkipNameValidation *bool

	// GroupKindConcurrency is a map from a Kind to the number of concurrent reconciliation
	// allowed for that controller.
	//
	// When a controller is registered within this manager using the builder utilities,
	// users have to specify the type the controller reconciles in the For(...) call.
	// If the object's kind passed matches one of the keys in this map, the concurrency
	// for that controller is set to the number specified.
	//
	// The key is expected to be consistent in form with GroupKind.String(),
	// e.g. ReplicaSet in apps group (regardless of version) would be `ReplicaSet.apps`.
	GroupKindConcurrency map[string]int

	// MaxConcurrentReconciles is the maximum number of concurrent Reconciles which can be run. Defaults to 1.
	MaxConcurrentReconciles int

	// CacheSyncTimeout refers to the time limit set to wait for syncing caches.
	// Defaults to 2 minutes if not set.
	CacheSyncTimeout time.Duration

	// RecoverPanic indicates whether the panic caused by reconcile should be recovered.
	// Can be overwritten for a controller via the RecoverPanic setting on the controller.
	// Defaults to true if RecoverPanic setting on controller and Manager are unset.
	RecoverPanic *bool

	// NeedLeaderElection indicates whether the controller needs to use leader election.
	// Defaults to true, which means the controller will use leader election.
	NeedLeaderElection *bool

	// EnableWarmup specifies whether the controller should start its sources when the manager is not
	// the leader. This is useful for cases where sources take a long time to start, as it allows
	// for the controller to warm up its caches even before it is elected as the leader. This
	// improves leadership failover time, as the caches will be prepopulated before the controller
	// transitions to be leader.
	//
	// Setting EnableWarmup to true and NeedLeaderElection to true means the controller will start its
	// sources without waiting to become leader.
	// Setting EnableWarmup to true and NeedLeaderElection to false is a no-op as controllers without
	// leader election do not wait on leader election to start their sources.
	// Defaults to false.
	//
	// Note: This feature is currently in beta and subject to change.
	// For more details, see: https://github.com/kubernetes-sigs/controller-runtime/issues/3220.
	EnableWarmup *bool

	// UsePriorityQueue configures the controllers queue to use the controller-runtime provided
	// priority queue.
	//
	// Note: This flag is enabled by default.
	// For more details, see: https://github.com/kubernetes-sigs/controller-runtime/issues/2374.
	UsePriorityQueue *bool

	// Logger is the logger controllers should use.
	Logger logr.Logger

	// ReconciliationTimeout is used as the timeout passed to the context of each Reconcile call.
	// By default, there is no timeout.
	ReconciliationTimeout time.Duration
}
