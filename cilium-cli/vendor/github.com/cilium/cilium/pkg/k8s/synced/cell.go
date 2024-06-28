// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package synced

import (
	"context"
	"errors"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

type syncedParams struct {
	cell.In

	CacheStatus CacheStatus
}

var Cell = cell.Module(
	"k8s-synced",
	"Provides types for internal K8s resource synchronization",

	cell.Provide(func() *APIGroups {
		return new(APIGroups)
	}),

	cell.Provide(func(params syncedParams) *Resources {
		return &Resources{
			CacheStatus: params.CacheStatus,
		}
	}),

	cell.Provide(func() CacheStatus {
		return make(CacheStatus)
	}),
)

var CRDSyncCell = cell.Module(
	"k8s-synced-crdsync",
	"Provides promise for waiting for CRD to have been synchronized",

	cell.Provide(newCRDSyncPromise),
)

// CRDSync is an empty type used for promise.Promise. If SyncCRDs() fails, the error is passed via
// promise Reject to the result of the promise Await() call.
type CRDSync struct{}

// CRDSyncResourceNames is a slice of CRD resource names CRDSync promise waits for
type CRDSyncResourceNames []string

var ErrCRDSyncDisabled = errors.New("CRDSync promise is disabled")

// RejectedCRDSyncPromise can be used in hives that do not provide the CRDSync promise.
var RejectedCRDSyncPromise = func() promise.Promise[CRDSync] {
	crdSyncResolver, crdSyncPromise := promise.New[CRDSync]()
	crdSyncResolver.Reject(ErrCRDSyncDisabled)
	return crdSyncPromise
}

type syncCRDsPromiseParams struct {
	cell.In

	Lifecycle     cell.Lifecycle
	Jobs          job.Registry
	Health        cell.Health
	Clientset     client.Clientset
	Resources     *Resources
	APIGroups     *APIGroups
	ResourceNames CRDSyncResourceNames
}

func newCRDSyncPromise(params syncCRDsPromiseParams) promise.Promise[CRDSync] {
	crdSyncResolver, crdSyncPromise := promise.New[CRDSync]()
	if !params.Clientset.IsEnabled() || option.Config.DryMode {
		crdSyncResolver.Reject(ErrCRDSyncDisabled)
		return crdSyncPromise
	}

	g := params.Jobs.NewGroup(params.Health)
	g.Add(job.OneShot("sync-crds", func(ctx context.Context, health cell.Health) error {
		err := SyncCRDs(ctx, params.Clientset, params.ResourceNames, params.Resources, params.APIGroups)
		if err != nil {
			crdSyncResolver.Reject(err)
		} else {
			crdSyncResolver.Resolve(struct{}{})
		}
		return err
	}))
	params.Lifecycle.Append(g)

	return crdSyncPromise
}
