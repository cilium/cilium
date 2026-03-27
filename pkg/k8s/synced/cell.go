// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package synced

import (
	"context"
	"errors"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/slices"
	"github.com/cilium/cilium/pkg/time"
)

type syncedParams struct {
	cell.In

	Logger      *slog.Logger
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
			logger:      params.Logger,
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
	cell.Config(DefaultCRDSyncConfig),
)

type CRDSyncConfig struct {
	CRDWaitTimeout time.Duration
}

var DefaultCRDSyncConfig = CRDSyncConfig{
	CRDWaitTimeout: 5 * time.Minute,
}

func (def CRDSyncConfig) Flags(flags *pflag.FlagSet) {
	flags.Duration("crd-wait-timeout", def.CRDWaitTimeout, "Cilium will exit if CRDs are not available within this duration upon startup")
}

// CRDSync is an empty type used for promise.Promise. If SyncCRDs() fails, the error is passed via
// promise Reject to the result of the promise Await() call.
type CRDSync struct{}

// CRDSyncResourceName represents a CRD resource name CRDSync promise waits for
type CRDSyncResourceName string

// CRDSyncResourceNamesOut is a utility struct for providing a list of [CRDSyncResourceName] to the hive.
type CRDSyncResourceNamesOut struct {
	cell.Out

	Names []CRDSyncResourceName `group:"crd-sync-resource-names,flatten"`
}

func NewCRDSyncResourceNamesOut(names ...string) (out CRDSyncResourceNamesOut) {
	out.Names = slices.Map(names,
		func(name string) CRDSyncResourceName {
			return CRDSyncResourceName(name)
		},
	)
	return out
}

var ErrCRDSyncDisabled = errors.New("CRDSync promise is disabled")

// RejectedCRDSyncPromise can be used in hives that do not provide the CRDSync promise.
var RejectedCRDSyncPromise = func() promise.Promise[CRDSync] {
	crdSyncResolver, crdSyncPromise := promise.New[CRDSync]()
	crdSyncResolver.Reject(ErrCRDSyncDisabled)
	return crdSyncPromise
}

type syncCRDsPromiseParams struct {
	cell.In

	Logger *slog.Logger

	JobGroup      job.Group
	Clientset     client.Clientset
	Resources     *Resources
	APIGroups     *APIGroups
	ResourceNames []CRDSyncResourceName `group:"crd-sync-resource-names"`
	Config        CRDSyncConfig
}

func newCRDSyncPromise(params syncCRDsPromiseParams) promise.Promise[CRDSync] {
	crdSyncResolver, crdSyncPromise := promise.New[CRDSync]()
	if !params.Clientset.IsEnabled() || option.Config.DryMode {
		crdSyncResolver.Reject(ErrCRDSyncDisabled)
		return crdSyncPromise
	}

	params.JobGroup.Add(job.OneShot("sync-crds", func(ctx context.Context, health cell.Health) error {
		names := slices.Map(params.ResourceNames, func(in CRDSyncResourceName) string { return string(in) })
		err := SyncCRDs(ctx, params.Logger, params.Clientset, names, params.Resources, params.APIGroups, params.Config)
		if err != nil {
			crdSyncResolver.Reject(err)
		} else {
			crdSyncResolver.Resolve(struct{}{})
		}
		return err
	}))

	return crdSyncPromise
}
