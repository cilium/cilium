// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package doublewrite

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/key"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/identitybackend"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/kvstore/allocator/doublewrite"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/slices"
)

// params contains all the dependencies for the double-write-metric-reporter.
// They will be provided through dependency injection.
type params struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle

	Clientset k8sClient.Clientset

	Cfg Config

	Metrics *Metrics
}

type DoubleWriteMetricReporter struct {
	logger *slog.Logger

	interval time.Duration

	kvStoreBackend        allocator.Backend
	clientset             k8sClient.Clientset
	crdBackend            allocator.Backend
	crdBackendWatcherStop context.CancelFunc
	crdBackendListDone    chan struct{}

	mgr *controller.Manager
	wg  sync.WaitGroup

	metrics *Metrics
}

func registerDoubleWriteMetricReporter(p params) {
	if option.Config.IdentityAllocationMode != option.IdentityAllocationModeDoubleWriteReadKVstore && option.Config.IdentityAllocationMode != option.IdentityAllocationModeDoubleWriteReadCRD {
		return
	}
	doubleWriteMetricReporter := &DoubleWriteMetricReporter{
		logger:    p.Logger,
		interval:  p.Cfg.Interval,
		clientset: p.Clientset,
		metrics:   p.Metrics,
	}
	p.Lifecycle.Append(doubleWriteMetricReporter)
}

type NoOpHandlerWithListDone struct {
	doublewrite.NoOpHandler

	listDone chan struct{}
}

func (h NoOpHandlerWithListDone) OnListDone() {
	close(h.listDone)
}

func (g *DoubleWriteMetricReporter) Start(ctx cell.HookContext) error {
	g.logger.Info("Starting the Double Write Metric Reporter")

	kvStoreBackend, err := kvstoreallocator.NewKVStoreBackend(g.logger, kvstoreallocator.KVStoreBackendConfiguration{BasePath: cache.IdentitiesPath, Suffix: "", Typ: nil, Backend: kvstore.Client()})
	if err != nil {
		g.logger.Error("Unable to initialize kvstore backend for the Double Write Metric Reporter", logfields.Error, err)
		return err
	}
	g.kvStoreBackend = kvStoreBackend

	crdBackend, err := identitybackend.NewCRDBackend(g.logger, identitybackend.CRDBackendConfiguration{Store: nil, StoreSet: &atomic.Bool{}, Client: g.clientset, KeyFunc: (&key.GlobalIdentity{}).PutKeyFromMap})
	if err != nil {
		g.logger.Error("Unable to initialize CRD backend for the Double Write Metric Reporter", logfields.Error, err)
		return err
	}
	g.crdBackend = crdBackend
	// Initialize the CRD backend store
	var cctx context.Context
	cctx, g.crdBackendWatcherStop = context.WithCancel(context.Background())
	g.crdBackendListDone = make(chan struct{})
	g.wg = sync.WaitGroup{}
	g.wg.Add(1)
	go func() {
		g.crdBackend.ListAndWatch(cctx, NoOpHandlerWithListDone{listDone: g.crdBackendListDone})
		g.wg.Done()
	}()

	g.mgr = controller.NewManager()
	g.mgr.UpdateController("double-write-metric-reporter",
		controller.ControllerParams{
			Group:       controller.NewGroup("double-write-metric-reporter"),
			RunInterval: g.interval,
			DoFunc:      g.compareCRDAndKVStoreIdentities,
		})

	return nil
}

func (g *DoubleWriteMetricReporter) Stop(ctx cell.HookContext) error {
	if g.mgr != nil {
		g.mgr.RemoveAllAndWait()
	}

	if g.crdBackendWatcherStop != nil {
		g.crdBackendWatcherStop()
	}

	g.wg.Wait()
	return nil
}

func (g *DoubleWriteMetricReporter) compareCRDAndKVStoreIdentities(ctx context.Context) error {
	select {
	case <-g.crdBackendListDone:
	case <-ctx.Done():
		return ctx.Err()
	}

	// Get CRD identities
	crdIdentityIds, err := g.crdBackend.ListIDs(ctx)
	if err != nil {
		g.logger.Error("Unable to get CRD identities", logfields.Error, err)
		return err
	}

	// Get KVStore identities
	kvstoreIdentityIds, err := g.kvStoreBackend.ListIDs(ctx)
	if err != nil {
		g.logger.Error("Unable to get KVStore identities", logfields.Error, err)
		return err
	}

	// Compare CRD and KVStore identities
	maxPrintedDiffIDs := 5 // Cap the number of differing IDs so as not to log too many
	onlyInCrd := slices.Diff(crdIdentityIds, kvstoreIdentityIds)
	onlyInKVStore := slices.Diff(kvstoreIdentityIds, crdIdentityIds)
	onlyInCrdCount := len(onlyInCrd)
	onlyInKVStoreCount := len(onlyInKVStore)
	onlyInCrdSample := onlyInCrd[:min(onlyInCrdCount, maxPrintedDiffIDs)]
	onlyInKVStoreSample := onlyInKVStore[:min(onlyInKVStoreCount, maxPrintedDiffIDs)]

	g.metrics.CRDIdentities.Set(float64(len(crdIdentityIds)))
	g.metrics.KVStoreIdentities.Set(float64(len(kvstoreIdentityIds)))
	g.metrics.CRDOnlyIdentities.Set(float64(onlyInCrdCount))
	g.metrics.KVStoreOnlyIdentities.Set(float64(onlyInKVStoreCount))

	if onlyInCrdCount == 0 && onlyInKVStoreCount == 0 {
		g.logger.Info("CRD and KVStore identities are in sync")
	} else {
		g.logger.Info("Detected differences between CRD and KVStore identities",
			logfields.CRDIdentityCount, len(crdIdentityIds),
			logfields.KVStoreIdentityCount, len(kvstoreIdentityIds),
			logfields.OnlyInCRDCount, onlyInCrdCount,
			logfields.OnlyInKVStoreCount, onlyInKVStoreCount,
			logfields.OnlyInCRDSample, onlyInCrdSample,
			logfields.OnlyInKVStoreSample, onlyInKVStoreSample,
		)

	}

	return nil
}
