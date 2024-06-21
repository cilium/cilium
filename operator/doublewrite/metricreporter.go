// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package doublewrite

import (
	"context"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity/key"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/identitybackend"

	"github.com/sirupsen/logrus"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/kvstore/allocator/doublewrite"
	"github.com/cilium/cilium/pkg/option"
)

// params contains all the dependencies for the double-write-metric-reporter.
// They will be provided through dependency injection.
type params struct {
	cell.In

	Logger    logrus.FieldLogger
	Lifecycle cell.Lifecycle

	Clientset k8sClient.Clientset

	Cfg Config

	Metrics *Metrics
}

type DoubleWriteMetricReporter struct {
	logger logrus.FieldLogger

	interval time.Duration

	kvStoreBackend            allocator.Backend
	clientset                 k8sClient.Clientset
	crdBackend                allocator.Backend
	crdBackendWatcherStopChan chan struct{}
	crdBackendListDone        chan struct{}

	mgr *controller.Manager
	wg  sync.WaitGroup

	metrics *Metrics
}

func registerDoubleWriteMetricReporter(p params) {
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
	if option.Config.IdentityAllocationMode != option.IdentityAllocationModeDoubleWriteReadKVstore && option.Config.IdentityAllocationMode != option.IdentityAllocationModeDoubleWriteReadCRD {
		return nil
	}
	g.logger.Info("Starting the Double Write Metric Reporter")

	kvStoreBackend, err := kvstoreallocator.NewKVStoreBackend(kvstoreallocator.KVStoreBackendConfiguration{BasePath: cache.IdentitiesPath, Suffix: "", Typ: nil, Backend: kvstore.Client()})
	if err != nil {
		g.logger.WithError(err).Error("Unable to initialize kvstore backend for the Double Write Metric Reporter")
		return err
	}
	g.kvStoreBackend = kvStoreBackend

	crdBackend, err := identitybackend.NewCRDBackend(identitybackend.CRDBackendConfiguration{Store: nil, Client: g.clientset, KeyFunc: (&key.GlobalIdentity{}).PutKeyFromMap})
	if err != nil {
		g.logger.WithError(err).Error("Unable to initialize CRD backend for the Double Write Metric Reporter")
		return err
	}
	g.crdBackend = crdBackend
	// Initialize the CRD backend store
	g.crdBackendWatcherStopChan = make(chan struct{})
	g.crdBackendListDone = make(chan struct{})
	g.wg = sync.WaitGroup{}
	g.wg.Add(1)
	go func() {
		g.crdBackend.ListAndWatch(context.Background(), NoOpHandlerWithListDone{listDone: g.crdBackendListDone}, g.crdBackendWatcherStopChan)
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
	close(g.crdBackendWatcherStopChan)
	g.wg.Wait()
	return nil
}

// difference counts the elements in `a` that aren't in `b` and returns a sample of differing elements (up to `maxElements`)
func difference(a, b []idpool.ID, maxElements int) (int, []idpool.ID) {
	mb := make(map[idpool.ID]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	c := 0
	var diff []idpool.ID
	for _, x := range a {
		if _, found := mb[x]; !found {
			c++
			if len(diff) < maxElements {
				diff = append(diff, x)
			}
		}
	}
	return c, diff
}

func (g *DoubleWriteMetricReporter) compareCRDAndKVStoreIdentities(ctx context.Context) error {
	// Get CRD identities
	<-g.crdBackendListDone
	crdIdentityIds, err := g.crdBackend.ListIDs(ctx)
	if err != nil {
		g.logger.WithError(err).Error("Unable to get CRD identities")
		return err
	}

	// Get KVStore identities
	kvstoreIdentityIds, err := g.kvStoreBackend.ListIDs(ctx)
	if err != nil {
		g.logger.WithError(err).Error("Unable to get KVStore identities")
		return err
	}

	// Compare CRD and KVStore identities
	maxPrintedDiffIDs := 5 // Cap the number of differing IDs so as not to log too many
	onlyInCrdCount, onlyInCrdSample := difference(crdIdentityIds, kvstoreIdentityIds, maxPrintedDiffIDs)
	onlyInKVStoreCount, onlyInKVStoreSample := difference(kvstoreIdentityIds, crdIdentityIds, maxPrintedDiffIDs)
	g.logger.Infof("CRD identities: %d\n"+
		"KVStore identities: %d\n"+
		"Identities only in CRD: %d. Example IDs (capped at %d): %v\n"+
		"Identities only in KVStore: %d. Example IDs (capped at %d): %v\n",
		len(crdIdentityIds), len(kvstoreIdentityIds), onlyInCrdCount, maxPrintedDiffIDs, onlyInCrdSample, onlyInKVStoreCount, maxPrintedDiffIDs, onlyInKVStoreSample)

	g.metrics.IdentityCRDTotalCount.Set(float64(len(crdIdentityIds)))
	g.metrics.IdentityKVStoreTotalCount.Set(float64(len(kvstoreIdentityIds)))
	g.metrics.IdentityCRDOnlyCount.Set(float64(onlyInCrdCount))
	g.metrics.IdentityKVStoreOnlyCount.Set(float64(onlyInKVStoreCount))

	return nil
}
