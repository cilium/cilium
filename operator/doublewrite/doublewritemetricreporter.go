package doublewrite

import (
	"context"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/idpool"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/identitybackend"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/option"
	"github.com/sirupsen/logrus"
	"strconv"
	"time"
)

// params contains all the dependencies for the double-write-metric-reporter.
// They will be provided through dependency injection.
type params struct {
	cell.In

	Logger    logrus.FieldLogger
	Lifecycle cell.Lifecycle

	identity resource.Resource[*v2.CiliumIdentity]

	SharedCfg SharedConfig

	Metrics *Metrics
}

type DoubleWriteMetricReporter struct {
	logger logrus.FieldLogger

	interval time.Duration

	identity       resource.Resource[*v2.CiliumIdentity]
	kvStoreBackend *kvstoreallocator.KVStoreBackend

	mgr *controller.Manager

	metrics *Metrics
}

func registerDoubleWriteMetricReporter(p params) {
	doubleWriteMetricReporter := &DoubleWriteMetricReporter{
		logger:   p.Logger,
		interval: p.SharedCfg.Interval,
		identity: p.identity,
		metrics:  p.Metrics,
	}
	p.Lifecycle.Append(doubleWriteMetricReporter)
}

func (g *DoubleWriteMetricReporter) Start(ctx cell.HookContext) error {
	if option.Config.IdentityAllocationMode != option.IdentityAllocationModeDoubleWrite {
		return nil
	}
	g.logger.Info("Starting the Double Write Metric Reporter")

	backend, err := kvstoreallocator.NewKVStoreBackend(kvstoreallocator.KVStoreBackendConfiguration{BasePath: cache.IdentitiesPath, Suffix: "", Typ: nil, Backend: kvstore.Client()})
	if err != nil {
		g.logger.WithError(err).Error("Unable to initialize kvstore backend for the Double Write Metric Reporter")
		return err
	}
	g.kvStoreBackend = backend

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
	return nil
}

func (g *DoubleWriteMetricReporter) getCRDIdentityIds(ctx context.Context) (identityIds []idpool.ID, markedForDeletionCount int, err error) {
	identityStore, err := g.identity.Store(ctx)
	markedForDeletionCount = 0
	for _, identity := range identityStore.List() {
		idParsed, err := strconv.ParseUint(identity.Name, 10, 64)
		if err != nil {
			return []idpool.ID{}, 0, err
		}
		identityIds = append(identityIds, idpool.ID(idParsed))

		if _, ok := identity.Annotations[identitybackend.HeartBeatAnnotation]; ok {
			markedForDeletionCount++
		}
	}
	return identityIds, markedForDeletionCount, nil
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
	crdIdentityIds, markedForDeletionCount, err := g.getCRDIdentityIds(ctx)
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
	g.logger.Infof("CRD identities in total: %d (Marked for deletion: %d)\n"+
		"KVStore identities: %d\n"+
		"Identities only in CRD: %d. Example IDs (capped at %d): %v\n"+
		"Identities only in KVStore: %d. Example IDs (capped at %d): %v\n",
		len(crdIdentityIds), markedForDeletionCount, len(kvstoreIdentityIds), onlyInCrdCount, maxPrintedDiffIDs, onlyInCrdSample, onlyInKVStoreCount, maxPrintedDiffIDs, onlyInKVStoreSample)

	g.metrics.IdentityCRDTotalCount.Set(float64(len(crdIdentityIds)))
	g.metrics.IdentityKVStoreTotalCount.Set(float64(len(kvstoreIdentityIds)))
	g.metrics.IdentityCRDOnlyCount.Set(float64(onlyInCrdCount))
	g.metrics.IdentityKVStoreOnlyCount.Set(float64(onlyInKVStoreCount))

	return nil
}
