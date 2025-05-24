// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitycachecell

import (
	"cmp"
	"context"
	"log/slog"
	"maps"
	"net"
	"slices"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/stream"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
)

// Cell provides the IdentityAllocator for allocating security identities
var Cell = cell.Module(
	"identity",
	"Allocating and managing security identities",

	metrics.Metric(newIdentityCacheMetrics),

	cell.Provide(newIdentityAllocator),
	cell.Config(defaultConfig),
)

// CachingIdentityAllocator provides an abstraction over the concrete type in
// pkg/identity/cache so that the underlying implementation can be mocked out
// in unit tests.
type CachingIdentityAllocator interface {
	cache.IdentityAllocator
	clustermesh.RemoteIdentityWatcher

	InitIdentityAllocator(versioned.Interface) <-chan struct{}

	// RestoreLocalIdentities reads in the checkpointed local allocator state
	// from disk and allocates a reference to every previously existing identity.
	//
	// Once all identity-allocating objects are synchronized (e.g. network policies,
	// remote nodes), call ReleaseRestoredIdentities to release the held references.
	RestoreLocalIdentities() (map[identity.NumericIdentity]*identity.Identity, error)

	// ReleaseRestoredIdentities releases any identities that were restored, reducing their reference
	// count and cleaning up as necessary.
	ReleaseRestoredIdentities()

	Close()

	LocalIdentityChanges() stream.Observable[cache.IdentityChange]
}

type identityAllocatorParams struct {
	cell.In

	Log              *slog.Logger
	Registry         job.Registry
	Health           cell.Health
	Lifecycle        cell.Lifecycle
	PolicyRepository policy.PolicyRepository
	EPManager        endpointmanager.EndpointManager
	Metrics          *identityCacheMetrics

	IdentityHandlers []identity.UpdateIdentities `group:"identity-handlers"`

	Config config
}

type identityAllocatorOut struct {
	cell.Out

	IdentityAllocator      CachingIdentityAllocator
	CacheIdentityAllocator cache.IdentityAllocator
	RemoteIdentityWatcher  clustermesh.RemoteIdentityWatcher
	IdentityObservable     stream.Observable[cache.IdentityChange]
}

type config struct {
	IdentityManagementMode string `mapstructure:"identity-management-mode"`
}

func (c config) Flags(flags *pflag.FlagSet) {
	flags.String(option.IdentityManagementMode, c.IdentityManagementMode, "Configure whether Cilium Identities are managed by cilium-agent, cilium-operator, or both")
}

var defaultConfig = config{
	IdentityManagementMode: option.IdentityManagementModeAgent,
}

func newIdentityAllocator(params identityAllocatorParams) identityAllocatorOut {
	// iao: updates SelectorCache and regenerates endpoints when
	// identity allocation / deallocation has occurred.
	iao := &identityAllocatorOwner{
		logger:    params.Log,
		policy:    params.PolicyRepository,
		epmanager: params.EPManager,

		identityHandlers: params.IdentityHandlers,
	}

	var idAlloc CachingIdentityAllocator

	if option.NetworkPolicyEnabled(option.Config) {
		isOperatorManageCIDsEnabled := cmp.Or(
			params.Config.IdentityManagementMode == option.IdentityManagementModeOperator,
			params.Config.IdentityManagementMode == option.IdentityManagementModeBoth,
		)

		allocatorConfig := cache.AllocatorConfig{
			EnableOperatorManageCIDs: isOperatorManageCIDsEnabled,
		}

		// Allocator: allocates local and cluster-wide security identities.
		cacheIDAlloc := cache.NewCachingIdentityAllocator(params.Log, iao, allocatorConfig)
		cacheIDAlloc.EnableCheckpointing()

		idAlloc = cacheIDAlloc
	} else {
		idAlloc = cache.NewNoopIdentityAllocator(params.Log)
	}

	params.Lifecycle.Append(cell.Hook{
		OnStop: func(hc cell.HookContext) error {
			idAlloc.Close()
			return nil
		},
	})

	iao.updatePolicyMaps = job.NewTrigger()
	jg := params.Registry.NewGroup(params.Health, params.Lifecycle, job.WithMetrics(params.Metrics), job.WithLogger(params.Log))
	jg.Add(job.Timer("id-alloc-update-policy-maps", iao.doUpdatePolicyMaps,
		/* no interval, only on trigger */ 0, job.WithTrigger(iao.updatePolicyMaps)))

	return identityAllocatorOut{
		IdentityAllocator:      idAlloc,
		CacheIdentityAllocator: idAlloc,
		RemoteIdentityWatcher:  idAlloc,
		IdentityObservable:     idAlloc,
	}
}

// identityAllocatorOwner is used to break the circular dependency between
// CachingIdentityAllocator and policy.Repository.
type identityAllocatorOwner struct {
	logger    *slog.Logger
	policy    policy.PolicyRepository
	epmanager endpointmanager.EndpointManager

	identityHandlers []identity.UpdateIdentities

	// set of notification waitgroups to wait in for batched UpdatePolicyMaps,
	// and a mutex to protect for writing
	wgsLock        lock.Mutex
	wgs            []*sync.WaitGroup
	firstStartTime time.Time // the start time for the first batched update

	updatePolicyMaps job.Trigger
}

// UpdateIdentities informs the policy package of all identity changes
// and also triggers policy updates. Updates to the endpoints are batched.
//
// The caller is responsible for making sure the same identity is not
// present in both 'added' and 'deleted'.
func (iao *identityAllocatorOwner) UpdateIdentities(added, deleted identity.IdentityMap) {
	// Have we already seen this exact set of updates? If so, we can skip.
	// This happens when a global identity is allocated locally (for an Endpoint).
	// We will add the identity twice; once directly from the endpoint creation,
	// and again from the global identity watcher (k8s or kvstore).
	if iao.policy.GetSelectorCache().CanSkipUpdate(added, deleted) {
		iao.logger.Debug("Skipping no-op identity update")
		return
	}

	start := time.Now()

	iao.logger.Info(
		"Processing identity update",
		logfields.AddedPolicyID, slices.Collect(maps.Keys(added)),
		logfields.DeletedPolicyID, slices.Collect(maps.Keys(deleted)),
	)

	wg := &sync.WaitGroup{}
	for _, handler := range iao.identityHandlers {
		handler.UpdateIdentities(added, deleted, wg)
	}
	// Invoke policy selector cache always as the last handler
	// This synchronously updates the SelectorCache and queues an incremental
	// update to any selectors. The waitgroup is closed when all endpoints
	// have been notified.
	iao.policy.GetSelectorCache().UpdateIdentities(added, deleted, wg)

	// Direct endpoints to consume pending incremental updates.
	iao.wgsLock.Lock()
	iao.wgs = append(iao.wgs, wg)
	if iao.firstStartTime.IsZero() {
		iao.firstStartTime = start
	}
	iao.wgsLock.Unlock()
	iao.updatePolicyMaps.Trigger()
}

// doUpdatePolicyMaps is the function called by the trigger job; it waits on the
// accumulated notification waitgroups, then triggers endpoints to consume
// the incremental update.
func (iao *identityAllocatorOwner) doUpdatePolicyMaps(ctx context.Context) error {
	// take existing queue, make new empty queue, unlock
	iao.wgsLock.Lock()
	if len(iao.wgs) == 0 {
		iao.wgsLock.Unlock()
		return nil
	}
	wgs := iao.wgs
	start := iao.firstStartTime
	iao.wgs = nil
	iao.firstStartTime = time.Time{}
	iao.wgsLock.Unlock()

	iao.logger.Info(
		"Incremental policy update: waiting for endpoint notifications to complete",
		logfields.Count, len(wgs),
	)

	// Wait for all batched incremental updates to be finished with their notifications.
	wdc := make(chan struct{})
	go func() {
		for _, wg := range wgs {
			wg.Wait()
		}
		close(wdc)
	}()
	select {
	case <-wdc:
	case <-ctx.Done():
		return ctx.Err()
	}

	// UpdatePolicyMaps also waits for notifications to be complete, but we already waited :-)
	noopWG := &sync.WaitGroup{}

	// Direct all endpoints to consume the incremental changes and update policy.
	// This returns a wg that is done when all endpoints have updated both their bpf
	// policymaps as well as Envoy. (Or if ctx is closed).
	iao.logger.Info("Incremental policy update: triggering UpdatePolicyMaps for all endpoints")
	updatedWG := iao.epmanager.UpdatePolicyMaps(ctx, noopWG)
	updatedWG.Wait()
	metrics.PolicyIncrementalUpdateDuration.WithLabelValues("global").Observe(time.Since(start).Seconds())
	return nil
}

// GetNodeSuffix returns the suffix to be appended to kvstore keys of this
// agent
func (iao *identityAllocatorOwner) GetNodeSuffix() string {
	var ip net.IP

	switch {
	case option.Config.EnableIPv4:
		ip = node.GetIPv4(logging.DefaultSlogLogger)
	case option.Config.EnableIPv6:
		ip = node.GetIPv6(logging.DefaultSlogLogger)
	}

	if ip == nil {
		logging.Fatal(iao.logger, "Node IP not available yet")
	}

	return ip.String()
}
