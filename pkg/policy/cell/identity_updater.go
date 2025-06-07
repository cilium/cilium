// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policycell

import (
	"context"
	"log/slog"
	"maps"
	"slices"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
)

type IdentityUpdater interface {
	// UpdateIdentities informs the SelectorCache of new identities, which then
	// distributes incremental updates to all endpoints. It also triggers endpoints
	// to consume the incremental updates and apply them to the BPF policy maps.
	//
	// The caller is responsible for making sure the same identity is not
	// present in both 'added' and 'deleted'.
	UpdateIdentities(added, deleted identity.IdentityMap)
}

type identityAllocatorParams struct {
	cell.In

	Log              *slog.Logger
	Registry         job.Registry
	Lifecycle        cell.Lifecycle
	PolicyRepository policy.PolicyRepository
	EPManager        endpointmanager.EndpointManager
	Health           cell.Health
	Metrics          *identityUpdaterMetrics

	IdentityHandlers []identity.UpdateIdentities `group:"identity-handlers"`
}

// identityUpdater is used to break the circular dependency between
// CachingIdentityAllocator and policy.Repository.
type identityUpdater struct {
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

func newIdentityUpdater(params identityAllocatorParams) IdentityUpdater {
	i := &identityUpdater{
		logger:    params.Log,
		policy:    params.PolicyRepository,
		epmanager: params.EPManager,

		identityHandlers: params.IdentityHandlers,
	}
	i.updatePolicyMaps = job.NewTrigger()
	jg := params.Registry.NewGroup(params.Health, params.Lifecycle, job.WithMetrics(params.Metrics), job.WithLogger(params.Log))
	jg.Add(job.Timer("id-alloc-update-policy-maps", i.doUpdatePolicyMaps,
		/* no interval, only on trigger */ 0, job.WithTrigger(i.updatePolicyMaps)))

	return i
}

// UpdateIdentities informs the SelectorCache of new identities, which then
// distributes incremental updates to all endpoints. It also triggers endpoints
// to consume the incremental updates and apply them to the BPF policy maps.
//
// The caller is responsible for making sure the same identity is not
// present in both 'added' and 'deleted'.
func (i *identityUpdater) UpdateIdentities(added, deleted identity.IdentityMap) {
	// Have we already seen this exact set of updates? If so, we can skip.
	// This happens when a global identity is allocated locally (for an Endpoint).
	// We will add the identity twice; once directly from the endpoint creation,
	// and again from the global identity watcher (k8s or kvstore).
	if i.policy.GetSelectorCache().CanSkipUpdate(added, deleted) {
		i.logger.Debug("Skipping no-op identity update")
		return
	}

	start := time.Now()

	i.logger.Info(
		"Processing identity update",
		logfields.AddedPolicyID, slices.Collect(maps.Keys(added)),
		logfields.DeletedPolicyID, slices.Collect(maps.Keys(deleted)),
	)

	wg := &sync.WaitGroup{}
	for _, handler := range i.identityHandlers {
		handler.UpdateIdentities(added, deleted, wg)
	}
	// Invoke policy selector cache always as the last handler
	// This synchronously updates the SelectorCache and queues an incremental
	// update to any selectors. The waitgroup is closed when all endpoints
	// have been notified.
	i.policy.GetSelectorCache().UpdateIdentities(added, deleted, wg)

	// Direct endpoints to consume pending incremental updates.
	i.wgsLock.Lock()
	i.wgs = append(i.wgs, wg)
	if i.firstStartTime.IsZero() {
		i.firstStartTime = start
	}
	i.wgsLock.Unlock()
	i.updatePolicyMaps.Trigger()
}

// doUpdatePolicyMaps is the function called by the trigger job; it waits on the
// accumulated notification waitgroups, then triggers endpoints to consume
// the incremental update.
func (i *identityUpdater) doUpdatePolicyMaps(ctx context.Context) error {
	// take existing queue, make new empty queue, unlock
	i.wgsLock.Lock()
	if len(i.wgs) == 0 {
		i.wgsLock.Unlock()
		return nil
	}
	wgs := i.wgs
	start := i.firstStartTime
	i.wgs = nil
	i.firstStartTime = time.Time{}
	i.wgsLock.Unlock()

	i.logger.Info(
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
	i.logger.Info("Incremental policy update: triggering UpdatePolicyMaps for all endpoints")
	updatedWG := i.epmanager.UpdatePolicyMaps(ctx, noopWG)
	updatedWG.Wait()
	metrics.PolicyIncrementalUpdateDuration.WithLabelValues("global").Observe(time.Since(start).Seconds())
	return nil
}

type identityUpdaterMetrics struct {
	TriggerLatency metric.Vec[metric.Observer]
	TriggerFolds   metric.Vec[metric.Observer]
	TimerDuration  metric.Vec[metric.Observer]
}

var _ job.Metrics = &identityUpdaterMetrics{}

const subsystem = "identity_updater"

func newIdentityUpdaterMetrics() *identityUpdaterMetrics {
	return &identityUpdaterMetrics{
		TriggerLatency: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "timer_trigger_latency",
			Help:      "The total time spent waiting for a timer to be ready to start",
		}, []string{"name"}),
		TriggerFolds: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "timer_trigger_folds",
			Help:      "The number of pending requests served by a single timer invocation",
		}, []string{"name"}),
		TimerDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "timer_duration",
			Help:      "The execution duration for a timer",
		}, []string{"name"}),
	}
}

func (m *identityUpdaterMetrics) TimerRunDuration(name string, duration time.Duration) {
	m.TimerDuration.WithLabelValues(name).Observe(duration.Seconds())
}

func (m *identityUpdaterMetrics) TimerTriggerStats(name string, latency time.Duration, folds int) {
	m.TriggerLatency.WithLabelValues(name).Observe(latency.Seconds())
	m.TriggerFolds.WithLabelValues(name).Observe(float64(folds))
}

func (m *identityUpdaterMetrics) JobError(name string, err error) {
}

func (m *identityUpdaterMetrics) ObserverRunDuration(name string, duration time.Duration) {
}

func (m *identityUpdaterMetrics) OneShotRunDuration(name string, duration time.Duration) {
}
