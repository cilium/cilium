// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

// TriggerPolicyUpdates triggers the policy update trigger.
//
// To follow what the trigger does, see NewUpdater.
func (u *Updater) TriggerPolicyUpdates(force bool, reason string) {
	if force {
		log.Debugf("Artificially increasing policy revision to enforce policy recalculation")
		u.repo.BumpRevision()
	}

	u.TriggerWithReason(reason)
}

// NewUpdater returns a new Updater instance to handle triggering policy
// updates ready for use.
func NewUpdater(r *Repository, regen regenerator) *Updater {
	t, err := trigger.NewTrigger(trigger.Parameters{
		Name:            "policy_update",
		MetricsObserver: &TriggerMetrics{},
		MinInterval:     option.Config.PolicyTriggerInterval,
		// Triggers policy updates for every local endpoint.
		// This may be called in a variety of situations: after policy changes,
		// changes in agent configuration, changes in endpoint labels, and
		// change of security identities.
		TriggerFunc: func(reasons []string) {
			log.Debug("Regenerating all endpoints")
			reason := strings.Join(reasons, ", ")

			regenerationMetadata := &regeneration.ExternalRegenerationMetadata{
				Reason:            reason,
				RegenerationLevel: regeneration.RegenerateWithoutDatapath,
			}
			regen.RegenerateAllEndpoints(regenerationMetadata)
		},
	})
	if err != nil {
		panic(err) // unreachable, only occurs if TriggerFunc is nil
	}
	return &Updater{
		Trigger: t,
		repo:    r,
	}
}

// Updater is responsible for triggering policy updates, in order to perform
// policy recalculation.
type Updater struct {
	*trigger.Trigger

	repo *Repository
}

type regenerator interface {
	// RegenerateAllEndpoints should trigger a regeneration of all endpoints.
	RegenerateAllEndpoints(*regeneration.ExternalRegenerationMetadata) *sync.WaitGroup
}

// TriggerMetrics handles the metrics for trigger policy recalculations.
type TriggerMetrics struct{}

func (p *TriggerMetrics) QueueEvent(reason string) {
	if metrics.TriggerPolicyUpdateTotal.IsEnabled() {
		metrics.TriggerPolicyUpdateTotal.WithLabelValues(reason).Inc()
	}
}

func (p *TriggerMetrics) PostRun(duration, latency time.Duration, folds int) {
	if metrics.TriggerPolicyUpdateCallDuration.IsEnabled() {
		metrics.TriggerPolicyUpdateCallDuration.WithLabelValues("duration").Observe(duration.Seconds())
		metrics.TriggerPolicyUpdateCallDuration.WithLabelValues("latency").Observe(latency.Seconds())
	}
	if metrics.TriggerPolicyUpdateFolds.IsEnabled() {
		metrics.TriggerPolicyUpdateFolds.Set(float64(folds))
	}
}
