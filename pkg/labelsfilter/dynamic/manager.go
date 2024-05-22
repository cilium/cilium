// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dynamic

import (
	"context"
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/trigger"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/hive"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_networking_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var (
	log           = logging.DefaultLogger.WithField(logfields.LogSubsys, "dynamic-labels-filter")
	jobTimeout    = &job.ExponentialBackoff{Min: 100 * time.Millisecond, Max: time.Second}
	jobRetryCount = 3
)

type controller struct {
	reconcileTrigger                    *trigger.Trigger
	CiliumNetworkPolicy                 resource.Resource[*cilium_v2.CiliumNetworkPolicy]
	CiliumClusterwideNetworkPolicy      resource.Resource[*cilium_v2.CiliumClusterwideNetworkPolicy]
	NetworkPolicy                       resource.Resource[*slim_networking_v1.NetworkPolicy]
	CiliumNetworkPolicyStore            resource.Store[*cilium_v2.CiliumNetworkPolicy]
	CiliumClusterwideNetworkPolicyStore resource.Store[*cilium_v2.CiliumClusterwideNetworkPolicy]
	NetworkPolicyStore                  resource.Store[*slim_networking_v1.NetworkPolicy]
}

type controllerParams struct {
	cell.In

	Lifecycle                        cell.Lifecycle
	Health                           cell.Health
	JobGroup                         job.Group
	Shutdowner                       hive.Shutdowner
	Config                           config
	CiliumNetworkPolicy              resource.Resource[*cilium_v2.CiliumNetworkPolicy]
	CiliumClusterWideNetworkPolicies resource.Resource[*cilium_v2.CiliumClusterwideNetworkPolicy]
	NetworkPolicy                    resource.Resource[*slim_networking_v1.NetworkPolicy]
}

func registerController(params controllerParams) (*controller, error) {
	if !params.Config.EnableDynamicLabelsFilter {
		return nil, nil
	}

	c := &controller{
		CiliumNetworkPolicy:            params.CiliumNetworkPolicy,
		CiliumClusterwideNetworkPolicy: params.CiliumClusterWideNetworkPolicies,
		NetworkPolicy:                  params.NetworkPolicy,
	}

	reconcileTrigger, err := trigger.NewTrigger(trigger.Parameters{
		MinInterval: 1 * time.Second, // TODO To be updated in phase 2 after agreeing on the design proposal
		TriggerFunc: func(reasons []string) {
			if err := c.Reconcile(); err != nil {
				log.WithError(err).Error("Dynamic Labels Filter Controller encountered error during reconciliation")
			} else {
				log.Debug("Dynamic Labels Filter Controller successfully completed reconciliation")
			}

		},
		Name: "dynamic-labels-filter-trigger",
	})

	if err != nil {
		log.WithError(err).Fatal("Unable to initialize dynamic labels filter synchronization trigger")
	}

	c.reconcileTrigger = reconcileTrigger

	params.JobGroup.Add(
		job.OneShot("dynamic-labels-filter-CNP-observer", func(ctx context.Context, health cell.Health) (err error) {
			for ev := range c.CiliumNetworkPolicy.Events(ctx) {
				switch ev.Kind {
				case resource.Upsert, resource.Delete:
					reconcileTrigger.Trigger()
				}
				ev.Done(nil)
			}
			return nil
		}),

		job.OneShot("dynamic-labels-filter-CCNP-observer", func(ctx context.Context, health cell.Health) (err error) {
			for ev := range c.CiliumClusterwideNetworkPolicy.Events(ctx) {
				switch ev.Kind {
				case resource.Upsert, resource.Delete:
					reconcileTrigger.Trigger()
				}
				ev.Done(nil)
			}
			return nil
		}),

		job.OneShot("dynamic-labels-filter-NP-observer", func(ctx context.Context, health cell.Health) (err error) {
			for ev := range c.NetworkPolicy.Events(ctx) {
				switch ev.Kind {
				case resource.Upsert, resource.Delete:
					reconcileTrigger.Trigger()
				}
				ev.Done(nil)
			}
			return nil
		}),

		job.OneShot("dynamic-labels-filter-init",
			func(ctx context.Context, health cell.Health) (err error) {
				if err = c.initStore(ctx); err != nil {
					health.Degraded("failed to init stores", err)
					return fmt.Errorf("error creating Dynamic Label Filter resource stores: %w", err)
				}

				// create initial trigger
				reconcileTrigger.Trigger()

				return nil
			},
			job.WithRetry(jobRetryCount, jobTimeout),
			job.WithShutdown()),
	)

	return c, nil
}

func (c *controller) initStore(ctx context.Context) (err error) {
	c.CiliumNetworkPolicyStore, err = c.CiliumNetworkPolicy.Store(ctx)
	if err != nil {
		return
	}
	c.NetworkPolicyStore, err = c.NetworkPolicy.Store(ctx)
	if err != nil {
		return
	}
	c.CiliumClusterwideNetworkPolicyStore, err = c.CiliumClusterwideNetworkPolicy.Store(ctx)
	if err != nil {
		return
	}

	return nil
}

// Reconcile is the control loop for the Controller.
//
// Reconcile will be invoked when one or more event sources trigger a signal
// via the Controller's Trigger structure.
//
// On signal, Reconcile will read all network policies selector key labels, construct a set,
// updates the labels filter and TODO reconcile in-place the affected pods generating new CIDs.
func (c *controller) Reconcile() error {
	var (
		l = log.WithFields(logrus.Fields{
			"component": "Controller.Reconcile",
		})
	)
	keyLabels := sets.New[string]()

	for _, policy := range c.CiliumNetworkPolicyStore.List() {
		keyLabels = keyLabels.Union(getRelevantKeyLabels(policy.Spec.EndpointSelector.MatchLabels, policy.Spec.EndpointSelector.MatchExpressions))
	}
	for _, policy := range c.CiliumClusterwideNetworkPolicyStore.List() {
		keyLabels = keyLabels.Union(getRelevantKeyLabels(policy.Spec.EndpointSelector.MatchLabels, policy.Spec.EndpointSelector.MatchExpressions))
	}
	for _, policy := range c.NetworkPolicyStore.List() {
		keyLabels = keyLabels.Union(getRelevantKeyLabels(policy.Spec.PodSelector.MatchLabels, policy.Spec.PodSelector.MatchExpressions))
	}

	l.Debug("dynamic labels to parse: ", keyLabels.UnsortedList())

	if err := labelsfilter.ParseLabelPrefixCfg(keyLabels.UnsortedList(), option.Config.NodeLabels, option.Config.LabelPrefixFile); err != nil {
		return fmt.Errorf("unable to parse Dynamic Label prefix: %w", err)
	}

	// TODO Phase 2: reconcile affected pods, update in-place so the old identities can be garbage collected

	return nil
}

// getRelevantKeyLabels extracts the label key from the MatchLabels and MatchExpressions.
// The extracted keys are being normalized to SOURCE:KEY from the extended format.
// If the SOURCE is any, the SOURCE will be an empty string to align with the default labels filters config.
func getRelevantKeyLabels(matchLabels map[string]slim_metav1.MatchLabelsValue, matchExpressionLabels []slim_metav1.LabelSelectorRequirement) sets.Set[string] {
	keyLabels := sets.New[string]()

	for key := range matchLabels {
		keyLabels.Insert(normalizeKeyLabel(key))
	}
	for _, expression := range matchExpressionLabels {
		keyLabels.Insert(normalizeKeyLabel(expression.Key))
	}

	return keyLabels
}

// normalizeKeyLabel converts the labels from the extended format source.key to SOURCE:KEY
// If the SOURCE is any the transformed value will be empty
// k8s.Foo converts to k8s:Foo, any.Foo converts to :Foo
func normalizeKeyLabel(labelWithSourcePrefix string) string {
	before, after, found := strings.Cut(labelWithSourcePrefix, ".")

	if found {
		if before == labels.LabelSourceAny {
			return ":" + after
		} else {
			return before + ":" + after
		}
	}

	return labelWithSourcePrefix
}
