// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labelsfilterdynamic

import (
	"context"
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/endpointmanager"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/hive"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_networking_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/labelsfilterdynamic/signals"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "dynamic-labels-filter")
)

type controller struct {

	// Signal informs the Controller that a Kubernetes event of interest has occurred.
	// The signal itself provides no other information, when it occurs the Controller will query each informer for the latest API information required to drive its control loop.
	Signal                              *signals.Signal
	CiliumNetworkPolicy                 resource.Resource[*cilium_v2.CiliumNetworkPolicy]
	CiliumClusterwideNetworkPolicy      resource.Resource[*cilium_v2.CiliumClusterwideNetworkPolicy]
	NetworkPolicy                       resource.Resource[*slim_networking_v1.NetworkPolicy]
	CiliumNetworkPolicyStore            resource.Store[*cilium_v2.CiliumNetworkPolicy]
	CiliumClusterwideNetworkPolicyStore resource.Store[*cilium_v2.CiliumClusterwideNetworkPolicy]
	NetworkPolicyStore                  resource.Store[*slim_networking_v1.NetworkPolicy]
	EndpointManager                     endpointmanager.EndpointManager
	NamespaceResource                   resource.Resource[*slim_core_v1.Namespace]
	NamespaceResourceStore              resource.Store[*slim_core_v1.Namespace]
}

type controllerParams struct {
	cell.In

	Lifecycle                        cell.Lifecycle
	Health                           cell.Health
	JobGroup                         job.Group
	Shutdowner                       hive.Shutdowner
	Signal                           *signals.Signal
	CiliumNetworkPolicy              resource.Resource[*cilium_v2.CiliumNetworkPolicy]
	CiliumClusterWideNetworkPolicies resource.Resource[*cilium_v2.CiliumClusterwideNetworkPolicy]
	NetworkPolicy                    resource.Resource[*slim_networking_v1.NetworkPolicy]
	DaemonConfig                     *option.DaemonConfig
	EndpointManager                  endpointmanager.EndpointManager
	NamespaceResource                resource.Resource[*slim_core_v1.Namespace]
}

func registerController(params controllerParams) (*controller, error) {
	if !params.DaemonConfig.DynamicLabelFilterEnabled() {
		return nil, nil
	}
	c := &controller{
		Signal:                         params.Signal,
		CiliumNetworkPolicy:            params.CiliumNetworkPolicy,
		CiliumClusterwideNetworkPolicy: params.CiliumClusterWideNetworkPolicies,
		NetworkPolicy:                  params.NetworkPolicy,
		EndpointManager:                params.EndpointManager,
		NamespaceResource:              params.NamespaceResource,
	}

	params.JobGroup.Add(
		job.OneShot("dlf-cilium-network-policy-observer", func(ctx context.Context, health cell.Health) (err error) {
			for ev := range c.CiliumNetworkPolicy.Events(ctx) {
				switch ev.Kind {
				case resource.Upsert, resource.Delete:
					c.Signal.Event(struct{}{})
				}
				ev.Done(nil)
			}
			return nil
		}),

		job.OneShot("dlf-cilium-clusterwide-policy-observer", func(ctx context.Context, health cell.Health) (err error) {
			for ev := range c.CiliumClusterwideNetworkPolicy.Events(ctx) {
				switch ev.Kind {
				case resource.Upsert, resource.Delete:
					c.Signal.Event(struct{}{})
				}
				ev.Done(nil)
			}
			return nil
		}),

		job.OneShot("dlf-network-policy-observer", func(ctx context.Context, health cell.Health) (err error) {
			for ev := range c.NetworkPolicy.Events(ctx) {
				switch ev.Kind {
				case resource.Upsert, resource.Delete:
					c.Signal.Event(struct{}{})
				}
				ev.Done(nil)
			}
			return nil
		}),

		job.OneShot("dlf-controller",
			func(ctx context.Context, health cell.Health) (err error) {
				if c.initStore(ctx) != nil {
					health.Degraded("failed to init stores", err)
					return fmt.Errorf("error creating Dynamic Label Filter resource stores: %w", err)
				}

				// Trigger initial event
				c.Signal.Event(struct{}{})

				c.Run(ctx)
				health.OK("Ready")

				return nil
			},
			job.WithRetry(3, &job.ExponentialBackoff{Min: 100 * time.Millisecond, Max: time.Second}),
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
	c.NamespaceResourceStore, err = c.NamespaceResource.Store(ctx)
	if err != nil {
		return
	}

	return nil
}

// Run places the Controller into its control loop.
//
// When new events trigger a signal the control loop will be evaluated.
//
// A cancel of the provided ctx will kill the control loop along with the running
// informers.
func (c *controller) Run(ctx context.Context) {
	var (
		l = log.WithFields(logrus.Fields{
			"component": "Controller.Run",
		})
	)

	l.Info("Cilium Dynamic Label Filter Controller now running...")
	for {
		select {
		case <-ctx.Done():
			l.Info("Cilium Dynamic Label Filter Controller shut down")
			return
		case <-c.Signal.Signal:
			if err := c.Reconcile(ctx); err != nil {
				l.WithError(err).Error("Cilium Dynamic Label Filter Controller encountered error during reconciliation")
			} else {
				l.Debug("Cilium Dynamic Label Filter Controller successfully completed reconciliation")
			}
		}
	}
}

// Reconcile is the control loop for the Controller.
//
// Reconcile will be invoked when one or more event sources trigger a signal
// via the Controller's Signal structure.
//
// On signal, Reconcile will read all network policies selector key labels, construct a set,
// updates the labels filter and modifies the CEP to reflect the new label changes.
func (c *controller) Reconcile(_ context.Context) error {
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

	l.Debug("Dynamic labels to parse: ", keyLabels.UnsortedList())

	if err := labelsfilter.ParseLabelPrefixCfg(keyLabels.UnsortedList(), option.Config.NodeLabels, option.Config.LabelPrefixFile); err != nil {
		return fmt.Errorf("unable to parse dynamic labels prefix: %w", err)
	}

	for _, ep := range c.EndpointManager.GetEndpoints() {
		if pod := ep.GetPod(); pod != nil {
			podNamespace, _, err := c.NamespaceResourceStore.GetByKey(resource.Key{
				Name: pod.GetNamespace(),
			})
			if err != nil {
				l.WithError(err).Error("unable to fetch pod namespace") // shouldn't happen
				continue
			}

			allExistingLabels := mergeAllExistingLabels(pod.GetLabels(), ep.GetLabels(), podNamespace.GetLabels())
			newIdentityLabels, _ := labelsfilter.Filter(allExistingLabels)
			labelsToAdd, labelsToRemove := computeLabelsToAddAndRemove(newIdentityLabels, ep.GetLabels())

			if len(labelsToAdd) == 0 && len(labelsToRemove) == 0 {
				continue
			}

			l.Debugf("modifying endpoint %s labels to add: %s, remove: %s", ep.GetK8sCEPName(), labelsToAdd.String(), labelsToRemove.String())

			err = ep.ModifyIdentityLabels(labels.LabelSourceK8s, labelsToAdd, labelsToRemove)
			if err != nil {
				return fmt.Errorf("unable to update endpoint with new identity labels: %w", err)
			}
		}
	}

	return nil
}

// computeLabelsToAddAndRemove return the labels that are in identityLabels and labels that are only present in endpointLabels
func computeLabelsToAddAndRemove(identityLabels labels.Labels, endpointLabels []string) (labels.Labels, labels.Labels) {
	identityLabelsMap := identityLabels.StringMap()
	labelsToRemove := labels.Labels{}

	for _, label := range endpointLabels {
		l := labels.ParseLabel(label)
		lKey := l.Source + ":" + l.Key
		if _, ok := identityLabelsMap[lKey]; ok {
			delete(identityLabelsMap, lKey)
		} else {
			labelsToRemove[l.Key] = l
		}
	}

	return labels.Map2Labels(identityLabelsMap, ""), labelsToRemove
}

// mergeAllExistingLabels merges pod labels, existing endpoint labels and namespace labels together
func mergeAllExistingLabels(podLabels map[string]string, endpointLabels []string, namespaceLabels map[string]string) labels.Labels {
	exitingLabels := labels.Labels{}

	// Parse endpoint identity labels
	for _, label := range endpointLabels {
		l := labels.ParseLabel(label)
		exitingLabels[l.Key] = l
	}
	// Merge with pod labels
	exitingLabels.MergeLabels(labels.Map2Labels(podLabels, labels.LabelSourceK8s))

	// Append cilium PodNamespaceMetaLabels
	nsLabelMap := make(map[string]string, len(namespaceLabels))
	for k, v := range namespaceLabels {
		nsLabelMap[policy.JoinPath(ciliumio.PodNamespaceMetaLabels, k)] = v
	}
	// Merge with namespace labels
	exitingLabels.MergeLabels(labels.Map2Labels(nsLabelMap, labels.LabelSourceK8s))

	return exitingLabels
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
		if before == "any" {
			return ":" + after
		} else {
			return before + ":" + after
		}
	}

	return labelWithSourcePrefix
}
