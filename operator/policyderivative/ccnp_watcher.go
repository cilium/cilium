// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policyderivative

import (
	"context"

	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy/groups"
)

var ccnpToGroupsControllerGroup = controller.NewGroup("cilium-clusterwide-network-policy-to-groups")

func k8sEventMetric(scope, action string) {
	metrics.EventTS.WithLabelValues(metrics.LabelEventSourceK8s, scope, action).SetToCurrentTime()
}

// startCCNPWatcher is similar to startCNPWatcher but handles the watch events for
// clusterwide policies. Since, internally Clusterwide policies are implemented
// using CiliumNetworkPolicy itself, the entire implementation uses the methods
// associated with CiliumNetworkPolicy.
func (c *policyDerivativeController) startCCNPWatcher() {
	c.logger.Info("Starting CCNP derivative handler")

	ccnpStore := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)

	ciliumV2Controller := informer.NewInformerWithStore(
		utils.ListerWatcherFromTyped[*cilium_v2.CiliumClusterwideNetworkPolicyList](c.clientset.CiliumV2().CiliumClusterwideNetworkPolicies()),
		&cilium_v2.CiliumClusterwideNetworkPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				k8sEventMetric(resources.MetricCCNP, resources.MetricCreate)
				if cnp := informer.CastInformerEvent[types.SlimCNP](c.logger, obj); cnp != nil {
					// We need to deepcopy this structure because we are writing
					// fields.
					// See https://github.com/cilium/cilium/blob/27fee207f5422c95479422162e9ea0d2f2b6c770/pkg/policy/api/ingress.go#L112-L134
					cnpCpy := cnp.DeepCopy()

					groups.AddDerivativePolicyIfNeeded(c.logger, c.clientset, c.clusterName, cnpCpy.CiliumNetworkPolicy, true)
				}
			},
			UpdateFunc: func(oldObj, newObj any) {
				k8sEventMetric(resources.MetricCCNP, resources.MetricUpdate)
				if oldCNP := informer.CastInformerEvent[types.SlimCNP](c.logger, oldObj); oldCNP != nil {
					if newCNP := informer.CastInformerEvent[types.SlimCNP](c.logger, newObj); newCNP != nil {
						if oldCNP.DeepEqual(newCNP) {
							return
						}

						// We need to deepcopy this structure because we are writing
						// fields.
						// See https://github.com/cilium/cilium/blob/27fee207f5422c95479422162e9ea0d2f2b6c770/pkg/policy/api/ingress.go#L112-L134
						newCNPCpy := newCNP.DeepCopy()
						oldCNPCpy := oldCNP.DeepCopy()

						groups.UpdateDerivativePolicyIfNeeded(c.logger, c.clientset, c.clusterName, newCNPCpy.CiliumNetworkPolicy, oldCNPCpy.CiliumNetworkPolicy, true)
					}
				}
			},
			DeleteFunc: func(obj any) {
				k8sEventMetric(resources.MetricCCNP, resources.MetricDelete)
				cnp := informer.CastInformerEvent[types.SlimCNP](c.logger, obj)
				if cnp == nil {
					return
				}
				// The derivative policy will be deleted by the parent but need
				// to delete the cnp from the pooling.
				groups.DeleteDerivativeFromCache(cnp.CiliumNetworkPolicy)
			},
		},
		k8s.TransformToCCNP,
		ccnpStore,
	)
	mgr := controller.NewManager()

	c.wg.Go(func() {
		ciliumV2Controller.Run(c.ctx.Done())
		mgr.RemoveAllAndWait()
	})

	mgr.UpdateController(
		"ccnp-to-groups",
		controller.ControllerParams{
			Group: ccnpToGroupsControllerGroup,
			DoFunc: func(ctx context.Context) error {
				groups.UpdateCNPInformation(c.logger, c.clientset, c.clusterName)
				return nil
			},
			RunInterval: c.updateInterval,
		})
}
