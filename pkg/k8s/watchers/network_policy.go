// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/source"
)

func (k *K8sWatcher) NetworkPoliciesInit() {
	k.networkPoliciesInitOnce.Do(func() {
		var synced atomic.Bool
		swg := lock.NewStoppableWaitGroup()
		k.blockWaitGroupToSyncResources(k.stop, swg, func() bool { return synced.Load() }, k8sAPIGroupNetworkingV1Core)
		go k.networkPolicyEventLoop(&synced)
		swg.Wait()
		k.k8sAPIGroups.AddAPI(k8sAPIGroupNetworkingV1Core)
	})
}

func (k *K8sWatcher) networkPolicyEventLoop(synced *atomic.Bool) {
	apiGroup := k8sAPIGroupNetworkingV1Core
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := k.resources.NetworkPolicies.Events(ctx)
	for {
		select {
		case <-k.stop:
			cancel()
		case event, ok := <-events:
			if !ok {
				return
			}
			var err error
			switch event.Kind {
			case resource.Sync:
				var store resource.Store[*slim_networkingv1.NetworkPolicy]
				synced.Store(true)
				store, err = k.resources.NetworkPolicies.Store(ctx)
				if err == nil {
					k.networkpolicyStore = store.CacheStore()
					close(k.networkPoliciesStoreSet)
				}
			case resource.Upsert:
				k.k8sResourceSynced.SetEventTimestamp(apiGroup)
				err = k.addK8sNetworkPolicyV1(event.Object)
			case resource.Delete:
				k.k8sResourceSynced.SetEventTimestamp(apiGroup)
				err = k.deleteK8sNetworkPolicyV1(event.Object)
			}
			event.Done(err)
		}
	}
}

func (k *K8sWatcher) addK8sNetworkPolicyV1(k8sNP *slim_networkingv1.NetworkPolicy) error {
	scopedLog := log.WithField(logfields.K8sAPIVersion, k8sNP.TypeMeta.APIVersion)
	rules, err := k8s.ParseNetworkPolicy(k8sNP)
	if err != nil {
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
		scopedLog.WithError(err).WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicy: logfields.Repr(k8sNP),
		}).Error("Error while parsing k8s kubernetes NetworkPolicy")
		return err
	}
	scopedLog = scopedLog.WithField(logfields.K8sNetworkPolicyName, k8sNP.ObjectMeta.Name)

	opts := policy.AddOptions{
		Replace: true,
		Source:  source.Kubernetes,
		Resource: ipcacheTypes.NewResourceID(
			ipcacheTypes.ResourceKindNetpol,
			k8sNP.ObjectMeta.Namespace,
			k8sNP.ObjectMeta.Name,
		),
	}
	if _, err := k.policyManager.PolicyAdd(rules, &opts); err != nil {
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
		scopedLog.WithError(err).WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicy: logfields.Repr(rules),
		}).Error("Unable to add NetworkPolicy rules to policy repository")
		return err
	}

	metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()
	scopedLog.Info("NetworkPolicy successfully added")
	return nil
}

func (k *K8sWatcher) deleteK8sNetworkPolicyV1(k8sNP *slim_networkingv1.NetworkPolicy) error {
	labels := k8s.GetPolicyLabelsv1(k8sNP)

	if labels == nil {
		log.Fatalf("provided v1 NetworkPolicy is nil, so cannot delete it")
	}

	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sNetworkPolicyName: k8sNP.ObjectMeta.Name,
		logfields.K8sNamespace:         k8sNP.ObjectMeta.Namespace,
		logfields.K8sAPIVersion:        k8sNP.TypeMeta.APIVersion,
		logfields.Labels:               logfields.Repr(labels),
	})
	if _, err := k.policyManager.PolicyDelete(labels, &policy.DeleteOptions{
		Source: source.Kubernetes,
		Resource: ipcacheTypes.NewResourceID(
			ipcacheTypes.ResourceKindNetpol,
			k8sNP.ObjectMeta.Namespace,
			k8sNP.ObjectMeta.Name,
		),
	}); err != nil {
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
		scopedLog.WithError(err).Error("Error while deleting k8s NetworkPolicy")
		return err
	}

	metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()
	scopedLog.Info("NetworkPolicy successfully removed")
	return nil
}
