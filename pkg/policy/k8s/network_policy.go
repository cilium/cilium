// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/source"
)

func (p *policyWatcher) addK8sNetworkPolicyV1(k8sNP *slim_networkingv1.NetworkPolicy, apiGroup string, dc chan uint64, clusterName string) error {
	defer func() {
		p.k8sResourceSynced.SetEventTimestamp(apiGroup)
	}()

	rules, err := k8s.ParseNetworkPolicy(p.log, clusterName, k8sNP)
	if err != nil {
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
		p.log.Error(
			"Error while parsing k8s kubernetes NetworkPolicy",
			logfields.Error, err,
			logfields.K8sAPIVersion, k8sNP.TypeMeta.APIVersion,
			logfields.CiliumNetworkPolicy, k8sNP,
		)
		return err
	}

	if dc != nil {
		p.knpSyncPending.Add(1)
	}
	p.policyImporter.UpdatePolicy(&policytypes.PolicyUpdate{
		Rules:  rules,
		Source: source.Kubernetes,
		Resource: ipcacheTypes.NewResourceID(
			ipcacheTypes.ResourceKindNetpol,
			k8sNP.ObjectMeta.Namespace,
			k8sNP.ObjectMeta.Name,
		),
		DoneChan: dc,
	})

	metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()
	p.log.Info(
		"NetworkPolicy successfully added",
		logfields.K8sNetworkPolicyName, k8sNP.ObjectMeta.Name,
		logfields.K8sAPIVersion, k8sNP.TypeMeta.APIVersion,
	)
	return nil
}

func (p *policyWatcher) deleteK8sNetworkPolicyV1(k8sNP *slim_networkingv1.NetworkPolicy, apiGroup string, dc chan uint64) error {
	defer func() {
		p.k8sResourceSynced.SetEventTimestamp(apiGroup)
	}()

	labels := k8s.GetPolicyLabelsv1(p.log, k8sNP)

	if labels == nil {
		logging.Fatal(p.log, "provided v1 NetworkPolicy is nil, so cannot delete it")
	}

	if dc != nil {
		p.knpSyncPending.Add(1)
	}
	p.policyImporter.UpdatePolicy(&policytypes.PolicyUpdate{
		Source: source.Kubernetes,
		Resource: ipcacheTypes.NewResourceID(
			ipcacheTypes.ResourceKindNetpol,
			k8sNP.ObjectMeta.Namespace,
			k8sNP.ObjectMeta.Name,
		),
		DoneChan: dc,
	})

	metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()
	p.log.Info(
		"NetworkPolicy successfully removed",
		logfields.K8sNetworkPolicyName, k8sNP.ObjectMeta.Name,
		logfields.K8sNamespace, k8sNP.ObjectMeta.Namespace,
		logfields.K8sAPIVersion, k8sNP.TypeMeta.APIVersion,
		logfields.Labels, labels,
	)
	return nil
}
