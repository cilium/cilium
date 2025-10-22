// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"errors"

	policyv1alpha2 "sigs.k8s.io/network-policy-api/apis/v1alpha2"

	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/source"
)

func (p *policyWatcher) addK8sClusterNetworkPolicy(k8sCNP *policyv1alpha2.ClusterNetworkPolicy, apiGroup string, dc chan uint64, clusterName string) error {
	defer func() {
		p.k8sResourceSynced.SetEventTimestamp(apiGroup)
	}()

	rules, err := k8s.ParseClusterNetworkPolicy(p.log, clusterName, k8sCNP)
	if err != nil {
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
		p.log.Error(
			"Error while parsing k8s kubernetes ClusterNetworkPolicy",
			logfields.Error, err,
			logfields.K8sAPIVersion, k8sCNP.TypeMeta.APIVersion,
			logfields.K8sClusterNetworkPolicy, k8sCNP,
		)
		return err
	}

	if dc != nil {
		p.kcnpSyncPending.Add(1)
	}
	p.policyImporter.UpdatePolicy(&policytypes.PolicyUpdate{
		Rules:  rules,
		Source: source.Kubernetes,
		Resource: ipcacheTypes.NewResourceID(
			ipcacheTypes.ResourceKindKCNP,
			k8sCNP.ObjectMeta.Namespace,
			k8sCNP.ObjectMeta.Name,
		),
		DoneChan: dc,
	})

	metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()
	p.log.Info(
		"ClusterNetworkPolicy successfully added",
		logfields.K8sClusterNetworkPolicyName, k8sCNP.ObjectMeta.Name,
		logfields.K8sAPIVersion, k8sCNP.TypeMeta.APIVersion,
	)
	return nil
}

func (p *policyWatcher) deleteK8sClusterNetworkPolicy(k8sCNP *policyv1alpha2.ClusterNetworkPolicy, apiGroup string, dc chan uint64) error {
	defer func() {
		p.k8sResourceSynced.SetEventTimestamp(apiGroup)
	}()

	labels := k8s.GetKCNPPolicyLabels(p.log, k8sCNP)

	if labels == nil {
		return errors.New("provided ClusterNetworkPolicy is nil, so cannot delete it")
	}

	if dc != nil {
		p.kcnpSyncPending.Add(1)
	}
	p.policyImporter.UpdatePolicy(&policytypes.PolicyUpdate{
		Source: source.Kubernetes,
		Resource: ipcacheTypes.NewResourceID(
			ipcacheTypes.ResourceKindKCNP,
			k8sCNP.ObjectMeta.Namespace,
			k8sCNP.ObjectMeta.Name,
		),
		DoneChan: dc,
	})

	metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()
	p.log.Info(
		"ClusterNetworkPolicy successfully removed",
		logfields.K8sClusterNetworkPolicyName, k8sCNP.ObjectMeta.Name,
		logfields.K8sAPIVersion, k8sCNP.TypeMeta.APIVersion,
		logfields.Labels, labels,
	)
	return nil
}
