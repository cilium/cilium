// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"github.com/sirupsen/logrus"

	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/source"
)

func (p *policyWatcher) addK8sNetworkPolicyV1(k8sNP *slim_networkingv1.NetworkPolicy, apiGroup string, dc chan uint64) error {
	defer func() {
		p.k8sResourceSynced.SetEventTimestamp(apiGroup)
	}()

	scopedLog := p.log.WithField(logfields.K8sAPIVersion, k8sNP.TypeMeta.APIVersion)
	rules, err := k8s.ParseNetworkPolicy(k8sNP)
	if err != nil {
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
		scopedLog.WithError(err).WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicy: logfields.Repr(k8sNP),
		}).Error("Error while parsing k8s kubernetes NetworkPolicy")
		return err
	}
	scopedLog = scopedLog.WithField(logfields.K8sNetworkPolicyName, k8sNP.ObjectMeta.Name)

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
	scopedLog.Info("NetworkPolicy successfully added")
	return nil
}

func (p *policyWatcher) deleteK8sNetworkPolicyV1(k8sNP *slim_networkingv1.NetworkPolicy, apiGroup string, dc chan uint64) error {
	defer func() {
		p.k8sResourceSynced.SetEventTimestamp(apiGroup)
	}()

	labels := k8s.GetPolicyLabelsv1(k8sNP)

	if labels == nil {
		p.log.Fatalf("provided v1 NetworkPolicy is nil, so cannot delete it")
	}

	scopedLog := p.log.WithFields(logrus.Fields{
		logfields.K8sNetworkPolicyName: k8sNP.ObjectMeta.Name,
		logfields.K8sNamespace:         k8sNP.ObjectMeta.Namespace,
		logfields.K8sAPIVersion:        k8sNP.TypeMeta.APIVersion,
		logfields.Labels:               logfields.Repr(labels),
	})
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
	scopedLog.Info("NetworkPolicy successfully removed")
	return nil
}
