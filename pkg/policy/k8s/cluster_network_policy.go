// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"errors"

	policyv1alpha2 "sigs.k8s.io/network-policy-api/apis/v1alpha2"

	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

func (p *policyWatcher) addK8sClusterNetworkPolicy(k8sCNP *policyv1alpha2.ClusterNetworkPolicy, apiGroup string, dc chan uint64, clusterName string) error {
	initialRecvTime := time.Now()

	defer func() {
		p.k8sResourceSynced.SetEventTimestamp(apiGroup)
	}()

	rules, err := k8s.ParseClusterNetworkPolicy(p.log, clusterName, k8sCNP,
		k8s.WithFQDNPolicyDNSServerConfig(p.fqdnPolicyDNSServerConfig),
		k8s.WithServiceResolver(p.serviceResolver),
	)
	if err != nil {
		metrics.PolicyChangeTotal.WithLabelValues(string(source.Kubernetes), metrics.LabelValueUpdateOperation, metrics.LabelValueOutcomeFail).Inc()
		p.log.Error(
			"Error while parsing k8s kubernetes ClusterNetworkPolicy",
			logfields.Error, err,
			logfields.K8sAPIVersion, k8sCNP.TypeMeta.APIVersion,
			logfields.K8sClusterNetworkPolicy, k8sCNP,
		)
		return err
	}

	// Remember policies with domainNames peers, so that they can be recomputed
	// when the backends of the DNS server service change.
	key := resource.Key{Name: k8sCNP.ObjectMeta.Name, Namespace: k8sCNP.ObjectMeta.Namespace}
	if kcnpHasDomainNames(k8sCNP) {
		p.fqdnKCNPs[key] = k8sCNP
	} else {
		delete(p.fqdnKCNPs, key)
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
		ProcessingStartTime: initialRecvTime,
		DoneChan:            dc,
	})

	metrics.PolicyChangeTotal.WithLabelValues(string(source.Kubernetes), metrics.LabelValueUpdateOperation, metrics.LabelValueOutcomeSuccess).Inc()
	p.log.Info(
		"ClusterNetworkPolicy successfully added",
		logfields.K8sClusterNetworkPolicyName, k8sCNP.ObjectMeta.Name,
		logfields.K8sAPIVersion, k8sCNP.TypeMeta.APIVersion,
	)
	return nil
}

func (p *policyWatcher) deleteK8sClusterNetworkPolicy(k8sCNP *policyv1alpha2.ClusterNetworkPolicy, apiGroup string, dc chan uint64) error {
	initialRecvTime := time.Now()

	defer func() {
		p.k8sResourceSynced.SetEventTimestamp(apiGroup)
	}()

	labels := k8s.GetKCNPPolicyLabels(p.log, k8sCNP)

	if labels == nil {
		return errors.New("provided ClusterNetworkPolicy is nil, so cannot delete it")
	}

	key := resource.Key{Name: k8sCNP.ObjectMeta.Name, Namespace: k8sCNP.ObjectMeta.Namespace}
	delete(p.fqdnKCNPs, key)

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
		ProcessingStartTime: initialRecvTime,
		DoneChan:            dc,
	})

	metrics.PolicyChangeTotal.WithLabelValues(string(source.Kubernetes), metrics.LabelValueDeleteOperation, metrics.LabelValueOutcomeSuccess).Inc()
	p.log.Info(
		"ClusterNetworkPolicy successfully removed",
		logfields.K8sClusterNetworkPolicyName, k8sCNP.ObjectMeta.Name,
		logfields.K8sAPIVersion, k8sCNP.TypeMeta.APIVersion,
		logfields.Labels, labels,
	)
	return nil
}

// kcnpHasDomainNames returns true if any egress peer of the policy selects domain names.
func kcnpHasDomainNames(kcnp *policyv1alpha2.ClusterNetworkPolicy) bool {
	for _, rule := range kcnp.Spec.Egress {
		for _, peer := range rule.To {
			if len(peer.DomainNames) > 0 {
				return true
			}
		}
	}
	return false
}
