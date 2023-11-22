// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package policy

import (
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
)

type policyMetricsActions interface {
	SetPolicySelections(namespace, policyType, policyName string, selections int)
	DeletePolicySelections(namespace, policyType, policyName string)
	SetSelections(selectorType, policyType string, selections int)
}
type sourceIdent struct {
	derivedFrom  string
	selectorType identitySelectorType
}

type policySourceIdent struct {
	derivedFrom, namespace, name string
}

func (s policySourceIdent) isEmpty() bool {
	return s.derivedFrom == "" && s.name == ""
}

func policySourceTuple(s CachedSelector) (string, string, string) {
	ns := s.GetMetadataLabels().Get(labels.LabelSourceK8sKeyPrefix + k8sConst.PolicyLabelNamespace)
	name := s.GetMetadataLabels().Get(labels.LabelSourceK8sKeyPrefix + k8sConst.PolicyLabelName)
	derivedFrom := s.GetMetadataLabels().Get(labels.LabelSourceK8sKeyPrefix + k8sConst.PolicyLabelDerivedFrom)
	return ns, name, derivedFrom
}

func policySourceIdentifier(s CachedSelector) policySourceIdent {
	ns, name, derivedFrom := policySourceTuple(s)
	return policySourceIdent{
		derivedFrom: derivedFrom,
		namespace:   ns,
		name:        name,
	}
}

func selectorSourceIdentifier(s CachedSelector) sourceIdent {
	_, _, derivedFrom := policySourceTuple(s)
	return sourceIdent{
		derivedFrom:  derivedFrom,
		selectorType: s.selectorType(),
	}
}

// selectorSourceMetrics does accounting for selector metrics that are aggregated
// by the source of the policy (i.e. namespace/name/derivedFrom).
//
// This is to avoid having to keep references to policy objects or policy repo in
// the selector cache as we can deduce sources from labels.
type selectorSourceMetrics struct {
	policyMetricsActions
	policyToSelectorCount map[policySourceIdent]refCountedCount
	// Not ref counted, as this will have a fixed set of values.
	selectorSourceToCount map[sourceIdent]int
}

type refCountedCount struct {
	refs, count int
}

func newSelectorMetrics(metrics policyMetricsActions) *selectorSourceMetrics {
	return &selectorSourceMetrics{
		policyToSelectorCount: make(map[policySourceIdent]refCountedCount),
		selectorSourceToCount: make(map[sourceIdent]int),
		policyMetricsActions:  metrics,
	}
}

// updateSelector updates metrics for a selector, by:
// * Source tuple (i.e. namespace, name, derivedFrom).
// * Source type + selector type tuple (i.e. derivedFrom, selectorType).
// This also increments a ref count for the source so that we can track when the policy source
// is no longer referenced by any policies in the policy cache.
func (sm *selectorSourceMetrics) updateSelector(selector CachedSelector, delta int, selectorIsNew bool) {
	if sm == nil {
		return
	}

	sid := policySourceIdentifier(selector)
	if sid.isEmpty() {
		// This is a selector that is not associated with a policy source
		return
	}

	cp := sm.policyToSelectorCount[policySourceIdentifier(selector)]
	if selectorIsNew {
		cp.refs++
	}
	cp.count += delta
	sm.policyToSelectorCount[policySourceIdentifier(selector)] = cp
	sm.SetPolicySelections(sid.namespace, sid.derivedFrom, sid.name, cp.count)

	// Update selector-source metrics.
	ssid := selectorSourceIdentifier(selector)

	c := sm.selectorSourceToCount[ssid]
	c += delta
	sm.selectorSourceToCount[ssid] = c
	sm.SetSelections(string(ssid.selectorType), ssid.derivedFrom, c)
}

// deleteSelector decrements the ref count for a policy source (i.e. namespace/name/derivedFrom)
// and updates the metric given that this selector is no longer in use.
// Thus, the passed selections should be the former number of selections for this selector, prior
// to release.
// If there are no more policies using this source, the metric is deleted.
func (sm *selectorSourceMetrics) deleteSelector(selector CachedSelector, selections int) {
	if sm == nil {
		return
	}
	cp := sm.policyToSelectorCount[policySourceIdentifier(selector)]
	cp.refs--
	cp.count -= selections
	ns, name, derivedFrom := policySourceTuple(selector)
	if cp.refs <= 0 {
		delete(sm.policyToSelectorCount, policySourceIdentifier(selector))
		sm.DeletePolicySelections(ns, derivedFrom, name)
	} else {
		sm.policyToSelectorCount[policySourceIdentifier(selector)] = cp
		sm.SetPolicySelections(ns, derivedFrom, name, cp.count)
	}

	ssid := selectorSourceIdentifier(selector)
	sstc := sm.selectorSourceToCount[ssid]
	sstc -= selections
	sm.selectorSourceToCount[ssid] = sstc
	sm.SetSelections(string(ssid.selectorType), ssid.derivedFrom, sstc)
}
