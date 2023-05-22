// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	cilium_v2_alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy/api"
)

func (k *K8sWatcher) onUpsertCIDRGroup(
	cidrGroup *cilium_v2_alpha1.CiliumCIDRGroup,
	cidrGroupCache map[string]*cilium_v2_alpha1.CiliumCIDRGroup,
	cnpCache map[resource.Key]*types.SlimCNP,
	cs client.Clientset,
	apiGroup, metricLabel string,
) error {
	var (
		equal  bool
		action string
	)

	// wrap k.K8sEventReceived call into a naked func() to capture equal in the closure
	defer func() {
		k.K8sEventReceived(apiGroup, metricLabel, action, true, equal)
	}()

	oldCidrGroup, ok := cidrGroupCache[cidrGroup.Name]
	if ok && oldCidrGroup.Spec.DeepEqual(&cidrGroup.Spec) {
		equal = true
		return nil
	} else if ok {
		action = resources.MetricUpdate
	} else {
		action = resources.MetricCreate
	}

	cidrGroupCpy := cidrGroup.DeepCopy()
	cidrGroupCache[cidrGroup.Name] = cidrGroupCpy

	err := k.updateCIDRGroupRefPolicies(cidrGroup.Name, cidrGroupCache, cnpCache, cs)

	k.K8sEventProcessed(metricLabel, action, err == nil)

	return err
}

func (k *K8sWatcher) onDeleteCIDRGroup(
	cidrGroupName string,
	cidrGroupCache map[string]*cilium_v2_alpha1.CiliumCIDRGroup,
	cnpCache map[resource.Key]*types.SlimCNP,
	cs client.Clientset,
	apiGroup, metricLabel string,
) error {
	delete(cidrGroupCache, cidrGroupName)

	err := k.updateCIDRGroupRefPolicies(cidrGroupName, cidrGroupCache, cnpCache, cs)

	k.K8sEventProcessed(metricLabel, resources.MetricDelete, err == nil)
	k.K8sEventReceived(apiGroup, metricLabel, resources.MetricDelete, true, true)

	return err
}

func (k *K8sWatcher) updateCIDRGroupRefPolicies(
	cidrGroup string,
	cidrGroupCache map[string]*cilium_v2_alpha1.CiliumCIDRGroup,
	cnpCache map[resource.Key]*types.SlimCNP,
	cs client.Clientset,
) error {
	var errs []error
	for key, cnp := range cnpCache {
		if !hasCIDRGroupRef(cnp, cidrGroup) {
			continue
		}

		log.WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicyName: cnp.Name,
			logfields.K8sAPIVersion:           cnp.APIVersion,
			logfields.K8sNamespace:            cnp.Namespace,
			logfields.CIDRGroupRef:            cidrGroup,
		}).Info("Referenced CiliumCIDRGroup updated or deleted, recalculating CiliumNetworkPolicy rules")

		initialRecvTime := time.Now()

		// We need to deepcopy this structure because we are writing
		// fields.
		// See https://github.com/cilium/cilium/blob/27fee207f5422c95479422162e9ea0d2f2b6c770/pkg/policy/api/ingress.go#L112-L134
		cnpCpy := cnp.DeepCopy()

		translationStart := time.Now()
		translatedCNP := resolveCIDRGroupRef(cnpCpy, cidrGroupCache)
		metrics.CIDRGroupTranslationTimeStats.Observe(time.Since(translationStart).Seconds())

		resourceKind := ipcacheTypes.ResourceKindCNP
		if len(key.Namespace) == 0 {
			resourceKind = ipcacheTypes.ResourceKindCCNP
		}
		resourceID := ipcacheTypes.NewResourceID(
			resourceKind,
			cnpCpy.ObjectMeta.Namespace,
			cnpCpy.ObjectMeta.Name,
		)
		err := k.updateCiliumNetworkPolicyV2(cs, cnpCpy, translatedCNP, initialRecvTime, resourceID)
		if err == nil {
			cnpCache[key] = cnpCpy
		}

		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func resolveCIDRGroupRef(cnp *types.SlimCNP, cidrGroupCache map[string]*cilium_v2_alpha1.CiliumCIDRGroup) *types.SlimCNP {
	refs := getCIDRGroupRefs(cnp)
	if len(refs) == 0 {
		return cnp
	}

	cidrsSets, err := cidrGroupRefsToCIDRsSets(refs, cidrGroupCache)
	if err != nil {
		log.WithFields(logrus.Fields{
			logfields.K8sAPIVersion:           cnp.TypeMeta.APIVersion,
			logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
			logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
			logfields.CIDRGroupRef:            refs,
		}).WithError(err).Warning("Unable to translate all CIDR groups to CIDRs")
	}

	translated := translateCIDRGroupRefs(cnp, cidrsSets)

	return translated
}

func hasCIDRGroupRef(cnp *types.SlimCNP, cidrGroup string) bool {
	if specHasCIDRGroupRef(cnp.Spec, cidrGroup) {
		return true
	}
	for _, spec := range cnp.Specs {
		if specHasCIDRGroupRef(spec, cidrGroup) {
			return true
		}
	}
	return false
}

func specHasCIDRGroupRef(spec *api.Rule, cidrGroup string) bool {
	if spec == nil {
		return false
	}
	for _, ingress := range spec.Ingress {
		for _, rule := range ingress.FromCIDRSet {
			if string(rule.CIDRGroupRef) == cidrGroup {
				return true
			}
		}
	}
	return false
}

func getCIDRGroupRefs(cnp *types.SlimCNP) []string {
	if cnp.Spec == nil && cnp.Specs == nil {
		return nil
	}

	specs := cnp.Specs
	if cnp.Spec != nil {
		specs = append(specs, cnp.Spec)
	}

	var cidrGroupRefs []string
	for _, spec := range specs {
		for _, ingress := range spec.Ingress {
			for _, rule := range ingress.FromCIDRSet {
				// If CIDR is not set, then we assume CIDRGroupRef is set due
				// to OneOf, even if CIDRGroupRef is empty, as that's still a
				// valid reference (although useless from a user perspective).
				if len(rule.Cidr) == 0 {
					cidrGroupRefs = append(cidrGroupRefs, string(rule.CIDRGroupRef))
				}
			}
		}
	}

	return cidrGroupRefs
}

func cidrGroupRefsToCIDRsSets(cidrGroupRefs []string, cache map[string]*cilium_v2_alpha1.CiliumCIDRGroup) (map[string][]api.CIDR, error) {
	var errs []error
	cidrsSet := make(map[string][]api.CIDR)
	for _, cidrGroupRef := range cidrGroupRefs {
		var found bool
		for cidrGroupName, cidrGroup := range cache {
			if cidrGroupName == cidrGroupRef {
				cidrs := make([]api.CIDR, 0, len(cidrGroup.Spec.ExternalCIDRs))
				for _, cidr := range cidrGroup.Spec.ExternalCIDRs {
					cidrs = append(cidrs, api.CIDR(cidr))
				}
				cidrsSet[cidrGroupRef] = cidrs
				found = true
				break
			}
		}
		if !found {
			errs = append(errs, fmt.Errorf("cidr group %q not found, skipping translation", cidrGroupRef))
		}
	}
	return cidrsSet, errors.Join(errs...)
}

func translateCIDRGroupRefs(cnp *types.SlimCNP, cidrsSets map[string][]api.CIDR) *types.SlimCNP {
	cnpCpy := cnp.DeepCopy()

	if cnpCpy.Spec != nil {
		translateSpec(cnpCpy.Spec, cidrsSets)
	}
	for i := range cnpCpy.Specs {
		if cnpCpy.Specs[i] != nil {
			translateSpec(cnpCpy.Specs[i], cidrsSets)
		}
	}
	return cnpCpy
}

func translateSpec(spec *api.Rule, cidrsSets map[string][]api.CIDR) {
	for i := range spec.Ingress {
		var (
			oldRules api.CIDRRuleSlice
			refRules []api.CIDRRule
		)

		for _, rule := range spec.Ingress[i].FromCIDRSet {
			if rule.CIDRGroupRef == "" {
				// keep rules without a cidr group reference
				oldRules = append(oldRules, rule)
				continue
			}
			// collect all rules with references to a cidr group
			refRules = append(refRules, rule)
		}

		// add rules for each cidr in the referenced cidr groups
		var newRules api.CIDRRuleSlice
		for _, refRule := range refRules {
			cidrs, found := cidrsSets[string(refRule.CIDRGroupRef)]
			if !found || len(cidrs) == 0 {
				continue
			}
			for _, cidr := range cidrs {
				newRules = append(newRules, api.CIDRRule{Cidr: cidr, ExceptCIDRs: refRule.ExceptCIDRs})
			}
		}

		spec.Ingress[i].FromCIDRSet = append(oldRules, newRules...)
	}
}
