// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"

	cilium_v2_alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/time"
)

func (p *PolicyWatcher) onUpsertCIDRGroup(
	cidrGroup *cilium_v2_alpha1.CiliumCIDRGroup,
	apiGroup string,
) error {

	defer func() {
		p.k8sResourceSynced.SetEventTimestamp(apiGroup)
	}()

	oldCidrGroup, ok := p.cidrGroupCache[cidrGroup.Name]
	if ok && oldCidrGroup.Spec.DeepEqual(&cidrGroup.Spec) {
		return nil
	}

	cidrGroupCpy := cidrGroup.DeepCopy()
	p.cidrGroupCache[cidrGroup.Name] = cidrGroupCpy

	err := p.updateCIDRGroupRefPolicies(cidrGroup.Name)

	return err
}

func (p *PolicyWatcher) onDeleteCIDRGroup(
	cidrGroupName string,
	apiGroup string,
) error {
	delete(p.cidrGroupCache, cidrGroupName)

	err := p.updateCIDRGroupRefPolicies(cidrGroupName)

	p.k8sResourceSynced.SetEventTimestamp(apiGroup)

	return err
}

func (p *PolicyWatcher) updateCIDRGroupRefPolicies(
	cidrGroup string,
) error {
	var errs []error
	for key, cnp := range p.cnpCache {
		if !hasCIDRGroupRef(cnp, cidrGroup) {
			continue
		}

		p.log.WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicyName: cnp.Name,
			logfields.K8sAPIVersion:           cnp.APIVersion,
			logfields.K8sNamespace:            cnp.Namespace,
			logfields.CIDRGroupRef:            cidrGroup,
		}).Info("Referenced CiliumCIDRGroup updated or deleted, recalculating CiliumNetworkPolicy rules")

		initialRecvTime := time.Now()

		resourceID := resourceIDForCiliumNetworkPolicy(key, cnp)

		errs = append(errs, p.resolveCiliumNetworkPolicyRefs(cnp, key, initialRecvTime, resourceID))
	}
	return errors.Join(errs...)
}

func (p *PolicyWatcher) resolveCIDRGroupRef(cnp *types.SlimCNP) {
	refs := getCIDRGroupRefs(cnp)
	if len(refs) == 0 {
		return
	}

	cidrsSets, err := p.cidrGroupRefsToCIDRsSets(refs)
	if err != nil {
		p.log.WithFields(logrus.Fields{
			logfields.K8sAPIVersion:           cnp.TypeMeta.APIVersion,
			logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
			logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
			logfields.CIDRGroupRef:            refs,
		}).WithError(err).Warning("Unable to translate all CIDR groups to CIDRs")
	}

	translateCIDRGroupRefs(cnp, cidrsSets)
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
	for _, egress := range spec.Egress {
		for _, rule := range egress.ToCIDRSet {
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
		for _, egress := range spec.Egress {
			for _, rule := range egress.ToCIDRSet {
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

func (p *PolicyWatcher) cidrGroupRefsToCIDRsSets(cidrGroupRefs []string) (map[string][]api.CIDR, error) {
	var errs []error
	cidrsSet := make(map[string][]api.CIDR)
	for _, cidrGroupRef := range cidrGroupRefs {
		cidrGroup, found := p.cidrGroupCache[cidrGroupRef]
		if !found {
			errs = append(errs, fmt.Errorf("cidr group %q not found, skipping translation", cidrGroupRef))
			continue
		}

		cidrs := make([]api.CIDR, 0, len(cidrGroup.Spec.ExternalCIDRs))
		for _, cidr := range cidrGroup.Spec.ExternalCIDRs {
			cidrs = append(cidrs, api.CIDR(cidr))
		}
		cidrsSet[cidrGroupRef] = cidrs
	}
	return cidrsSet, errors.Join(errs...)
}

func translateCIDRGroupRefs(cnp *types.SlimCNP, cidrsSets map[string][]api.CIDR) {
	if cnp.Spec != nil {
		translateSpec(cnp.Spec, cidrsSets)
	}
	for i := range cnp.Specs {
		if cnp.Specs[i] != nil {
			translateSpec(cnp.Specs[i], cidrsSets)
		}
	}
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
	for i := range spec.Egress {
		var (
			oldRules api.CIDRRuleSlice
			refRules []api.CIDRRule
		)

		for _, rule := range spec.Egress[i].ToCIDRSet {
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

		spec.Egress[i].ToCIDRSet = append(oldRules, newRules...)
	}
}
